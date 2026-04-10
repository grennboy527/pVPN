package stealth

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"sync"
)

// TunSafe framing as implemented by Proton's wireguard-go fork.
//
// Header: 2 bytes
//   Bits [15:14] of header[0] = type:
//     0b00 = normal: full WireGuard packet follows
//     0b10 = data:   WG data packet with 16-byte header stripped
//   Bits [13:0] = payload size (max 16383)
//
// For "normal" type: payload is the complete WG packet.
// For "data" type: payload is the WG data packet minus its 16-byte header.
//   The receiver reconstructs the header from previously seen packets.

const (
	tunSafeHeaderSize = 2
	tunSafeNormalType = uint8(0b00)
	tunSafeDataType   = uint8(0b10)

	wgDataPrefix      = 4 // WG transport data message type
	wgDataHeaderSize  = 16
	wgDataPrefixSize  = 8      // WG data header without counter
	maxTunSafePayload = 0x3FFF // 14-bit max
)

// tunSafeState tracks WG packet header state for data-type optimization.
type tunSafeState struct {
	sendPrefix []byte
	sendCount  uint64
	recvPrefix []byte
	recvCount  uint64
}

func newTunSafeState() *tunSafeState {
	return &tunSafeState{
		sendPrefix: make([]byte, wgDataPrefixSize),
		recvPrefix: make([]byte, wgDataPrefixSize),
	}
}

// wgToTunSafe converts a WireGuard packet to TunSafe framing.
func (ts *tunSafeState) wgToTunSafe(wgPacket []byte) []byte {
	wgLen := len(wgPacket)
	if wgLen < wgDataHeaderSize {
		return ts.wgToTunSafeNormal(wgPacket)
	}

	wgPrefix := wgPacket[:wgDataPrefixSize]
	var wgCount uint64
	binary.Read(bytes.NewReader(wgPacket[wgDataPrefixSize:wgDataHeaderSize]), binary.LittleEndian, &wgCount)

	prefixMatch := bytes.Equal(wgPrefix, ts.sendPrefix)
	if prefixMatch && wgCount == ts.sendCount+1 {
		ts.sendCount++
		return ts.wgToTunSafeData(wgPacket)
	}

	// Check if this is a WG data packet (type 4)
	if wgPacket[0] == wgDataPrefix {
		copy(ts.sendPrefix, wgPrefix)
		ts.sendCount = wgCount
	}
	return ts.wgToTunSafeNormal(wgPacket)
}

func (ts *tunSafeState) wgToTunSafeNormal(wgPacket []byte) []byte {
	payloadSize := len(wgPacket)
	result := make([]byte, payloadSize+tunSafeHeaderSize)
	// Type 0b00 in top 2 bits, size in lower 14 bits
	result[0] = uint8(payloadSize >> 8)
	result[1] = uint8(payloadSize & 0xFF)
	copy(result[tunSafeHeaderSize:], wgPacket)
	return result
}

func (ts *tunSafeState) wgToTunSafeData(wgPacket []byte) []byte {
	payloadSize := len(wgPacket) - wgDataHeaderSize
	result := make([]byte, payloadSize+tunSafeHeaderSize)
	// Type 0b10 in top 2 bits, size in lower 14 bits
	result[0] = uint8(tunSafeDataType<<6 | uint8(payloadSize>>8))
	result[1] = uint8(payloadSize & 0xFF)
	copy(result[tunSafeHeaderSize:], wgPacket[wgDataHeaderSize:])
	return result
}

// onRecvPacket updates state after receiving a packet.
func (ts *tunSafeState) onRecvPacket(tunSafeType byte, wgPacket []byte) {
	if tunSafeType == tunSafeNormalType {
		if len(wgPacket) >= wgDataHeaderSize && wgPacket[0] == wgDataPrefix {
			copy(ts.recvPrefix, wgPacket[:wgDataPrefixSize])
			binary.Read(
				bytes.NewReader(wgPacket[wgDataPrefixSize:wgDataHeaderSize]),
				binary.LittleEndian,
				&ts.recvCount,
			)
		}
	}
	ts.recvCount++
}

// prepareWgPacket creates a buffer for receiving and reconstructs headers if needed.
func (ts *tunSafeState) prepareWgPacket(tunSafeType byte, payloadSize int) ([]byte, int, error) {
	switch tunSafeType {
	case tunSafeNormalType:
		return make([]byte, payloadSize), 0, nil
	case tunSafeDataType:
		offset := wgDataHeaderSize
		wgPacket := make([]byte, payloadSize+offset)
		// Reconstruct the WG header from tracked state
		buf := new(bytes.Buffer)
		buf.Grow(wgDataPrefixSize + 8)
		buf.Write(ts.recvPrefix)
		binary.Write(buf, binary.LittleEndian, ts.recvCount)
		copy(wgPacket, buf.Bytes())
		return wgPacket, offset, nil
	default:
		return nil, 0, fmt.Errorf("unknown TunSafe type: %d", tunSafeType)
	}
}

// parseTunSafeHeader parses the 2-byte TunSafe header.
func parseTunSafeHeader(header []byte) (byte, int) {
	tunSafeType := header[0] >> 6
	size := (int(header[0])&0x3F)<<8 | int(header[1])
	return tunSafeType, size
}

// FrameWriter writes TunSafe-framed WireGuard packets to a stream.
type FrameWriter struct {
	mu      sync.Mutex
	w       io.Writer
	tunsafe *tunSafeState
}

// NewFrameWriter creates a framing writer.
func NewFrameWriter(w io.Writer) *FrameWriter {
	return &FrameWriter{w: w, tunsafe: newTunSafeState()}
}

// WritePacket converts a WG packet to TunSafe framing and writes it.
func (fw *FrameWriter) WritePacket(pkt []byte) error {
	fw.mu.Lock()
	defer fw.mu.Unlock()

	frame := fw.tunsafe.wgToTunSafe(pkt)
	_, err := fw.w.Write(frame)
	return err
}

// FrameReader reads TunSafe-framed WireGuard packets from a stream.
type FrameReader struct {
	mu      sync.Mutex
	r       io.Reader
	tunsafe *tunSafeState
}

// NewFrameReader creates a framing reader.
func NewFrameReader(r io.Reader) *FrameReader {
	return &FrameReader{r: r, tunsafe: newTunSafeState()}
}

// ReadPacket reads the next TunSafe-framed WireGuard packet.
func (fr *FrameReader) ReadPacket(buf []byte) (int, error) {
	fr.mu.Lock()
	defer fr.mu.Unlock()

	// Read 2-byte TunSafe header
	var hdr [tunSafeHeaderSize]byte
	if _, err := io.ReadFull(fr.r, hdr[:]); err != nil {
		return 0, err
	}

	tunSafeType, payloadSize := parseTunSafeHeader(hdr[:])
	if payloadSize == 0 {
		return 0, fmt.Errorf("zero-length frame")
	}

	wgPacket, offset, err := fr.tunsafe.prepareWgPacket(tunSafeType, payloadSize)
	if err != nil {
		return 0, err
	}

	// Read payload into the packet buffer (after any reconstructed header)
	if _, err := io.ReadFull(fr.r, wgPacket[offset:]); err != nil {
		return 0, err
	}

	fr.tunsafe.onRecvPacket(tunSafeType, wgPacket)

	// Copy to caller's buffer
	n := len(wgPacket)
	if n > len(buf) {
		return 0, fmt.Errorf("buffer too small: need %d, have %d", n, len(buf))
	}
	copy(buf[:n], wgPacket)
	return n, nil
}
