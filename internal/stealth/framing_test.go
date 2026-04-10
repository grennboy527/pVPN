package stealth

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"
)

// TunSafe framing is a bit-level codec: a 2-bit type field packed into the top
// two bits of a 14-bit size header, with optional WG header stripping for the
// "data" type. A regression here silently corrupts packets — users just see
// "connection doesn't work" with no clear error. These tests lock the wire
// format and the state-tracking invariants.

// wgHandshake constructs a fake WG handshake-initiation packet (type 1).
// These are always sent as "normal" framing since the type byte != 4.
func wgHandshake(payload []byte) []byte {
	pkt := make([]byte, 1+len(payload))
	pkt[0] = 1 // WG handshake type
	copy(pkt[1:], payload)
	return pkt
}

// wgDataPacket constructs a WG transport data packet (type 4) with the given
// 3-byte prefix (padding/receiver index fields) and 8-byte counter.
func wgDataPacket(prefix [3]byte, counter uint64, payload []byte) []byte {
	pkt := make([]byte, wgDataHeaderSize+len(payload))
	pkt[0] = wgDataPrefix
	pkt[1], pkt[2], pkt[3] = prefix[0], prefix[1], prefix[2]
	// Bytes 4..7 are the receiver index (kept as zeros for these tests).
	binary.LittleEndian.PutUint64(pkt[wgDataPrefixSize:wgDataHeaderSize], counter)
	copy(pkt[wgDataHeaderSize:], payload)
	return pkt
}

// TestHeaderRoundTrip verifies parseTunSafeHeader correctly round-trips every
// valid size/type combination at the bit boundary.
func TestHeaderRoundTrip(t *testing.T) {
	cases := []struct {
		name string
		typ  byte
		size int
	}{
		{"normal zero", tunSafeNormalType, 0},
		{"normal small", tunSafeNormalType, 42},
		{"normal max", tunSafeNormalType, maxTunSafePayload},
		{"data zero", tunSafeDataType, 0},
		{"data small", tunSafeDataType, 42},
		{"data max", tunSafeDataType, maxTunSafePayload},
		{"14-bit boundary", tunSafeNormalType, 0x2000}, // bit 13 set
		{"8-bit boundary", tunSafeNormalType, 0xFF},
		{"9-bit boundary", tunSafeNormalType, 0x100},
	}
	for _, c := range cases {
		hdr := make([]byte, tunSafeHeaderSize)
		hdr[0] = c.typ<<6 | uint8(c.size>>8)
		hdr[1] = uint8(c.size & 0xFF)

		gotType, gotSize := parseTunSafeHeader(hdr)
		if gotType != c.typ {
			t.Errorf("%s: type = %d, want %d", c.name, gotType, c.typ)
		}
		if gotSize != c.size {
			t.Errorf("%s: size = %d, want %d", c.name, gotSize, c.size)
		}
	}
}

// TestNormalRoundTrip is the core invariant: a WG packet fed through the
// writer and back through the reader must come out byte-identical.
func TestNormalRoundTrip(t *testing.T) {
	pkt := wgHandshake([]byte("hello wireguard handshake"))

	var buf bytes.Buffer
	fw := NewFrameWriter(&buf)
	if err := fw.WritePacket(pkt); err != nil {
		t.Fatalf("WritePacket: %v", err)
	}

	// Verify on-wire layout: first byte should have type 0b00 in top 2 bits
	// and high bits of size in the bottom 6.
	if got := buf.Bytes()[0] >> 6; got != tunSafeNormalType {
		t.Errorf("on-wire type = %d, want %d (normal)", got, tunSafeNormalType)
	}

	fr := NewFrameReader(&buf)
	out := make([]byte, 2048)
	n, err := fr.ReadPacket(out)
	if err != nil {
		t.Fatalf("ReadPacket: %v", err)
	}
	if !bytes.Equal(out[:n], pkt) {
		t.Errorf("roundtrip mismatch:\n got %x\nwant %x", out[:n], pkt)
	}
}

// TestDataTypeOptimization verifies that sequential WG data packets with
// matching prefix + incrementing counter get encoded as the compressed "data"
// type (16-byte header stripped) and reconstructed correctly on read.
//
// This is the riskiest path: if the state tracking desyncs by even one
// counter, decrypted WG packets look valid on the wire but the WG engine
// rejects them as replays / bad MAC.
func TestDataTypeOptimization(t *testing.T) {
	prefix := [3]byte{0xAB, 0xCD, 0xEF}
	payload := []byte("encrypted tunnel payload bytes here")

	// Build a writer state that's already "seen" counter=42 with this prefix.
	var wbuf bytes.Buffer
	fw := NewFrameWriter(&wbuf)
	// Send the seed packet (normal framing, establishes send state).
	seed := wgDataPacket(prefix, 42, payload)
	if err := fw.WritePacket(seed); err != nil {
		t.Fatalf("write seed: %v", err)
	}
	// Sequential packet (counter 43) — should be encoded as data type.
	next := wgDataPacket(prefix, 43, payload)
	if err := fw.WritePacket(next); err != nil {
		t.Fatalf("write sequential: %v", err)
	}

	// Inspect the on-wire form of the second frame: its top 2 bits must
	// indicate the data-type optimization was applied.
	seedFrameLen := tunSafeHeaderSize + len(seed)
	if wbuf.Len() <= seedFrameLen {
		t.Fatalf("writer buffer too small: %d bytes", wbuf.Len())
	}
	secondFrameType := wbuf.Bytes()[seedFrameLen] >> 6
	if secondFrameType != tunSafeDataType {
		t.Errorf("sequential packet on wire has type %d, want %d (data)",
			secondFrameType, tunSafeDataType)
	}

	// Read both back. The reader should reconstruct the full WG packets
	// byte-identical to what went in.
	fr := NewFrameReader(&wbuf)
	out := make([]byte, 2048)

	n, err := fr.ReadPacket(out)
	if err != nil {
		t.Fatalf("read seed: %v", err)
	}
	if !bytes.Equal(out[:n], seed) {
		t.Errorf("seed mismatch:\n got %x\nwant %x", out[:n], seed)
	}

	n, err = fr.ReadPacket(out)
	if err != nil {
		t.Fatalf("read sequential: %v", err)
	}
	if !bytes.Equal(out[:n], next) {
		t.Errorf("sequential mismatch after reconstruction:\n got %x\nwant %x",
			out[:n], next)
	}
}

// TestDataTypeNotUsedOnPrefixMismatch verifies that a WG packet with a
// different prefix than the last-seen one falls back to normal framing.
// If this regresses, the reader will reconstruct the wrong header and the
// WG engine will reject every packet after a rekey.
func TestDataTypeNotUsedOnPrefixMismatch(t *testing.T) {
	var wbuf bytes.Buffer
	fw := NewFrameWriter(&wbuf)

	// Seed with one prefix...
	seed := wgDataPacket([3]byte{0x11, 0x22, 0x33}, 1, []byte("first"))
	if err := fw.WritePacket(seed); err != nil {
		t.Fatalf("seed: %v", err)
	}
	// ...then send a packet with a DIFFERENT prefix. Must not use data-type
	// compression even though the counter technically follows.
	other := wgDataPacket([3]byte{0x99, 0x88, 0x77}, 2, []byte("second"))
	if err := fw.WritePacket(other); err != nil {
		t.Fatalf("other: %v", err)
	}

	seedFrameLen := tunSafeHeaderSize + len(seed)
	secondFrameType := wbuf.Bytes()[seedFrameLen] >> 6
	if secondFrameType != tunSafeNormalType {
		t.Errorf("prefix-mismatch packet used type %d, want %d (normal fallback)",
			secondFrameType, tunSafeNormalType)
	}

	// Read both back; they must still round-trip byte-identical.
	fr := NewFrameReader(&wbuf)
	out := make([]byte, 2048)
	n, _ := fr.ReadPacket(out)
	if !bytes.Equal(out[:n], seed) {
		t.Errorf("seed mismatch: got %x want %x", out[:n], seed)
	}
	n, _ = fr.ReadPacket(out)
	if !bytes.Equal(out[:n], other) {
		t.Errorf("other mismatch: got %x want %x", out[:n], other)
	}
}

// TestDataTypeNotUsedOnCounterGap verifies that a non-sequential counter
// (gap, retransmit, reorder) falls back to normal framing rather than
// silently miscoding a header.
func TestDataTypeNotUsedOnCounterGap(t *testing.T) {
	var wbuf bytes.Buffer
	fw := NewFrameWriter(&wbuf)

	prefix := [3]byte{0x42, 0x42, 0x42}
	seed := wgDataPacket(prefix, 10, []byte("a"))
	if err := fw.WritePacket(seed); err != nil {
		t.Fatalf("seed: %v", err)
	}
	// Counter jumps from 10 to 15 — not sequential.
	gap := wgDataPacket(prefix, 15, []byte("b"))
	if err := fw.WritePacket(gap); err != nil {
		t.Fatalf("gap: %v", err)
	}

	seedFrameLen := tunSafeHeaderSize + len(seed)
	secondFrameType := wbuf.Bytes()[seedFrameLen] >> 6
	if secondFrameType != tunSafeNormalType {
		t.Errorf("counter-gap packet used type %d, want %d (normal fallback)",
			secondFrameType, tunSafeNormalType)
	}
}

// TestMaxPayloadSize exercises the 14-bit size-field boundary. A packet
// exactly at maxTunSafePayload must round-trip; one byte over would overflow
// the 14-bit field and is out of scope (callers must fragment).
func TestMaxPayloadSize(t *testing.T) {
	payload := make([]byte, maxTunSafePayload-1)
	for i := range payload {
		payload[i] = byte(i % 251) // non-zero pattern
	}
	pkt := wgHandshake(payload)
	if len(pkt) != maxTunSafePayload {
		t.Fatalf("test setup: packet len %d, want %d", len(pkt), maxTunSafePayload)
	}

	var buf bytes.Buffer
	fw := NewFrameWriter(&buf)
	if err := fw.WritePacket(pkt); err != nil {
		t.Fatalf("write: %v", err)
	}

	fr := NewFrameReader(&buf)
	out := make([]byte, maxTunSafePayload+64)
	n, err := fr.ReadPacket(out)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(out[:n], pkt) {
		t.Errorf("max-size roundtrip mismatch at boundary")
	}
}

// TestReadTruncatedFrame ensures that a short read during frame parsing
// surfaces as an error rather than a silent partial packet.
func TestReadTruncatedFrame(t *testing.T) {
	// Only 1 byte of the 2-byte header.
	fr := NewFrameReader(bytes.NewReader([]byte{0x00}))
	buf := make([]byte, 128)
	if _, err := fr.ReadPacket(buf); err == nil {
		t.Error("expected error on truncated header, got nil")
	}

	// Full header announcing 100 bytes, but only 10 bytes of payload follow.
	short := []byte{0x00, 100}
	short = append(short, make([]byte, 10)...)
	fr = NewFrameReader(bytes.NewReader(short))
	if _, err := fr.ReadPacket(buf); err == nil {
		t.Error("expected error on truncated payload, got nil")
	}
}

// TestReadZeroLengthFrame rejects empty frames, which would otherwise confuse
// the state-tracking counter.
func TestReadZeroLengthFrame(t *testing.T) {
	fr := NewFrameReader(bytes.NewReader([]byte{0x00, 0x00}))
	buf := make([]byte, 128)
	if _, err := fr.ReadPacket(buf); err == nil {
		t.Error("expected error on zero-length frame, got nil")
	}
}

// TestReadBufferTooSmall verifies the caller's buffer-size check fires rather
// than overwriting adjacent memory.
func TestReadBufferTooSmall(t *testing.T) {
	var wbuf bytes.Buffer
	fw := NewFrameWriter(&wbuf)
	pkt := wgHandshake(make([]byte, 64))
	if err := fw.WritePacket(pkt); err != nil {
		t.Fatalf("write: %v", err)
	}

	fr := NewFrameReader(&wbuf)
	small := make([]byte, 4) // way too small
	if _, err := fr.ReadPacket(small); err == nil {
		t.Error("expected error on small buffer, got nil")
	}
}

// TestMultiplePacketsInStream verifies that the reader can decode many
// packets from a single stream without losing state or framing.
func TestMultiplePacketsInStream(t *testing.T) {
	var wbuf bytes.Buffer
	fw := NewFrameWriter(&wbuf)

	// Mix of handshake + data packets, some sequential, some not.
	packets := [][]byte{
		wgHandshake([]byte("h1")),
		wgDataPacket([3]byte{1, 2, 3}, 100, []byte("payload-a")),
		wgDataPacket([3]byte{1, 2, 3}, 101, []byte("payload-b")), // sequential → data type
		wgDataPacket([3]byte{1, 2, 3}, 102, []byte("payload-c")), // sequential → data type
		wgHandshake([]byte("h2")),                                // handshake again
		wgDataPacket([3]byte{9, 9, 9}, 5, []byte("payload-d")),   // new prefix
	}
	for i, p := range packets {
		if err := fw.WritePacket(p); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}

	fr := NewFrameReader(&wbuf)
	out := make([]byte, 2048)
	for i, want := range packets {
		n, err := fr.ReadPacket(out)
		if err != nil {
			t.Fatalf("read %d: %v", i, err)
		}
		if !bytes.Equal(out[:n], want) {
			t.Errorf("packet %d mismatch:\n got %x\nwant %x", i, out[:n], want)
		}
	}

	// Stream should be exhausted.
	if _, err := fr.ReadPacket(out); err != io.EOF {
		t.Errorf("after last packet, err = %v, want io.EOF", err)
	}
}
