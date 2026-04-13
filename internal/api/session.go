package api

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"

	"github.com/YourDoritos/pvpn/internal/config"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/nacl/secretbox"
)

const (
	// Argon2id parameters for key derivation
	argonTime    = 3
	argonMemory  = 64 * 1024
	argonThreads = 4
	argonKeyLen  = 32

	nonceSize = 24
)

// SessionStore handles encrypted persistence of session tokens.
type SessionStore struct {
	path string
	key  [32]byte
}

// NewSessionStore creates a session store at the given path.
// The encryption key is derived from /etc/machine-id using Argon2id.
func NewSessionStore(path string) (*SessionStore, error) {
	key, err := deriveKey()
	if err != nil {
		return nil, fmt.Errorf("derive encryption key: %w", err)
	}

	store := &SessionStore{path: path}
	copy(store.key[:], key)
	return store, nil
}

// Save encrypts and persists the session to disk.
func (s *SessionStore) Save(session *Session) error {
	plaintext, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("marshal session: %w", err)
	}

	// Generate random nonce
	var nonce [nonceSize]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return fmt.Errorf("generate nonce: %w", err)
	}

	// Encrypt with NaCl secretbox (XSalsa20-Poly1305)
	encrypted := secretbox.Seal(nonce[:], plaintext, &nonce, &s.key)

	// Write atomically via temp file
	tmpPath := s.path + ".tmp"
	if err := os.WriteFile(tmpPath, encrypted, 0660); err != nil {
		return fmt.Errorf("write session file: %w", err)
	}
	if err := os.Rename(tmpPath, s.path); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("rename session file: %w", err)
	}

	config.FixFileOwnership(s.path)
	return nil
}

// Load decrypts and reads the session from disk.
// Returns nil, nil if the file doesn't exist (not an error — just needs login).
func (s *SessionStore) Load() (*Session, error) {
	data, err := os.ReadFile(s.path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read session file: %w", err)
	}

	if len(data) < nonceSize {
		return nil, fmt.Errorf("session file too short")
	}

	// Extract nonce and ciphertext
	var nonce [nonceSize]byte
	copy(nonce[:], data[:nonceSize])
	ciphertext := data[nonceSize:]

	// Decrypt
	plaintext, ok := secretbox.Open(nil, ciphertext, &nonce, &s.key)
	if !ok {
		return nil, fmt.Errorf("decryption failed (machine-id changed or file corrupted)")
	}

	var session Session
	if err := json.Unmarshal(plaintext, &session); err != nil {
		return nil, fmt.Errorf("unmarshal session: %w", err)
	}

	return &session, nil
}

// Delete removes the session file.
func (s *SessionStore) Delete() error {
	err := os.Remove(s.path)
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

// Exists returns true if a session file exists.
func (s *SessionStore) Exists() bool {
	_, err := os.Stat(s.path)
	return err == nil
}

// deriveKey derives a 32-byte encryption key from /etc/machine-id using Argon2id.
func deriveKey() ([]byte, error) {
	machineID, err := os.ReadFile("/etc/machine-id")
	if err != nil {
		return nil, fmt.Errorf("read /etc/machine-id: %w (is this a Linux system?)", err)
	}

	// Use a fixed salt derived from the application name.
	// This is fine because machine-id already has high entropy.
	salt := []byte("pvpn-session-encryption-v1")

	key := argon2.IDKey(machineID, salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return key, nil
}
