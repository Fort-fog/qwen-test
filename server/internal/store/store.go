// Package store provides durable, per-device message storage for the relay.
//
// Design constraints:
//   - The server stays content-blind: payloads are stored exactly as received
//     (opaque, expected to be E2E-encrypted blobs on the client side).
//   - Storage is a single JSON file, written atomically (temp + rename) so a
//     crash never leaves a truncated store.
//   - Messages are kept per RECIPIENT device id, capped at MaxStoredMessages
//     per device (oldest dropped first — FIFO ring behaviour).
package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// ErrNotFound is returned when a stored message id does not exist.
var ErrNotFound = errors.New("store: message not found")

// MaxStoredMessages caps how many messages are retained per recipient.
const MaxStoredMessages = 500

// StoredMessage is one relayed packet persisted for an offline (or online)
// recipient until it is explicitly ACKed by that device.
type StoredMessage struct {
	MsgID   string          `json:"msg_id"`
	From    string          `json:"from"`
	TS      int64           `json:"ts"`
	Type    string          `json:"type"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

type deviceBox struct {
	Messages []StoredMessage `json:"messages"`
}

type fileFormat struct {
	Version int                   `json:"version"`
	Boxes   map[string]*deviceBox `json:"boxes"`
}

// Store is a concurrency-safe persistent message store.
type Store struct {
	mu   sync.Mutex
	path string
	boxe map[string]*deviceBox
}

// Open loads (or creates) the store backed by the given file path.
// An empty path disables persistence (pure in-memory, useful in tests).
func Open(path string) (*Store, error) {
	s := &Store{path: path, boxe: make(map[string]*deviceBox)}
	if path == "" {
		return s, nil
	}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, fmt.Errorf("store: read: %w", err)
	}
	var f fileFormat
	if err := json.Unmarshal(raw, &f); err != nil {
		// A corrupt store must not silently pass as empty.
		return nil, fmt.Errorf("store: parse %s: %w", path, err)
	}
	if f.Version != 1 {
		return nil, fmt.Errorf("store: unsupported file version %d", f.Version)
	}
	if f.Boxes != nil {
		s.boxe = f.Boxes
	}
	return s, nil
}

// saveLocked persists the store atomically. Must be called with mu held.
func (s *Store) saveLocked() error {
	if s.path == "" {
		return nil
	}
	f := fileFormat{Version: 1, Boxes: s.boxe}
	raw, err := json.Marshal(&f)
	if err != nil {
		return fmt.Errorf("store: marshal: %w", err)
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return fmt.Errorf("store: write temp: %w", err)
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return fmt.Errorf("store: rename: %w", err)
	}
	return nil
}

// Append stores one message for the recipient device id. When the per-device
// cap is exceeded the oldest message is dropped.
func (s *Store) Append(recipient string, m StoredMessage) error {
	if recipient == "" || m.MsgID == "" {
		return errors.New("store: recipient and msg_id are required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	b := s.boxe[recipient]
	if b == nil {
		b = &deviceBox{}
		s.boxe[recipient] = b
	}
	b.Messages = append(b.Messages, m)
	if len(b.Messages) > MaxStoredMessages {
		drop := len(b.Messages) - MaxStoredMessages
		b.Messages = append(b.Messages[:0], b.Messages[drop:]...)
	}
	return s.saveLocked()
}

// Pending returns (without deleting) all stored messages for a recipient,
// oldest first.
func (s *Store) Pending(recipient string) ([]StoredMessage, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b := s.boxe[recipient]
	if b == nil {
		return nil, nil
	}
	out := make([]StoredMessage, len(b.Messages))
	copy(out, b.Messages)
	return out, nil
}

// Ack removes the message with the given id from the recipient's box.
// Returns ErrNotFound if no such message exists.
func (s *Store) Ack(recipient, msgID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	b := s.boxe[recipient]
	if b == nil {
		return ErrNotFound
	}
	for i, m := range b.Messages {
		if m.MsgID == msgID {
			b.Messages = append(b.Messages[:i], b.Messages[i+1:]...)
			if len(b.Messages) == 0 {
				delete(s.boxe, recipient)
			}
			return s.saveLocked()
		}
	}
	return ErrNotFound
}

// Count returns the number of stored messages for a recipient.
func (s *Store) Count(recipient string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if b := s.boxe[recipient]; b != nil {
		return len(b.Messages)
	}
	return 0
}

// TotalCount returns the number of stored messages across all devices.
// Used by /healthz.
func (s *Store) TotalCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, b := range s.boxe {
		n += len(b.Messages)
	}
	return n
}

// Path reports the backing file path ("" when in-memory).
func (s *Store) Path() string { return s.path }

// EnsureDir makes sure the directory for the store file exists.
func EnsureDir(path string) error {
	dir := filepath.Dir(path)
	return os.MkdirAll(dir, 0o750)
}
