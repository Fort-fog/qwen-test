// Package pairing defines the interfaces and data model for QR-based
// trusted-device linking.
//
// STATUS: PROTOCOL STUB ONLY. No part of this package performs real
// cryptography yet, and nothing here should be treated as secure binding.
// The design is documented in docs/SECURITY.md §"Device pairing".
package pairing

import (
	"crypto/rand"
	"encoding/base32"
	"errors"
	"sync"
	"time"
)

// Session state machine: PENDING -> SCANNED -> VERIFIED -> COMPLETED | REJECTED | EXPIRED | CANCELLED
type State string

const (
	StatePending   State = "PENDING"
	StateScanned   State = "SCANNED"
	StateVerified  State = "VERIFIED"
	StateCompleted State = "COMPLETED"
	StateRejected  State = "REJECTED"
	StateExpired   State = "EXPIRED"
	StateCancelled State = "CANCELLED"
)

// Challenge is what the old (trusted) device encodes into the QR code.
// It contains NO secret keys. The shared_secret_hash is a one-time random
// value committed to up front; the new device must later prove knowledge
// of it inside an authenticated channel (zero-knowledge proof or signed
// confirmation — final choice pending crypto-library decision).
type Challenge struct {
	Version          int       `json:"version"`        // pairing format version
	SessionID        string    `json:"session_id"`     // random one-time id
	OldDeviceID      string    `json:"old_device_id"`  // claiming identity (not proof!)
	OldDevicePub     string    `json:"old_device_pub"` // public key, base64 (placeholder field)
	SharedSecretHash string    `json:"secret_commit"`  // commitment hash of one-time secret
	ExpiresAt        time.Time `json:"expires_at"`
	// Display info shown to the scanning user (device name/model hint).
	DeviceLabel string `json:"device_label,omitempty"`
}

// Manager tracks live pairing sessions server-side. Sessions are single-use:
// once completed/rejected/cancelled/expired the challenge cannot be reused
// (QR replay protection).
type Manager struct {
	mu   sync.Mutex
	sess map[string]*entry
	ttl  time.Duration
}

type entry struct {
	chal  Challenge
	state State
	nonce string // server-issued random per session
}

var (
	ErrNotFound = errors.New("pairing: unknown session")
	ErrReused   = errors.New("pairing: session already used or not pending")
	ErrExpired  = errors.New("pairing: session expired")
	ErrNotImpl  = errors.New("pairing: secure pairing NOT IMPLEMENTED - stub only")
)

func NewManager(ttl time.Duration) *Manager {
	return &Manager{sess: make(map[string]*entry), ttl: ttl}
}

func randomID() string {
	b := make([]byte, 15)
	if _, err := rand.Read(b); err != nil {
		panic("pairing: entropy failure: " + err.Error())
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)
}

// CreateChallenge starts a new pairing session (called by the trusted
// device). Returns the challenge to render as QR.
//
// STUB WARNING: the returned challenge does not yet include cryptographic
// proofs of the old device's identity. Do not ship to production.
func (m *Manager) CreateChallenge(oldDeviceID, label string) (*Challenge, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c := &Challenge{
		Version:          1,
		SessionID:        randomID(),
		OldDeviceID:      oldDeviceID,
		SharedSecretHash: randomID() + "." + randomID(), // placeholder commitment
		ExpiresAt:        time.Now().Add(m.ttl),
		DeviceLabel:      label,
	}
	m.sess[c.SessionID] = &entry{chal: *c, state: StatePending, nonce: randomID()}
	return c, nil
}

// Consume marks a session as scanned by the new device and returns server
// nonce material for the confirmation step. Single use.
func (m *Manager) Consume(sessionID string) (*Challenge, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.sess[sessionID]
	if !ok {
		return nil, ErrNotFound
	}
	if time.Now().After(e.chal.ExpiresAt) {
		e.state = StateExpired
		delete(m.sess, sessionID)
		return nil, ErrExpired
	}
	if e.state != StatePending {
		return nil, ErrReused
	}
	e.state = StateScanned
	c := e.chal
	return &c, nil
}

// Cancel lets the originating device abort a pending pairing.
func (m *Manager) Cancel(sessionID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.sess[sessionID]
	if !ok {
		return ErrNotFound
	}
	e.state = StateCancelled
	delete(m.sess, sessionID)
	return nil
}

// Complete transitions SCANNED -> COMPLETED. In the real protocol this may
// only be called after the server verified a cryptographic confirmation
// from BOTH devices. Currently it is an unverified stub.
func (m *Manager) Complete(sessionID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.sess[sessionID]
	if !ok {
		return ErrNotFound
	}
	if e.state != StateScanned {
		return ErrReused
	}
	// TODO(security): verify double confirmation + ZK proof of secret_commit.
	e.state = StateCompleted
	delete(m.sess, sessionID)
	return nil
}

// StubError makes explicit that no caller may rely on this build for trust
// establishment.
func StubError() error { return ErrNotImpl }
