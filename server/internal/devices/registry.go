// Package devices maintains the registry of connected device sessions.
//
// IMPORTANT (prototype status): in the current skeleton, a device "registers"
// by sending HELLO with a self-chosen device ID and an ephemeral session
// nonce. This proves *presence*, NOT identity. Real authentication requires
// key-based proof (see docs/SECURITY.md, "Device authentication"). The server
// deliberately does not store any private key material — it never receives
// any.
package devices

import (
	"errors"
	"sync"
	"time"
)

// ErrExists is returned when registering a duplicate active device ID.
var ErrExists = errors.New("devices: device id already connected")

// Session describes one live connection bound to a device identity claim.
type Session struct {
	DeviceID    string
	SessionID   string // server-generated opaque id
	Nonce       string // client-provided random nonce for this session
	IdentityPub string // client's long-lived X25519 public key, base64 std (optional)
	ConnectedAt time.Time
	LastSeen    time.Time
	// Send queues a serialised packet to this session's writer goroutine.
	// Managed by the transport layer; nil inside pure-registry tests.
	Send chan []byte
}

// Registry is a concurrency-safe map of online device sessions.
type Registry struct {
	mu       sync.RWMutex
	sessions map[string]*Session // deviceID -> session
	tokens   map[string]string   // sessionID -> deviceID
}

func NewRegistry() *Registry {
	return &Registry{
		sessions: make(map[string]*Session),
		tokens:   make(map[string]string),
	}
}

// Register adds a session. Fails if the device ID is already online.
func (r *Registry) Register(s *Session) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, dup := r.sessions[s.DeviceID]; dup {
		return ErrExists
	}
	now := time.Now()
	s.ConnectedAt = now
	s.LastSeen = now
	r.sessions[s.DeviceID] = s
	r.tokens[s.SessionID] = s.DeviceID
	return nil
}

// Unregister removes a session by session ID. It ignores stale unregister
// calls (e.g. from a reconnecting client's old goroutine).
func (r *Registry) Unregister(sessionID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	dev, ok := r.tokens[sessionID]
	if !ok {
		return
	}
	if cur, ok := r.sessions[dev]; ok && cur.SessionID == sessionID {
		delete(r.sessions, dev)
	}
	delete(r.tokens, sessionID)
}

// Get returns the live session for a device ID.
func (r *Registry) Get(deviceID string) (*Session, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	s, ok := r.sessions[deviceID]
	return s, ok
}

// Touch updates LastSeen for a session.
func (r *Registry) Touch(sessionID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if dev, ok := r.tokens[sessionID]; ok {
		if s, ok := r.sessions[dev]; ok && s.SessionID == sessionID {
			s.LastSeen = time.Now()
		}
	}
}

// Count returns the number of online sessions.
func (r *Registry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.sessions)
}

// Online reports whether a device currently has a live connection.
func (r *Registry) Online(deviceID string) bool {
	_, ok := r.Get(deviceID)
	return ok
}

// IdentityPub returns the announced X25519 identity public key (base64 std)
// of an ONLINE device, if it presented one at HELLO. The relay only stores
// and publishes public keys — never private material.
func (r *Registry) IdentityPub(deviceID string) (string, bool) {
	s, ok := r.Get(deviceID)
	if !ok || s.IdentityPub == "" {
		return "", false
	}
	return s.IdentityPub, true
}
