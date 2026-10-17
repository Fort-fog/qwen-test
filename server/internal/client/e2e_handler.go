package client

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/boltun/server/internal/e2e"
	"github.com/boltun/server/internal/protocol"
)

// E2EEnvelopePayload is the MESSAGE payload format produced by
// SendE2EMessage and consumed by OpenIncoming (protocol "e2ee" v1):
//
//	{"kind":"e2ee","v":1,"env":"<base64 std envelope>"}
//
// The relay only ever sees this opaque object; plaintext never appears on
// the wire. See docs/protocol/e2e-v1.md for the full envelope contract.
type E2EEnvelopePayload struct {
	Kind string `json:"kind"` // always "e2ee"
	V    int    `json:"v"`    // envelope version, currently 1
	Env  string `json:"env"`  // base64 std of the raw e2e envelope bytes
}

// E2EHandler adds end-to-end encryption on top of a plain Client:
//   - announces our identity public key in HELLO (via Config.IdentityPub);
//   - resolves peer identity keys through KEY_REQUEST / KEY_RESPONSE;
//   - seals outgoing messages with e2e.Seal and opens incoming ones with
//     e2e.Open before they reach the user handler.
//
// It wraps an EventHandler: OnMessage receives ONLY messages that
// successfully opened against our identity key with the authenticated
// sender binding. Messages that fail to open are reported via OnError so
// the UI can show them as undecryptable — they are never silently dropped.
//
// Trust limitation (IMPORTANT): a key obtained via KEY_RESPONSE is merely
// *announced* by the peer at its HELLO. The relay forwards it verbatim but
// does not prove ownership — this exchange is NOT MITM-resistant
// authentication. Out-of-band fingerprint verification is future work.
type E2EHandler struct {
	*Client
	user UserEvents

	mu       sync.Mutex
	keyPair  *e2e.KeyPair
	peerKeys map[string]*[32]byte // deviceID -> identity pub (resolved)
	waiters  map[string]chan *[32]byte
	deferred map[string][]Message // deviceID -> envelopes awaiting its key
}

// UserEvents is the reduced callback set applications implement when using
// E2EHandler (OnMessage payloads are already decrypted).
type UserEvents interface {
	OnWelcome(w Welcome)
	// OnPlainText delivers incoming MESSAGEs whose payload is not an "e2ee"
	// envelope (legacy / unencrypted senders). May be nil-safe ignored.
	OnPlainText(m Message)
	// OnDecrypted delivers an incoming message after successful Open.
	// From is the server-authenticated sender device id.
	OnDecrypted(msgID, from string, plaintext []byte, ts int64)
	OnError(e ServerError)
	OnClosed(reason error)
}

// NewE2E creates an E2E-enabled client session. kp is this device's
// long-lived identity key pair; its public part is announced at HELLO.
func NewE2E(cfg Config, kp *e2e.KeyPair, user UserEvents) (*E2EHandler, error) {
	cfg.IdentityPub = base64.StdEncoding.EncodeToString(kp.Public[:])
	h := &E2EHandler{
		user:     user,
		keyPair:  kp,
		peerKeys: make(map[string]*[32]byte),
		waiters:  make(map[string]chan *[32]byte),
		deferred: make(map[string][]Message),
	}
	c, err := New(cfg, h)
	if err != nil {
		return nil, err
	}
	h.Client = c
	return h, nil
}

// --- EventHandler plumbing (internal, not part of UserEvents surface) ---

func (h *E2EHandler) OnWelcome(w Welcome)    { h.user.OnWelcome(w) }
func (h *E2EHandler) OnAck(a Ack)            {}
func (h *E2EHandler) OnKeyResponse(k KeyRes) { h.handleKeyResponse(k) }
func (h *E2EHandler) OnClosed(err error)     { h.user.OnClosed(err) }

func (h *E2EHandler) OnError(e ServerError) {
	// A failed KEY_REQUEST lookup surfaces as PEER_NOT_FOUND/timeout; pass
	// all server errors through — the app decides what is relevant.
	h.user.OnError(e)
}

// maxDeferredPerPeer bounds how many undecryptable envelopes we keep per
// sender while waiting for its identity key (memory guard).
const maxDeferredPerPeer = 100

// OnMessage transparently opens "e2ee" envelopes; anything else is passed
// to OnPlainText untouched.
func (h *E2EHandler) OnMessage(m Message) {
	h.tryOpen(m)
}

// tryOpen attempts to open m. Envelopes whose sender key is not yet known
// are queued in deferred and retried automatically when the KEY_RESPONSE
// for that sender arrives; they are also released via forget() from the
// client's msg_id dedupe cache so an external re-delivery can re-process
// them. All other outcomes (plaintext passthrough, malformed envelope,
// failed Open, successful decrypt) are terminal — no retry.
func (h *E2EHandler) tryOpen(m Message) {
	var env E2EEnvelopePayload
	if err := json.Unmarshal(m.Payload, &env); err != nil || env.Kind != "e2ee" {
		h.user.OnPlainText(m)
		return
	}
	raw, err := e2e.DecodeEnvelope(env.Env)
	if err != nil {
		h.user.OnError(ServerError{Code: "E2E_MALFORMED_ENVELOPE", Message: "cannot base64-decode envelope", RefMsgID: m.MsgID})
		return
	}
	senderPub, ok := h.resolvedKey(m.From)
	if !ok {
		// We cannot open without the sender's key. Queue the envelope for
		// automatic retry when KEY_RESPONSE lands, ask for the key (best
		// effort) and report the message as undecryptable-for-now.
		h.mu.Lock()
		dq := h.deferred[m.From]
		if len(dq) < maxDeferredPerPeer {
			h.deferred[m.From] = append(dq, m)
		}
		h.mu.Unlock()
		h.forget(m.MsgID) // allow re-processing once the key resolves
		_ = h.RequestPeerKey(m.From)
		h.user.OnError(ServerError{Code: "E2E_NO_SENDER_KEY", Message: "sender identity key unknown yet", RefMsgID: m.MsgID})
		return
	}
	plain, err := e2e.Open(h.keyPair, raw, m.MsgID, senderPub)
	if err != nil {
		h.user.OnError(ServerError{Code: "E2E_OPEN_FAILED", Message: err.Error(), RefMsgID: m.MsgID})
		return
	}
	h.user.OnDecrypted(m.MsgID, m.From, plain, m.TS)
}

// --- Public E2E API ---

// PublicKeyB64 returns this device's identity public key (base64 std).
func (h *E2EHandler) PublicKeyB64() string {
	return base64.StdEncoding.EncodeToString(h.keyPair.Public[:])
}

// PeerKey returns a previously resolved peer identity key, if any.
func (h *E2EHandler) PeerKey(deviceID string) (*[32]byte, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	k, ok := h.peerKeys[deviceID]
	return k, ok
}

func (h *E2EHandler) resolvedKey(deviceID string) (*[32]byte, bool) {
	return h.PeerKey(deviceID)
}

// FetchPeerKey issues a KEY_REQUEST for target and returns a channel that
// yields the parsed 32-byte X25519 identity key when KEY_RESPONSE arrives
// (closed without a value if the lookup fails). Results are cached in the
// handler; repeated fetches for a known peer return immediately.
func (h *E2EHandler) FetchPeerKey(target string) (<-chan *[32]byte, error) {
	h.mu.Lock()
	if k, ok := h.peerKeys[target]; ok {
		h.mu.Unlock()
		ch := make(chan *[32]byte, 1)
		ch <- k
		return ch, nil
	}
	ch, exists := h.waiters[target]
	if !exists {
		ch = make(chan *[32]byte, 1)
		h.waiters[target] = ch
	}
	h.mu.Unlock()
	if exists {
		// A request is already in flight; reuse its waiter channel.
		return ch, nil
	}
	if err := h.RequestPeerKey(target); err != nil {
		h.mu.Lock()
		delete(h.waiters, target)
		h.mu.Unlock()
		return nil, err
	}
	return ch, nil
}

func (h *E2EHandler) handleKeyResponse(k KeyRes) {
	var resolved *[32]byte
	if pub, err := base64.StdEncoding.DecodeString(k.IdentityPub); err == nil && len(pub) == 32 && k.Found {
		var key [32]byte
		copy(key[:], pub)
		resolved = &key
	}
	h.mu.Lock()
	if resolved != nil {
		h.peerKeys[k.TargetDeviceID] = resolved
	}
	ch, waiting := h.waiters[k.TargetDeviceID]
	if waiting {
		delete(h.waiters, k.TargetDeviceID)
	}
	retry := h.deferred[k.TargetDeviceID]
	delete(h.deferred, k.TargetDeviceID)
	h.mu.Unlock()
	if waiting {
		if resolved != nil {
			ch <- resolved
		}
		close(ch)
	}
	// Retry envelopes that arrived before the sender's key was known.
	for _, m := range retry {
		mm := m
		go h.tryOpen(mm)
	}
}

// SealFor encrypts plaintext for target using target's resolved identity
// key, returning the JSON MESSAGE payload ready for SendMessage.
func (h *E2EHandler) SealFor(target string, msgID string, plaintext []byte) (json.RawMessage, error) {
	key, ok := h.PeerKey(target)
	if !ok {
		return nil, fmt.Errorf("boltun/client/e2e: no identity key for %q (FetchPeerKey first)", target)
	}
	env, err := e2e.Seal(h.keyPair, key, msgID, plaintext)
	if err != nil {
		return nil, err
	}
	return mustJSON(E2EEnvelopePayload{
		Kind: "e2ee",
		V:    1,
		Env:  e2e.EncodeEnvelope(env),
	}), nil
}

// SendE2EMessage seals plaintext for recipient and sends it as a MESSAGE.
// If the recipient's key is not yet known, it is fetched first (blocking
// until KEY_RESPONSE arrives or the lookup fails). Returns the msg_id used
// for ack correlation and Open binding — the same id is bound into the
// envelope AAD, so relaying cannot re-route or replay it under another id.
func (h *E2EHandler) SendE2EMessage(recipient string, plaintext []byte) (string, error) {
	if _, ok := h.PeerKey(recipient); !ok {
		ch, err := h.FetchPeerKey(recipient)
		if err != nil {
			return "", err
		}
		key, ok := <-ch
		if !ok || key == nil {
			return "", fmt.Errorf("boltun/client/e2e: peer key lookup failed for %q", recipient)
		}
	}
	// Generate msg_id BEFORE sealing so the envelope AAD binds it.
	msgID := newMsgID()
	payload, err := h.SealFor(recipient, msgID, plaintext)
	if err != nil {
		return "", err
	}
	return h.sendWithID(protocol.PacketMessage, recipient, msgID, payload)
}

// sendWithID is Client.send with a caller-chosen msg_id (needed because the
// id must exist before Seal can bind it into AAD).
func (c *Client) sendWithID(t protocol.PacketType, to, msgID string, payload json.RawMessage) (string, error) {
	if !c.Connected() {
		return "", ErrNotConnected
	}
	p := newEnvelope(t)
	p.MsgID = msgID
	p.From = c.cfg.DeviceID // server overwrites with bound identity anyway
	p.To = to
	p.Payload = payload
	select {
	case c.sendCh <- p:
		return msgID, nil
	case <-c.done:
		return "", ErrNotConnected
	}
}
