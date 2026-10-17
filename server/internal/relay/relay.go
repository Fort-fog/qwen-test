// Package relay implements the server-side packet router. It is deliberately
// content-blind: MESSAGE / FILE_* payloads are treated as opaque blobs and
// are never parsed beyond JSON envelope structure.
package relay

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"time"

	"github.com/boltun/server/internal/devices"
	"github.com/boltun/server/internal/protocol"
	"github.com/boltun/server/internal/store"
)

// Relay routes packets between connected sessions.
type Relay struct {
	reg      *devices.Registry
	store    *store.Store
	logger   *log.Logger
	maxBytes int
}

func New(reg *devices.Registry, st *store.Store, logger *log.Logger, maxBytes int) *Relay {
	return &Relay{reg: reg, store: st, logger: logger, maxBytes: maxBytes}
}

// Registry exposes the device registry (health endpoint, tests).
func (r *Relay) Registry() *devices.Registry { return r.reg }

// Store exposes the message store (health endpoint, tests).
func (r *Relay) Store() *store.Store { return r.store }

func newSessionID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand failure is fatal-level; surface via panic so the
		// connection handler can close cleanly rather than mint weak IDs.
		panic("relay: entropy source failure: " + err.Error())
	}
	return hex.EncodeToString(b)
}

// e2eeWarningFor returns the WELCOME warning text for the session's E2E
// posture. Empty string means encryption is active (no warning banner).
func e2eeWarningFor(active bool) string {
	if active {
		return ""
	}
	return "END-TO-END ENCRYPTION NOT ACTIVE YET: this client did not present an identity key. Do not send real private data."
}

// HandleHello validates a HELLO packet payload and registers the session.
// It returns the WELCOME (or ERROR) packet to send back, plus the live
// session when registration succeeded (nil otherwise). If the device has
// messages queued in the offline store, they are flushed proactively into
// the session queue as SYNC_RESPONSE right after registration — the client
// does not need to send SYNC_REQUEST first (explicit SYNC_REQUEST still
// works and is idempotent).
func (r *Relay) HandleHello(send chan []byte, raw json.RawMessage) (*protocol.Packet, *devices.Session) {
	var hello struct {
		DeviceID    string `json:"device_id"`
		ClientNonce string `json:"client_nonce"`
		CapVersion  int    `json:"client_version"`
		IdentityPub string `json:"identity_pub"` // base64 std X25519 pub (optional)
	}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &hello); err != nil {
			return r.errorPacket(protocol.ErrCodeMalformed, "HELLO payload is not valid JSON", ""), nil
		}
	}
	if !validDeviceID(hello.DeviceID) {
		return r.errorPacket(protocol.ErrCodeMalformed,
			"HELLO requires a well-formed device_id (8..64 chars of [A-Za-z0-9_-])", ""), nil
	}
	// identity_pub is optional (legacy/plaintext clients). When present it
	// must be a well-formed X25519 public key; the relay never interprets
	// message payloads, but knowing peers' identity keys lets it publish
	// them for E2E envelope sealing by other clients.
	if hello.IdentityPub != "" {
		pk, err := base64.StdEncoding.DecodeString(hello.IdentityPub)
		if err != nil || len(pk) != 32 {
			return r.errorPacket(protocol.ErrCodeMalformed,
				"HELLO identity_pub must be base64 of a 32-byte X25519 public key", ""), nil
		}
	}
	sess := &devices.Session{
		DeviceID:    hello.DeviceID,
		SessionID:   newSessionID(),
		Nonce:       hello.ClientNonce,
		IdentityPub: hello.IdentityPub,
		Send:        send,
	}
	if err := r.reg.Register(sess); err != nil {
		return r.errorPacket(protocol.ErrCodeUnauthorized,
			"device id already connected; disconnect the other session first", ""), nil
	}
	r.logger.Printf("session opened device=%s session=%s", sess.DeviceID, short(sess.SessionID))

	pending := 0
	if r.store != nil {
		pending = r.store.Count(sess.DeviceID)
	}

	// E2E posture: the relay itself never decrypts anything. A session that
	// announced an identity key at HELLO is capable of sealing/opening v1
	// envelopes; we report e2ee_active accordingly and hand back the peer's
	// identity key (when online) so the client can encrypt for it. Clients
	// without identity_pub keep receiving the plaintext-mode warning.
	e2eeActive := sess.IdentityPub != ""
	welcome := &protocol.Packet{
		Version: protocol.ProtocolVersion,
		Type:    protocol.PacketWelcome,
		From:    "server",
		Payload: mustJSON(protocol.WelcomePayload{
			ServerTime:      time.Now().UnixMilli(),
			SessionID:       sess.SessionID,
			E2EEActive:      e2eeActive,
			E2EEWarning:     e2eeWarningFor(e2eeActive),
			MaxPacketBytes:  r.maxBytes,
			PingIntervalSec: 25,
			PendingMessages: pending,
		}),
	}

	// Proactive flush: deliver queued offline messages immediately after the
	// handshake so clients don't have to issue SYNC_REQUEST on every reconnect.
	if pending > 0 {
		r.flushPending(sess)
	}

	return welcome, sess
}

// flushPending sends a SYNC_RESPONSE with everything currently queued for
// the session's device. Safe to call repeatedly (idempotent until acked).
func (r *Relay) flushPending(sess *devices.Session) {
	if r.store == nil {
		return
	}
	msgs, err := r.store.Pending(sess.DeviceID)
	if err != nil || len(msgs) == 0 {
		return
	}
	synced := make([]protocol.SyncedMessage, 0, len(msgs))
	for _, m := range msgs {
		synced = append(synced, protocol.SyncedMessage{
			MsgID:   m.MsgID,
			From:    m.From,
			Type:    m.Type,
			TS:      m.TS,
			Payload: m.Payload,
		})
	}
	resp := &protocol.Packet{
		Version: protocol.ProtocolVersion,
		Type:    protocol.PacketSyncResponse,
		From:    "server",
		To:      sess.DeviceID,
		MsgID:   newSessionID(), // synthetic id; dedup happens per message inside
		TS:      time.Now().UnixMilli(),
		Payload: mustJSON(protocol.SyncResponsePayload{Messages: synced}),
	}
	send(sess.Send, resp)
	r.logger.Printf("auto-sync device=%s messages=%d", sess.DeviceID, len(synced))
}

// Dispatch processes one validated inbound packet from an authenticated
// session. out is the sender's own delivery queue.
func (r *Relay) Dispatch(sender *devices.Session, p *protocol.Packet, out chan []byte) {
	// Identity binding: the server overwrites From with the session-bound
	// device id. A client cannot spoof another device through this field.
	p.From = sender.DeviceID

	switch p.Type {
	case protocol.PacketPing:
		pong := &protocol.Packet{
			Version: protocol.ProtocolVersion,
			Type:    protocol.PacketPong,
			From:    "server",
			MsgID:   p.MsgID,
			TS:      time.Now().UnixMilli(),
		}
		send(out, pong)
		return

	case protocol.PacketMessage, protocol.PacketMessageAck, protocol.PacketDeliveryStat,
		protocol.FileOffer, protocol.FileChunk, protocol.FileComplete,
		protocol.PairRequest, protocol.PairAccept, protocol.PairReject,
		protocol.CallOffer, protocol.CallAnswer, protocol.CallICE,
		protocol.CallReject, protocol.CallEnd:
		r.routeToPeer(sender, p, out)

	case protocol.PacketSyncRequest:
		r.handleSync(sender, p, out)

	case protocol.PacketStoreAck:
		r.handleStoreAck(sender, p, out)

	case protocol.PacketKeyRequest:
		r.handleKeyRequest(sender, p, out)

	case protocol.PacketDeviceReg:
		// Reserved for key-based registration handshake (not implemented).
		send(out, r.errorPacketAt(protocol.ErrCodeNotSupported,
			"DEVICE_REGISTER key-based enrollment is not implemented in this build", p.MsgID))

	default:
		send(out, r.errorPacketAt(protocol.ErrCodeMalformed, "unexpected packet type", p.MsgID))
	}
}

// routeToPeer relays p to the recipient session, or reports availability.
func (r *Relay) routeToPeer(sender *devices.Session, p *protocol.Packet, out chan []byte) {
	if p.To == sender.DeviceID {
		send(out, r.errorPacketAt(protocol.ErrCodeMalformed, "cannot send to self", p.MsgID))
		return
	}
	peer, ok := r.reg.Get(p.To)
	if !ok {
		// Deterministic status: peer has never been seen OR is not online.
		// MESSAGE packets to offline peers are persisted in the store and
		// delivered later via SYNC_REQUEST / STORE_ACK.
		if p.Type == protocol.PacketMessage && r.store != nil {
			sm := store.StoredMessage{
				MsgID:   p.MsgID,
				From:    sender.DeviceID,
				TS:      time.Now().UnixMilli(),
				Type:    string(p.Type),
				Payload: p.Payload,
			}
			if err := r.store.Append(p.To, sm); err != nil {
				r.logger.Printf("store append failed recipient=%s msg_id=%s: %v", p.To, p.MsgID, err)
				send(out, r.errorPacketAt(protocol.ErrCodeInternal, "offline storage failed", p.MsgID))
				return
			}
			storedAck := &protocol.Packet{
				Version: protocol.ProtocolVersion,
				Type:    protocol.PacketMessageAck,
				From:    "server",
				To:      sender.DeviceID,
				MsgID:   p.MsgID + ".stored",
				TS:      time.Now().UnixMilli(),
				Payload: mustJSON(map[string]any{"ref_msg_id": p.MsgID, "stage": "STORED_FOR_LATER_DELIVERY"}),
			}
			send(out, storedAck)
			return
		}
		send(out, r.errorPacketAt(protocol.ErrCodeOffline,
			"recipient is not currently connected", p.MsgID))
		return
	}
	// Server never inspects p.Payload contents (E2E design).
	raw, err := protocol.Encode(p)
	if err != nil {
		send(out, r.errorPacketAt(protocol.ErrCodeInternal, "encode failed", p.MsgID))
		return
	}
	select {
	case peer.Send <- raw:
		r.reg.Touch(peer.SessionID)
	default:
		// Peer write queue full -> treat as unavailable rather than block.
		send(out, r.errorPacketAt(protocol.ErrCodeRateLimited,
			"recipient send buffer full", p.MsgID))
		return
	}
	// Transport-level receipt confirmation only. This is NOT proof of
	// reading, and NOT an E2E ack — clients must define their own.
	if p.Type == protocol.PacketMessage {
		ack := &protocol.Packet{
			Version: protocol.ProtocolVersion,
			Type:    protocol.PacketMessageAck,
			From:    "server",
			To:      sender.DeviceID,
			MsgID:   p.MsgID + ".relay",
			TS:      time.Now().UnixMilli(),
			Payload: mustJSON(map[string]any{"ref_msg_id": p.MsgID, "stage": "RELAYED_TO_PEER"}),
		}
		send(out, ack)
	}
}

func send(ch chan []byte, p *protocol.Packet) {
	raw, err := protocol.Encode(p)
	if err != nil {
		return
	}
	select {
	case ch <- raw:
	default:
	}
}

func (r *Relay) errorPacket(code protocol.ErrorCode, msg, ref string) *protocol.Packet {
	return r.errorPacketAt(code, msg, ref)
}

func (r *Relay) errorPacketAt(code protocol.ErrorCode, msg, ref string) *protocol.Packet {
	return &protocol.Packet{
		Version: protocol.ProtocolVersion,
		Type:    protocol.PacketError,
		From:    "server",
		Payload: mustJSON(protocol.ErrorPayload{Code: code, Message: msg, RefMsgID: ref}),
	}
}

func mustJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		b = []byte(`{"code":"INTERNAL_ERROR","message":"payload marshal failed"}`)
	}
	return b
}

// validDeviceID checks syntax only. Syntax validity is NOT identity proof.
func validDeviceID(id string) bool {
	if len(id) < 8 || len(id) > 64 {
		return false
	}
	for _, c := range id {
		ok := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '-' || c == '_'
		if !ok {
			return false
		}
	}
	return true
}

func short(s string) string {
	if len(s) > 8 {
		return s[:8]
	}
	return s
}

// handleSync delivers the recipient's stored offline queue. Messages are
// NOT deleted here — deletion happens only on explicit STORE_ACK, so a
// client that crashes mid-sync will receive them again next time
// (at-least-once delivery; clients must deduplicate by msg_id).
func (r *Relay) handleSync(sender *devices.Session, p *protocol.Packet, out chan []byte) {
	if r.store == nil {
		send(out, r.errorPacketAt(protocol.ErrCodeNotSupported,
			"offline storage disabled on this server", p.MsgID))
		return
	}
	msgs, err := r.store.Pending(sender.DeviceID)
	if err != nil {
		send(out, r.errorPacketAt(protocol.ErrCodeInternal, "store read failed", p.MsgID))
		return
	}
	synced := make([]protocol.SyncedMessage, 0, len(msgs))
	for _, m := range msgs {
		synced = append(synced, protocol.SyncedMessage{
			MsgID:   m.MsgID,
			From:    m.From,
			Type:    m.Type,
			TS:      m.TS,
			Payload: m.Payload,
		})
	}
	resp := &protocol.Packet{
		Version: protocol.ProtocolVersion,
		Type:    protocol.PacketSyncResponse,
		From:    "server",
		To:      sender.DeviceID,
		MsgID:   p.MsgID,
		TS:      time.Now().UnixMilli(),
		Payload: mustJSON(protocol.SyncResponsePayload{Messages: synced}),
	}
	send(out, resp)
}

// handleKeyRequest answers KEY_REQUEST lookups: returns the identity public
// key an ONLINE peer announced at HELLO, so the requester can seal an E2E
// envelope for it. The relay only publishes public keys that clients chose
// to announce; it never sees private material or message content.
func (r *Relay) handleKeyRequest(sender *devices.Session, p *protocol.Packet, out chan []byte) {
	var req struct {
		TargetDeviceID string `json:"target_device_id"`
	}
	if len(p.Payload) == 0 || json.Unmarshal(p.Payload, &req) != nil || req.TargetDeviceID == "" {
		send(out, r.errorPacketAt(protocol.ErrCodeMalformed,
			"KEY_REQUEST requires payload {\"target_device_id\": ...}", p.MsgID))
		return
	}
	pub, ok := r.reg.IdentityPub(req.TargetDeviceID)
	resp := &protocol.Packet{
		Version: protocol.ProtocolVersion,
		Type:    protocol.PacketKeyResponse,
		From:    "server",
		To:      sender.DeviceID,
		MsgID:   p.MsgID, // correlation id
		TS:      time.Now().UnixMilli(),
		Payload: mustJSON(protocol.KeyResponsePayload{
			TargetDeviceID: req.TargetDeviceID,
			Found:          ok,
			IdentityPub:    pub,
		}),
	}
	send(out, resp)
}

// handleStoreAck removes one previously-synced message from the store after
// the recipient confirms durable receipt. Only the authenticated recipient
// may ack its own queue entries (sender identity is bound to the session).
func (r *Relay) handleStoreAck(sender *devices.Session, p *protocol.Packet, out chan []byte) {
	if r.store == nil {
		send(out, r.errorPacketAt(protocol.ErrCodeNotSupported,
			"offline storage disabled on this server", p.MsgID))
		return
	}
	var ack struct {
		RefMsgID string `json:"ref_msg_id"`
	}
	if len(p.Payload) > 0 {
		if err := json.Unmarshal(p.Payload, &ack); err != nil || ack.RefMsgID == "" {
			send(out, r.errorPacketAt(protocol.ErrCodeMalformed,
				"STORE_ACK requires payload {\"ref_msg_id\": ...}", p.MsgID))
			return
		}
	} else {
		send(out, r.errorPacketAt(protocol.ErrCodeMalformed,
			"STORE_ACK requires payload {\"ref_msg_id\": ...}", p.MsgID))
		return
	}
	err := r.store.Ack(sender.DeviceID, ack.RefMsgID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		// Idempotent: already removed (duplicate ack). Not an error.
		r.logger.Printf("store_ack noop device=%s ref=%s", sender.DeviceID, ack.RefMsgID)
	case err != nil:
		send(out, r.errorPacketAt(protocol.ErrCodeInternal, "store ack failed", p.MsgID))
	default:
		r.logger.Printf("store_ack device=%s ref=%s", sender.DeviceID, ack.RefMsgID)
	}
}
