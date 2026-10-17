// Package relay implements the server-side packet router. It is deliberately
// content-blind: MESSAGE / FILE_* payloads are treated as opaque blobs and
// are never parsed beyond JSON envelope structure.
package relay

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log"
	"time"

	"github.com/boltun/server/internal/devices"
	"github.com/boltun/server/internal/protocol"
)

// Relay routes packets between connected sessions.
type Relay struct {
	reg      *devices.Registry
	logger   *log.Logger
	maxBytes int
}

func New(reg *devices.Registry, logger *log.Logger, maxBytes int) *Relay {
	return &Relay{reg: reg, logger: logger, maxBytes: maxBytes}
}

// Registry exposes the device registry (health endpoint, tests).
func (r *Relay) Registry() *devices.Registry { return r.reg }

func newSessionID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand failure is fatal-level; surface via panic so the
		// connection handler can close cleanly rather than mint weak IDs.
		panic("relay: entropy source failure: " + err.Error())
	}
	return hex.EncodeToString(b)
}

// HandleHello validates a HELLO packet payload and registers the session.
// It returns the WELCOME (or ERROR) packet to send back, plus the live
// session when registration succeeded (nil otherwise).
func (r *Relay) HandleHello(send chan []byte, raw json.RawMessage) (*protocol.Packet, *devices.Session) {
	var hello struct {
		DeviceID    string `json:"device_id"`
		ClientNonce string `json:"client_nonce"`
		CapVersion  int    `json:"client_version"`
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
	sess := &devices.Session{
		DeviceID:  hello.DeviceID,
		SessionID: newSessionID(),
		Nonce:     hello.ClientNonce,
		Send:      send,
	}
	if err := r.reg.Register(sess); err != nil {
		return r.errorPacket(protocol.ErrCodeUnauthorized,
			"device id already connected; disconnect the other session first", ""), nil
	}
	r.logger.Printf("session opened device=%s session=%s", sess.DeviceID, short(sess.SessionID))

	welcome := &protocol.Packet{
		Version: protocol.ProtocolVersion,
		Type:    protocol.PacketWelcome,
		From:    "server",
		Payload: mustJSON(protocol.WelcomePayload{
			ServerTime:      time.Now().UnixMilli(),
			SessionID:       sess.SessionID,
			E2EEActive:      false,
			E2EEWarning:     "END-TO-END ENCRYPTION NOT ACTIVE YET: this build relays plaintext test packets. Do not send real private data.",
			MaxPacketBytes:  r.maxBytes,
			PingIntervalSec: 25,
		}),
	}
	return welcome, sess
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
		// Skeleton does not persist device directory, so both map to OFFLINE.
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
