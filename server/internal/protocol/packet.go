// Package protocol defines the versioned wire protocol used between
// BOLTUN clients and the relay server.
//
// Security notes (must be read before extending this package):
//   - SenderID / To fields are NOT authentication. The server binds the
//     authenticated session identity to the WebSocket connection; any
//     mismatch is rejected. See internal/relay.
//   - Payload of MESSAGE and FILE_* packets must be opaque end-to-end
//     encrypted blobs produced on the client. The server never decrypts.
package protocol

import (
	"encoding/json"
	"fmt"
)

// ProtocolVersion is the current wire protocol version.
const ProtocolVersion = 1

// MaxPacketSize is the maximum size (in bytes) of a single JSON packet
// accepted from a client. Enforced at the transport layer.
const MaxPacketSize = 256 * 1024 // 256 KiB

// PacketType enumerates all packet types of the protocol.
type PacketType string

const (
	PacketHello        PacketType = "HELLO"
	PacketWelcome      PacketType = "WELCOME"
	PacketError        PacketType = "ERROR"
	PacketPing         PacketType = "PING"
	PacketPong         PacketType = "PONG"
	PacketDeviceReg    PacketType = "DEVICE_REGISTER"
	PairRequest        PacketType = "PAIR_REQUEST"
	PairAccept         PacketType = "PAIR_ACCEPT"
	PairReject         PacketType = "PAIR_REJECT"
	PacketMessage      PacketType = "MESSAGE"
	PacketMessageAck   PacketType = "MESSAGE_ACK"
	PacketDeliveryStat PacketType = "DELIVERY_STATUS"
	PacketSyncRequest  PacketType = "SYNC_REQUEST"
	PacketSyncResponse PacketType = "SYNC_RESPONSE"
	PacketStoreAck     PacketType = "STORE_ACK"
	FileOffer          PacketType = "FILE_OFFER"
	FileChunk          PacketType = "FILE_CHUNK"
	FileComplete       PacketType = "FILE_COMPLETE"
	CallOffer          PacketType = "CALL_OFFER"
	CallAnswer         PacketType = "CALL_ANSWER"
	CallICE            PacketType = "CALL_ICE"
	CallReject         PacketType = "CALL_REJECT"
	CallEnd            PacketType = "CALL_END"
)

var validTypes = map[PacketType]bool{
	PacketHello: true, PacketWelcome: true, PacketError: true,
	PacketPing: true, PacketPong: true, PacketDeviceReg: true,
	PairRequest: true, PairAccept: true, PairReject: true,
	PacketMessage: true, PacketMessageAck: true, PacketDeliveryStat: true,
	FileOffer: true, FileChunk: true, FileComplete: true,
	CallOffer: true, CallAnswer: true, CallICE: true,
	CallReject: true, CallEnd: true,
}

// IsValid reports whether t is a known packet type.
func (t PacketType) IsValid() bool { return validTypes[t] }

// ClientToServerTypes lists packet types a client may send to the server.
// WELCOME and PONG are server-only; sending them from a client is an error.
var ClientToServerTypes = map[PacketType]bool{
	PacketHello: true, PacketPing: true, PacketDeviceReg: true,
	PairRequest: true, PairAccept: true, PairReject: true,
	PacketMessage: true, PacketMessageAck: true, PacketDeliveryStat: true,
	PacketSyncRequest: true, PacketStoreAck: true,
	FileOffer: true, FileChunk: true, FileComplete: true,
	CallOffer: true, CallAnswer: true, CallICE: true,
	CallReject: true, CallEnd: true,
}

// ServerOnlyTypes lists packet types only the server may send.
var ServerOnlyTypes = map[PacketType]bool{
	PacketWelcome: true, PacketPong: true, PacketError: true, PacketSyncResponse: true,
}

// Packet is the envelope for every protocol message.
//
// Field semantics:
//   - Version: protocol version; must equal ProtocolVersion.
//   - Type: packet type, see PacketType.
//   - MsgID: unique operation identifier chosen by the originator. Used for
//     correlation (acks) and replay-detection hints.
//   - From / To: device identifiers. On inbound packets From MUST match the
//     identity bound to the connection (see SessionDeviceID); the server
//     overwrites From with the authenticated value before relaying.
//   - TS: unix-milliseconds timestamp, informational only.
//   - Payload: raw JSON sub-object, interpreted per Type. For MESSAGE it is
//     an opaque E2E-encrypted envelope.
type Packet struct {
	Version int             `json:"version"`
	Type    PacketType      `json:"type"`
	MsgID   string          `json:"msg_id,omitempty"`
	From    string          `json:"from,omitempty"`
	To      string          `json:"to,omitempty"`
	TS      int64           `json:"ts,omitempty"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

// Validation errors.
var (
	ErrMissingType    = fmt.Errorf("protocol: missing packet type")
	ErrUnknownType    = fmt.Errorf("protocol: unknown packet type")
	ErrBadVersion     = fmt.Errorf("protocol: unsupported protocol version")
	ErrMissingMsgID   = fmt.Errorf("protocol: missing msg_id")
	ErrMissingTo      = fmt.Errorf("protocol: missing recipient (to)")
	ErrPayloadTooBig  = fmt.Errorf("protocol: payload exceeds limit")
	ErrInvalidJSON    = fmt.Errorf("protocol: invalid JSON packet")
)

// Validate performs structural checks that do not depend on session state.
func (p *Packet) Validate() error {
	if !p.Type.IsValid() {
		if p.Type == "" {
			return ErrMissingType
		}
		return ErrUnknownType
	}
	if p.Version != ProtocolVersion {
		return ErrBadVersion
	}
	switch p.Type {
	case PacketHello, PacketPing, PacketPong, PacketWelcome, PacketError:
		// control packets: no msg_id required
	default:
		if p.MsgID == "" {
			return ErrMissingMsgID
		}
	}
	switch p.Type {
	case PacketMessage, PacketMessageAck, PacketDeliveryStat,
		FileOffer, FileChunk, FileComplete,
		PairRequest, PairAccept, PairReject,
		CallOffer, CallAnswer, CallICE, CallReject, CallEnd:
		if p.To == "" {
			return ErrMissingTo
		}
	}
	// SYNC_REQUEST targets the server itself (no recipient); STORE_ACK
	// references a stored message by ref_msg_id in its payload.
	return nil
}

// NeedsAuth reports whether the packet type requires an established
// (HELLO/Welcome-handled) session before the server will process it.
func (t PacketType) NeedsAuth() bool {
	switch t {
	case PacketHello, PacketPing, PacketPong:
		return false
	default:
		return true
	}
}

// Decode parses one packet from raw JSON bytes. It enforces MaxPacketSize
// and rejects unknown JSON fields is intentionally NOT done so that newer
// senders can add optional fields without breaking older servers
// (forward compatibility within the same major version).
func Decode(raw []byte) (*Packet, error) {
	if len(raw) > MaxPacketSize {
		return nil, ErrPayloadTooBig
	}
	var p Packet
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, ErrInvalidJSON
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

// Encode serialises a packet.
func Encode(p *Packet) ([]byte, error) {
	return json.Marshal(p)
}

// ErrorCode values returned inside ERROR packets.
type ErrorCode string

const (
	ErrCodeMalformed    ErrorCode = "MALFORMED_PACKET"
	ErrCodeUnauthorized ErrorCode = "UNAUTHORIZED"
	ErrCodeNotFound     ErrorCode = "PEER_NOT_FOUND"
	ErrCodeOffline      ErrorCode = "PEER_OFFLINE"
	ErrCodeTooLarge     ErrorCode = "PACKET_TOO_LARGE"
	ErrCodeRateLimited  ErrorCode = "RATE_LIMITED"
	ErrCodeInternal     ErrorCode = "INTERNAL_ERROR"
	ErrCodeNotSupported ErrorCode = "NOT_SUPPORTED"
	ErrCodeConnLimit    ErrorCode = "CONNECTION_LIMIT"
)

// ErrorPayload is the payload structure of an ERROR packet.
type ErrorPayload struct {
	Code    ErrorCode `json:"code"`
	Message string    `json:"message"`
	RefMsgID string   `json:"ref_msg_id,omitempty"`
}

// WelcomePayload is the payload structure of a WELCOME packet.
type WelcomePayload struct {
	ServerTime       int64  `json:"server_time"`
	SessionID        string `json:"session_id"`
	E2EEActive       bool   `json:"e2ee_active"`
	E2EEWarning      string `json:"e2ee_warning"`
	MaxPacketBytes   int    `json:"max_packet_bytes"`
	PingIntervalSec  int    `json:"ping_interval_sec"`
	PendingMessages  int    `json:"pending_messages"`
}

// SyncResponsePayload is the payload structure of a server-originated
// SYNC_RESPONSE packet (offline queue delivered on request).
type SyncResponsePayload struct {
	Messages []SyncedMessage `json:"messages"`
	Truncated bool           `json:"truncated,omitempty"`
}

// SyncedMessage mirrors one stored message back to its recipient.
type SyncedMessage struct {
	MsgID   string          `json:"msg_id"`
	From    string          `json:"from"`
	Type    string          `json:"type"`
	TS      int64           `json:"ts"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

// StoreAckPayload is the client->server confirmation that a synced message
// has been durably received and can be deleted from the relay store.
type StoreAckPayload struct {
	RefMsgID string `json:"ref_msg_id"`
}
