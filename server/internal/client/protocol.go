// Package client implements a reusable BOLTUN relay client (WebSocket,
// protocol v1) in pure Go. It mirrors the wire semantics enforced by the
// server: HELLO/WELCOME handshake, From-binding (the client never trusts
// server-supplied identity for its own sends), PING keep-alive at the
// interval announced in WELCOME, MESSAGE_ACK handling and the offline
// SYNC_REQUEST / STORE_ACK flow with at-least-once deduplication by msg_id.
package client

import (
	"encoding/json"
	"time"

	"github.com/boltun/server/internal/protocol"
)

// Config for dialing a relay.
type Config struct {
	URL      string // ws://host:port/ws or wss://...
	DeviceID string // 8..64 chars [A-Za-z0-9_-]
}

// Message is an application message as seen by the client. Payload stays
// opaque (E2E design): this package never interprets or decrypts it.
type Message struct {
	MsgID   string          `json:"msg_id"`
	From    string          `json:"from"`
	To      string          `json:"to"`
	Type    string          `json:"type"`
	TS      int64           `json:"ts"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

// Welcome carries server-advertised session parameters.
type Welcome struct {
	ServerTime      int64  `json:"server_time"`
	SessionID       string `json:"session_id"`
	E2EEActive      bool   `json:"e2ee_active"`
	E2EEWarning     string `json:"e2ee_warning"`
	MaxPacketBytes  int    `json:"max_packet_bytes"`
	PingIntervalSec int    `json:"ping_interval_sec"`
	PendingMessages int    `json:"pending_messages"`
}

// AckStage values observed in server MESSAGE_ACK payloads.
const (
	StageRelayed = "RELAYED_TO_PEER"
	StageStored  = "STORED_FOR_LATER_DELIVERY"
)

// Ack references a previously sent message via RefMsgID.
type Ack struct {
	RefMsgID string `json:"ref_msg_id"`
	Stage    string `json:"stage"`
}

// ServerError is an ERROR packet payload.
type ServerError struct {
	Code     protocol.ErrorCode `json:"code"`
	Message  string             `json:"message"`
	RefMsgID string             `json:"ref_msg_id,omitempty"`
}

func newEnvelope(t protocol.PacketType) *protocol.Packet {
	return &protocol.Packet{
		Version: protocol.ProtocolVersion,
		Type:    t,
		TS:      time.Now().UnixMilli(),
	}
}
