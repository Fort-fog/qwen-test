package relay

import (
	"encoding/json"
	"log"
	"testing"
	"time"

	"github.com/boltun/server/internal/devices"
	"github.com/boltun/server/internal/protocol"
	"github.com/boltun/server/internal/store"
)

// newFlushTestRelay builds a relay with an in-memory store and two helpers
// for draining encoded packets out of a session queue.
func newFlushTestRelay(t *testing.T) (*Relay, *store.Store) {
	t.Helper()
	st, err := store.Open("") // in-memory
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	r := New(devices.NewRegistry(), st, log.New(discard{}, "test: ", 0), protocol.MaxPacketSize)
	return r, st
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }

func decodeOut(t *testing.T, ch chan []byte) *protocol.Packet {
	t.Helper()
	select {
	case raw := <-ch:
		var p protocol.Packet
		if err := json.Unmarshal(raw, &p); err != nil {
			t.Fatalf("decode outbound packet: %v", err)
		}
		return &p
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for outbound packet")
		return nil
	}
}

// TestHelloTriggersAutoFlush verifies that when a device with pending offline
// messages sends HELLO, the server proactively delivers SYNC_RESPONSE without
// the client having to send SYNC_REQUEST first.
func TestHelloTriggersAutoFlush(t *testing.T) {
	r, st := newFlushTestRelay(t)

	sender := &devices.Session{
		DeviceID:  "sender-device-01",
		SessionID: "s1",
		Send:      make(chan []byte, 16),
	}
	if err := r.Registry().Register(sender); err != nil {
		t.Fatalf("register sender: %v", err)
	}

	// Simulate an inbound MESSAGE from sender to a currently-offline peer.
	msg := &protocol.Packet{
		Version: protocol.ProtocolVersion,
		Type:    protocol.PacketMessage,
		MsgID:   "abc123",
		From:    sender.DeviceID,
		To:      "peer-device-02",
		TS:      time.Now().UnixMilli(),
		Payload: json.RawMessage(`{"kind":"text","text":"hi"}`),
	}
	r.Dispatch(sender, msg, sender.Send)

	// Sender should get STORED_FOR_LATER_DELIVERY ack.
	ack := decodeOut(t, sender.Send)
	if ack.Type != protocol.PacketMessageAck {
		t.Fatalf("want MESSAGE_ACK, got %s", ack.Type)
	}
	if count := st.Count("peer-device-02"); count != 1 {
		t.Fatalf("want 1 stored msg for peer, got %d", count)
	}

	// Now the peer connects via HandleHello; it must receive WELCOME plus an
	// automatic SYNC_RESPONSE carrying the queued message.
	peerSend := make(chan []byte, 16)
	helloPayload := json.RawMessage(`{"device_id":"peer-device-02","client_nonce":"n1"}`)
	welcome, sess := r.HandleHello(peerSend, helloPayload)
	if welcome == nil || sess == nil {
		t.Fatalf("HELLO failed to produce session")
	}
	_ = welcome // WELCOME is returned directly, not queued on peerSend.

	syncPkt := decodeOut(t, peerSend)
	if syncPkt.Type != protocol.PacketSyncResponse {
		t.Fatalf("want auto SYNC_RESPONSE after HELLO, got %s", syncPkt.Type)
	}
	var body protocol.SyncResponsePayload
	if err := json.Unmarshal(syncPkt.Payload, &body); err != nil {
		t.Fatalf("decode sync payload: %v", err)
	}
	if len(body.Messages) != 1 || body.Messages[0].MsgID != "abc123" {
		t.Fatalf("unexpected synced messages: %+v", body.Messages)
	}
}

// TestStoreAckRemovesPending confirms STORE_ACK deletes exactly one entry and
// is idempotent for duplicate acks (at-least-once receiver semantics).
func TestStoreAckRemovesPending(t *testing.T) {
	r, st := newFlushTestRelay(t)

	if err := st.Append("me-device-0001", store.StoredMessage{
		MsgID:   "m1",
		From:    "other-device-02",
		TS:      time.Now().UnixMilli(),
		Type:    string(protocol.PacketMessage),
		Payload: json.RawMessage(`{"kind":"text","text":"x"}`),
	}); err != nil {
		t.Fatalf("append: %v", err)
	}

	sess := &devices.Session{
		DeviceID:  "me-device-0001",
		SessionID: "s2",
		Send:      make(chan []byte, 8),
	}
	if err := r.Registry().Register(sess); err != nil {
		t.Fatalf("register: %v", err)
	}

	ackPkt := &protocol.Packet{
		Version: protocol.ProtocolVersion,
		Type:    protocol.PacketStoreAck,
		MsgID:   "a1",
		Payload: json.RawMessage(`{"ref_msg_id":"m1"}`),
	}
	r.Dispatch(sess, ackPkt, sess.Send)

	if got := st.Count("me-device-0001"); got != 0 {
		t.Fatalf("expected store emptied after ack, got %d", got)
	}

	// Duplicate ack must be silently ignored (idempotent).
	r.Dispatch(sess, ackPkt, sess.Send)
	if got := st.Count("me-device-0001"); got != 0 {
		t.Fatalf("duplicate ack changed store state: %d", got)
	}
}
