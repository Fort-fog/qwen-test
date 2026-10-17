package relay

import (
	"encoding/json"
	"io"
	"log"
	"testing"
	"time"

	"github.com/boltun/server/internal/devices"
	"github.com/boltun/server/internal/protocol"
)

func newTestRelay() (*Relay, *devices.Registry) {
	reg := devices.NewRegistry()
	r := New(reg, log.New(io.Discard, "", 0), protocol.MaxPacketSize)
	return r, reg
}

func mkSession(dev string) (*devices.Session, chan []byte) {
	ch := make(chan []byte, 16)
	s := &devices.Session{DeviceID: dev, SessionID: "sess-" + dev, Send: ch}
	return s, ch
}

func readPacket(t *testing.T, ch chan []byte) *protocol.Packet {
	t.Helper()
	select {
	case raw := <-ch:
		p, err := protocol.Decode(raw)
		if err != nil {
			t.Fatalf("decode server packet: %v (%s)", err, raw)
		}
		return p
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for server packet")
		return nil
	}
}

func TestHelloWelcome(t *testing.T) {
	r, reg := newTestRelay()
	_, ca := mkSession("device-alpha")
	payload, _ := json.Marshal(map[string]string{"device_id": "device-alpha", "client_nonce": "n1"})
	resp, sess := r.HandleHello(ca, payload)
	if resp.Type != protocol.PacketWelcome || sess == nil {
		t.Fatalf("want WELCOME, got %s", resp.Type)
	}
	var wp protocol.WelcomePayload
	if err := json.Unmarshal(resp.Payload, &wp); err != nil {
		t.Fatal(err)
	}
	if wp.E2EEActive {
		t.Fatal("E2EE must be reported inactive in this build")
	}
	if wp.E2EEWarning == "" {
		t.Fatal("must carry explicit E2EE warning")
	}
	if !reg.Online("device-alpha") {
		t.Fatal("device should be online")
	}
}

func TestHelloBadDeviceID(t *testing.T) {
	r, _ := newTestRelay()
	_, c := mkSession("x")
	payload, _ := json.Marshal(map[string]string{"device_id": "bad id!!"})
	resp, sess := r.HandleHello(c, payload)
	if resp.Type != protocol.PacketError || sess != nil {
		t.Fatal("malformed device_id must be rejected")
	}
}

func TestDuplicateDeviceRejected(t *testing.T) {
	r, _ := newTestRelay()
	sa, ca := mkSession("device-alpha")
	payload, _ := json.Marshal(map[string]string{"device_id": sa.DeviceID})
	if _, sess := r.HandleHello(ca, payload); sess == nil {
		t.Fatal("first hello should succeed")
	}
	sb, cb := mkSession("device-alpha")
	_ = sb
	payload2, _ := json.Marshal(map[string]string{"device_id": "device-alpha"})
	resp, sess := r.HandleHello(cb, payload2)
	if resp.Type != protocol.PacketError || sess != nil {
		t.Fatal("duplicate device id must be rejected")
	}
}

func TestRouteBetweenTwoClients(t *testing.T) {
	r, _ := newTestRelay()
	sa, ca := mkSession("device-alpha")
	sb, cb := mkSession("device-bravo")
	reg := r.Registry()
	if err := reg.Register(sa); err != nil {
		t.Fatal(err)
	}
	if err := reg.Register(sb); err != nil {
		t.Fatal(err)
	}

	msg := &protocol.Packet{
		Version: protocol.ProtocolVersion,
		Type:    protocol.PacketMessage,
		MsgID:   "m-1",
		From:    "evil-spoofed-id", // must be overwritten by the server
		To:      "device-bravo",
		Payload: json.RawMessage(`{"opaque":"e2e-blob"}`),
	}
	r.Dispatch(sa, msg, ca)

	got := readPacket(t, cb)
	if got.Type != protocol.PacketMessage || got.MsgID != "m-1" {
		t.Fatalf("bravo got %s", got.Type)
	}
	if got.From != "device-alpha" {
		t.Fatalf("server must bind From to session identity, got %q", got.From)
	}
	if string(got.Payload) != `{"opaque":"e2e-blob"}` {
		t.Fatalf("payload altered in transit")
	}

	// transport ack to sender
	ack := readPacket(t, ca)
	if ack.Type != protocol.PacketMessageAck {
		t.Fatalf("want MESSAGE_ACK, got %s", ack.Type)
	}

	// reply path bravo -> alpha
	reply := &protocol.Packet{
		Version: protocol.ProtocolVersion,
		Type:    protocol.PacketMessage,
		MsgID:   "m-2",
		To:      "device-alpha",
		Payload: json.RawMessage(`{"reply":true}`),
	}
	r.Dispatch(sb, reply, cb)
	gotA := readPacket(t, ca)
	if gotA.Type != protocol.PacketMessage || gotA.MsgID != "m-2" {
		t.Fatalf("alpha did not receive reply")
	}
}

func TestRecipientOffline(t *testing.T) {
	r, _ := newTestRelay()
	sa, ca := mkSession("device-alpha")
	if err := r.Registry().Register(sa); err != nil {
		t.Fatal(err)
	}
	msg := &protocol.Packet{
		Version: protocol.ProtocolVersion,
		Type:    protocol.PacketMessage,
		MsgID:   "m-9",
		To:      "device-ghost",
		Payload: json.RawMessage(`{}`),
	}
	r.Dispatch(sa, msg, ca)
	got := readPacket(t, ca)
	if got.Type != protocol.PacketError {
		t.Fatalf("want ERROR, got %s", got.Type)
	}
	var ep protocol.ErrorPayload
	_ = json.Unmarshal(got.Payload, &ep)
	if ep.Code != protocol.ErrCodeOffline {
		t.Fatalf("want PEER_OFFLINE, got %s", ep.Code)
	}
	if ep.RefMsgID != "m-9" {
		t.Fatalf("error must reference original msg_id")
	}
}

func TestPingPong(t *testing.T) {
	r, _ := newTestRelay()
	sa, ca := mkSession("device-alpha")
	_ = r.Registry().Register(sa)
	r.Dispatch(sa, &protocol.Packet{Version: 1, Type: protocol.PacketPing}, ca)
	got := readPacket(t, ca)
	if got.Type != protocol.PacketPong {
		t.Fatalf("want PONG, got %s", got.Type)
	}
}

func TestSendToSelfRejected(t *testing.T) {
	r, _ := newTestRelay()
	sa, ca := mkSession("device-alpha")
	_ = r.Registry().Register(sa)
	r.Dispatch(sa, &protocol.Packet{
		Version: 1, Type: protocol.PacketMessage, MsgID: "s1", To: "device-alpha",
	}, ca)
	got := readPacket(t, ca)
	if got.Type != protocol.PacketError {
		t.Fatalf("want ERROR for self-send, got %s", got.Type)
	}
}

func TestDeviceRegisterNotSupportedYet(t *testing.T) {
	r, _ := newTestRelay()
	sa, ca := mkSession("device-alpha")
	_ = r.Registry().Register(sa)
	r.Dispatch(sa, &protocol.Packet{
		Version: 1, Type: protocol.PacketDeviceReg, MsgID: "d1", Payload: json.RawMessage(`{}`),
	}, ca)
	got := readPacket(t, ca)
	if got.Type != protocol.PacketError {
		t.Fatalf("want ERROR, got %s", got.Type)
	}
	var ep protocol.ErrorPayload
	_ = json.Unmarshal(got.Payload, &ep)
	if ep.Code != protocol.ErrCodeNotSupported {
		t.Fatalf("DEVICE_REGISTER must honestly report NOT_SUPPORTED, got %s", ep.Code)
	}
}
