// Package transport integration tests: two REAL websocket clients connect to
// a running server instance and exchange packets through it. No simulation.
package transport_test

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/boltun/server/internal/config"
	"github.com/boltun/server/internal/devices"
	"github.com/boltun/server/internal/protocol"
	"github.com/boltun/server/internal/relay"
	"github.com/boltun/server/internal/transport"
)

type testClient struct {
	t    *testing.T
	conn *websocket.Conn
	id   string
}

func newServer(t *testing.T) *httptest.Server {
	t.Helper()
	cfg := &config.Config{
		DevMode:        true,
		ListenAddr:     ":0",
		MaxConnections: 16,
		MaxPacketBytes: protocol.MaxPacketSize,
		ReadTimeout:    5 * time.Second,
		PingInterval:   2 * time.Second,
	}
	reg := devices.NewRegistry()
	rly := relay.New(reg, log.New(io.Discard, "", 0), cfg.MaxPacketBytes)
	srv := transport.New(cfg, rly, log.New(io.Discard, "", 0))
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts
}

func wsURL(ts *httptest.Server) string {
	return "ws" + strings.TrimPrefix(ts.URL, "http") + "/ws"
}

func dial(t *testing.T, ts *httptest.Server, deviceID string) *testClient {
	t.Helper()
	conn, _, err := websocket.DefaultDialer.Dial(wsURL(ts), nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	c := &testClient{t: t, conn: conn, id: deviceID}

	helloPayload, _ := json.Marshal(map[string]string{"device_id": deviceID, "client_nonce": "nonce-" + deviceID})
	err = conn.WriteJSON(protocol.Packet{
		Version: protocol.ProtocolVersion,
		Type:    protocol.PacketHello,
		Payload: helloPayload,
	})
	if err != nil {
		t.Fatalf("write HELLO: %v", err)
	}
	w := c.read()
	if w.Type != protocol.PacketWelcome {
		t.Fatalf("%s: expected WELCOME, got %s (%s)", deviceID, w.Type, w.Payload)
	}
	return c
}

func (c *testClient) read() *protocol.Packet {
	c.t.Helper()
	_ = c.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, raw, err := c.conn.ReadMessage()
	if err != nil {
		c.t.Fatalf("%s read: %v", c.id, err)
	}
	p, err := protocol.Decode(raw)
	if err != nil {
		c.t.Fatalf("%s decode: %v raw=%s", c.id, err, raw)
	}
	return p
}

// readUntil skips keepalive PINGs and returns the next non-PING packet.
func (c *testClient) readUntil(types ...protocol.PacketType) *protocol.Packet {
	c.t.Helper()
	for {
		p := c.read()
		if p.Type == protocol.PacketPing {
			continue
		}
		for _, want := range types {
			if p.Type == want {
				return p
			}
		}
		c.t.Fatalf("%s: got %s, wanted one of %v (payload=%s)", c.id, p.Type, types, p.Payload)
	}
}

func (c *testClient) send(p *protocol.Packet) {
	c.t.Helper()
	raw, err := protocol.Encode(p)
	if err != nil {
		c.t.Fatal(err)
	}
	if err := c.conn.WriteMessage(websocket.TextMessage, raw); err != nil {
		c.t.Fatalf("%s write: %v", c.id, err)
	}
}

func TestIntegrationTwoClientsExchange(t *testing.T) {
	ts := newServer(t)

	// Scenario: A connects, B connects, A -> B message, B receives,
	// B replies to A, A receives reply. Real sockets through the server.
	a := dial(t, ts, "device-alpha")
	b := dial(t, ts, "device-bravo")

	a.send(&protocol.Packet{
		Version: protocol.ProtocolVersion,
		Type:    protocol.PacketMessage,
		MsgID:   "int-1",
		From:    "device-alpha",
		To:      "device-bravo",
		TS:      time.Now().UnixMilli(),
		Payload: json.RawMessage(`{"note":"opaque e2e blob placeholder","text":"hello bravo"}`),
	})

	gotB := b.readUntil(protocol.PacketMessage)
	if gotB.MsgID != "int-1" || gotB.From != "device-alpha" {
		t.Fatalf("B received wrong envelope: %+v", gotB)
	}

	ackA := a.readUntil(protocol.PacketMessageAck)
	var ackBody map[string]any
	_ = json.Unmarshal(ackA.Payload, &ackBody)
	if ackBody["ref_msg_id"] != "int-1" {
		t.Fatalf("ack must reference int-1, got %v", ackBody)
	}

	b.send(&protocol.Packet{
		Version: protocol.ProtocolVersion,
		Type:    protocol.PacketMessage,
		MsgID:   "int-2",
		From:    "device-bravo",
		To:      "device-alpha",
		Payload: json.RawMessage(`{"text":"hi alpha"}`),
	})
	gotA := a.readUntil(protocol.PacketMessage)
	if gotA.MsgID != "int-2" || gotA.From != "device-bravo" {
		t.Fatalf("A received wrong reply: %+v", gotA)
	}
}

func TestIntegrationSpoofedFromIsBound(t *testing.T) {
	ts := newServer(t)
	a := dial(t, ts, "device-alpha")
	b := dial(t, ts, "device-bravo")

	a.send(&protocol.Packet{
		Version: protocol.ProtocolVersion,
		Type:    protocol.PacketMessage,
		MsgID:   "sp-1",
		From:    "device-bravo", // attempt to impersonate B
		To:      "device-bravo",
		Payload: json.RawMessage(`{}`),
	})
	gotB := b.readUntil(protocol.PacketMessage)
	if gotB.From != "device-alpha" {
		t.Fatalf("server must rewrite From to session identity; got %q", gotB.From)
	}
}

func TestIntegrationOfflineStatus(t *testing.T) {
	ts := newServer(t)
	a := dial(t, ts, "device-alpha")

	a.send(&protocol.Packet{
		Version: protocol.ProtocolVersion,
		Type:    protocol.PacketMessage,
		MsgID:   "off-1",
		To:      "device-nowhere",
		Payload: json.RawMessage(`{}`),
	})
	e := a.readUntil(protocol.PacketError)
	var ep protocol.ErrorPayload
	_ = json.Unmarshal(e.Payload, &ep)
	if ep.Code != protocol.ErrCodeOffline || ep.RefMsgID != "off-1" {
		t.Fatalf("want PEER_OFFLINE for off-1, got %+v", ep)
	}
}

func TestIntegrationMalformedRejected(t *testing.T) {
	ts := newServer(t)
	conn, _, err := websocket.DefaultDialer.Dial(wsURL(ts), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	if err := conn.WriteMessage(websocket.TextMessage, []byte(`{"version":1,"type":"MESSAGE"}`)); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, raw, err := conn.ReadMessage()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "msg_id") {
		t.Fatalf("expected validation error about msg_id, got %s", raw)
	}
}

func TestIntegrationPreAuthMessageRejected(t *testing.T) {
	ts := newServer(t)
	conn, _, err := websocket.DefaultDialer.Dial(wsURL(ts), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	msg, _ := json.Marshal(protocol.Packet{
		Version: protocol.ProtocolVersion,
		Type:    protocol.PacketMessage,
		MsgID:   "pre-1",
		To:      "device-whatever",
	})
	if err := conn.WriteMessage(websocket.TextMessage, msg); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, raw, err := conn.ReadMessage()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "UNAUTHORIZED") {
		t.Fatalf("pre-auth MESSAGE must be rejected, got %s", raw)
	}
}

func TestIntegrationDisconnectRemovesSession(t *testing.T) {
	ts := newServer(t)
	a := dial(t, ts, "device-alpha")
	b := dial(t, ts, "device-bravo")

	// Disconnect B; then A->B must yield PEER_OFFLINE eventually.
	if err := b.conn.WriteControl(websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""),
		time.Now().Add(time.Second)); err != nil {
		t.Log("close control:", err)
	}
	_ = b.conn.Close()

	deadline := time.Now().Add(3 * time.Second)
	for {
		a.send(&protocol.Packet{
			Version: protocol.ProtocolVersion,
			Type:    protocol.PacketMessage,
			MsgID:   "disc-1",
			To:      "device-bravo",
			Payload: json.RawMessage(`{}`),
		})
		p := a.readUntil(protocol.PacketError, protocol.PacketMessageAck)
		if p.Type == protocol.PacketError {
			var ep protocol.ErrorPayload
			_ = json.Unmarshal(p.Payload, &ep)
			if ep.Code == protocol.ErrCodeOffline {
				return // success: session removed after disconnect
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("session was not removed after client disconnect")
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func TestHealthz(t *testing.T) {
	ts := newServer(t)
	resp, err := http.Get(ts.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("healthz status %d", resp.StatusCode)
	}
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body["status"] != "ok" || body["e2ee_active"] != false {
		t.Fatalf("unexpected healthz body %v", body)
	}
}
