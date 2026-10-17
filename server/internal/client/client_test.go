package client_test

import (
	"io"
	"log"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/boltun/server/internal/client"
	"github.com/boltun/server/internal/config"
	"github.com/boltun/server/internal/devices"
	"github.com/boltun/server/internal/protocol"
	"github.com/boltun/server/internal/relay"
	"github.com/boltun/server/internal/store"
	"github.com/boltun/server/internal/transport"
)

func newServer(t *testing.T) (*httptest.Server, *store.Store) {
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
	st, err := store.Open("")
	if err != nil {
		t.Fatal(err)
	}
	rly := relay.New(reg, st, log.New(io.Discard, "", 0), cfg.MaxPacketBytes)
	srv := transport.New(cfg, rly, log.New(io.Discard, "", 0))
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts, st
}

func wsURL(ts *httptest.Server) string {
	return "ws" + strings.TrimPrefix(ts.URL, "http") + "/ws"
}

// collector is an EventHandler that records events.
type collector struct {
	mu       sync.Mutex
	welcome  *client.Welcome
	messages []client.Message
	acks     []client.Ack
	errs     []client.ServerError
	closed   error
	msgCh    chan client.Message
}

func newCollector() *collector {
	return &collector{msgCh: make(chan client.Message, 32)}
}

func (c *collector) OnWelcome(w client.Welcome) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.welcome = &w
}

func (c *collector) OnMessage(m client.Message) {
	c.mu.Lock()
	c.messages = append(c.messages, m)
	c.mu.Unlock()
	select {
	case c.msgCh <- m:
	default:
	}
}

func (c *collector) OnAck(a client.Ack) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.acks = append(c.acks, a)
}

func (c *collector) OnKeyResponse(k client.KeyResponse) {}

func (c *collector) OnError(e client.ServerError) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.errs = append(c.errs, e)
}

func (c *collector) OnClosed(reason error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = reason
}

func (c *collector) waitMsg(t *testing.T) client.Message {
	t.Helper()
	select {
	case m := <-c.msgCh:
		return m
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for message")
		return client.Message{}
	}
}

func dialOK(t *testing.T, ts *httptest.Server, dev string) (*client.Client, *collector) {
	t.Helper()
	col := newCollector()
	c, err := client.New(client.Config{URL: wsURL(ts), DeviceID: dev}, col)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	if _, err := c.Connect(); err != nil {
		t.Fatalf("connect %s: %v", dev, err)
	}
	t.Cleanup(func() { c.Close() })
	return c, col
}

func TestConnectHandshake(t *testing.T) {
	ts, _ := newServer(t)
	col := newCollector()
	c, err := client.New(client.Config{URL: wsURL(ts), DeviceID: "client-alpha"}, col)
	if err != nil {
		t.Fatal(err)
	}
	w, err := c.Connect()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if w.SessionID == "" {
		t.Error("welcome missing session id")
	}
	if w.PingIntervalSec != 25 {
		t.Errorf("ping interval = %d, want 25", w.PingIntervalSec)
	}
	if !strings.Contains(w.E2EEWarning, "END-TO-END") {
		t.Error("expected E2EE warning in dev build")
	}
	if col.welcome == nil {
		t.Error("OnWelcome callback not fired")
	}
}

func waitAcks(col *collector, n int) {
	deadline := time.After(5 * time.Second)
	for {
		col.mu.Lock()
		got := len(col.acks)
		col.mu.Unlock()
		if got >= n {
			return
		}
		select {
		case <-deadline:
			return // caller asserts counts directly
		default:
			time.Sleep(20 * time.Millisecond)
		}
	}
}

func TestSendMessageAndReceive(t *testing.T) {
	ts, _ := newServer(t)
	a, ac := dialOK(t, ts, "client-sender")
	_, bc := dialOK(t, ts, "client-receiver")

	payload := []byte(`{"text":"привет"}`)
	msgID, err := a.SendMessage("client-receiver", payload)
	if err != nil {
		t.Fatal(err)
	}

	got := bc.waitMsg(t)
	if got.MsgID != msgID {
		t.Errorf("msg id = %s, want %s", got.MsgID, msgID)
	}
	if got.From != "client-sender" {
		t.Errorf("from = %s, want server-bound client-sender", got.From)
	}
	if string(got.Payload) != string(payload) {
		t.Errorf("payload altered: %s", got.Payload)
	}

	// sender should observe RELAYED ack referencing the sent msg_id
	waitAcks(ac, 1)
	ac.mu.Lock()
	defer ac.mu.Unlock()
	if len(ac.acks) != 1 {
		t.Fatalf("acks = %d, want 1", len(ac.acks))
	}
	if ac.acks[0].Stage != client.StageRelayed || ac.acks[0].RefMsgID != msgID {
		t.Errorf("unexpected ack %+v", ac.acks[0])
	}
}

func TestOfflineStoreSyncFlow(t *testing.T) {
	ts, st := newServer(t)
	a, ac := dialOK(t, ts, "client-alice")

	// bob offline -> message must be stored
	if _, err := a.SendMessage("client-bob-device", []byte(`{"text":"later"}`)); err != nil {
		t.Fatal(err)
	}
	// wait for STORED ack
	deadline := time.After(5 * time.Second)
	foundStored := false
	for !foundStored {
		select {
		case <-deadline:
			t.Fatal("no ack received")
		default:
		}
		ac.mu.Lock()
		n := len(ac.acks)
		ac.mu.Unlock()
		if n > 0 {
			ac.mu.Lock()
			last := ac.acks[n-1]
			ac.mu.Unlock()
			if last.Stage == client.StageStored {
				foundStored = true
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	if st.Count("client-bob-device") != 1 {
		t.Fatalf("store count = %d, want 1", st.Count("client-bob-device"))
	}

	// bob connects, sees pending, syncs, acks
	b, bc := dialOK(t, ts, "client-bob-device")
	if bc.welcome == nil {
		t.Fatal("no welcome recorded")
	}
	bc.mu.Lock()
	pending := bc.welcome.PendingMessages
	bc.mu.Unlock()
	if pending != 1 {
		t.Fatalf("pending in WELCOME = %d, want 1", pending)
	}
	if err := b.RequestSync(); err != nil {
		t.Fatal(err)
	}
	m := bc.waitMsg(t)
	if m.From != "client-alice" {
		t.Errorf("synced from = %s, want client-alice", m.From)
	}
	if err := b.AckStored(m.MsgID); err != nil {
		t.Fatal(err)
	}
	// store drains asynchronously; poll briefly
	for i := 0; i < 100 && st.Count("client-bob-device") != 0; i++ {
		time.Sleep(20 * time.Millisecond)
	}
	if st.Count("client-bob-device") != 0 {
		t.Error("STORE_ACK did not drain the store")
	}
}

func TestDuplicateSyncedMessageDeduped(t *testing.T) {
	ts, _ := newServer(t)
	a, _ := dialOK(t, ts, "client-dupA")
	if _, err := a.SendMessage("client-dupB-dev", []byte(`{"n":1}`)); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond) // let STORED ack path settle

	b, bc := dialOK(t, ts, "client-dupB-dev")
	if err := b.RequestSync(); err != nil {
		t.Fatal(err)
	}
	bc.waitMsg(t) // first delivery
	// second sync WITHOUT ack -> same msg still in store, but client dedups
	if err := b.RequestSync(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
	bc.mu.Lock()
	n := len(bc.messages)
	bc.mu.Unlock()
	if n != 1 {
		t.Errorf("dedupe failed: got %d messages, want 1", n)
	}
}

func TestSendToUnknownPeerGetsError(t *testing.T) {
	ts, _ := newServer(t)
	a, ac := dialOK(t, ts, "client-nohost")
	// non-MESSAGE packet type to offline peer -> ERROR (MESSAGE would store)
	if _, err := a.SendPairRequest("never-seen-device", []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	deadline := time.After(5 * time.Second)
	for {
		ac.mu.Lock()
		errs := len(ac.errs)
		var code protocol.ErrorCode
		if errs > 0 {
			code = ac.errs[errs-1].Code
		}
		ac.mu.Unlock()
		if errs > 0 {
			if code != protocol.ErrCodeOffline {
				t.Errorf("error code = %s, want PEER_OFFLINE", code)
			}
			return
		}
		select {
		case <-deadline:
			t.Fatal("no ERROR received")
		default:
			time.Sleep(20 * time.Millisecond)
		}
	}
}

func TestBadDeviceIDRejectedAtNew(t *testing.T) {
	if _, err := client.New(client.Config{URL: "ws://x/ws", DeviceID: "short"}, nil); err == nil {
		t.Error("expected validation error for short device id")
	}
}
