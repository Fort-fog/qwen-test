package client

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"github.com/boltun/server/internal/protocol"
)

// Errors surfaced by the client.
var (
	ErrNotConnected   = errors.New("boltun/client: not connected (call Connect first)")
	ErrAlreadyConn    = errors.New("boltun/client: already connected")
	ErrServerRejected = errors.New("boltun/client: server rejected the request")
)

// EventHandler receives asynchronous client events. All callbacks run on the
// client's single read-loop goroutine, so handlers may keep simple state
// without extra locking. Handlers must not block for long; heavy work should
// be handed off to the caller's own queue.
type EventHandler interface {
	OnWelcome(w Welcome)
	// OnMessage delivers an incoming MESSAGE (live or synced). Duplicate
	// msg_ids are filtered by the client unless KeepDuplicates is set.
	OnMessage(m Message)
	OnAck(a Ack)
	OnError(e ServerError)
	// OnClosed fires when the connection ends (cleanly or with error).
	OnClosed(reason error)
}

// NullHandler can be embedded to implement EventHandler partially.
type NullHandler struct{}

func (NullHandler) OnWelcome(Welcome)   {}
func (NullHandler) OnMessage(Message)   {}
func (NullHandler) OnAck(Ack)           {}
func (NullHandler) OnError(ServerError) {}
func (NullHandler) OnClosed(error)      {}

// Client is a single relay session. Not safe for concurrent Connect/Close;
// Send/Sync may be called from any goroutine once Connected.
type Client struct {
	cfg     Config
	handler EventHandler

	// KeepDuplicates disables client-side msg_id deduplication of incoming
	// messages (default: deduplicate).
	KeepDuplicates bool

	connMu sync.Mutex
	conn   *websocket.Conn
	sendCh chan *protocol.Packet // serialized writer queue

	writeMu sync.Mutex // guards conn.WriteMessage ordering

	seenMu sync.Mutex
	seen   map[string]bool // inbound msg_id dedup

	closedOnce sync.Once
	closeErr   error
	done       chan struct{}

	pingInterval time.Duration
}

// New creates an unconnected client.
func New(cfg Config, h EventHandler) (*Client, error) {
	if cfg.URL == "" {
		return nil, errors.New("boltun/client: Config.URL required")
	}
	if len(cfg.DeviceID) < 8 || len(cfg.DeviceID) > 64 {
		return nil, errors.New("boltun/client: DeviceID must be 8..64 chars")
	}
	if h == nil {
		h = NullHandler{}
	}
	return &Client{
		cfg:     cfg,
		handler: h,
		seen:    make(map[string]bool),
		done:    make(chan struct{}),
	}, nil
}

func newMsgID() string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		panic("boltun/client: entropy failure: " + err.Error())
	}
	return hex.EncodeToString(b)
}

// Connect dials the relay and performs the HELLO/WELCOME handshake. It
// returns the parsed WELCOME payload. The read loop and PING ticker start
// automatically and run until Close or transport failure.
func (c *Client) Connect() (*Welcome, error) {
	c.connMu.Lock()
	defer c.connMu.Unlock()
	if c.conn != nil {
		return nil, ErrAlreadyConn
	}
	dialer := websocket.Dialer{HandshakeTimeout: 10 * time.Second}
	conn, _, err := dialer.Dial(c.cfg.URL, nil)
	if err != nil {
		return nil, fmt.Errorf("boltun/client: dial: %w", err)
	}
	c.conn = conn
	c.sendCh = make(chan *protocol.Packet, 64)

	writeRaw := func(p *protocol.Packet) error {
		raw, err := protocol.Encode(p)
		if err != nil {
			return err
		}
		conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		return conn.WriteMessage(websocket.TextMessage, raw)
	}

	// HELLO
	nonce := make([]byte, 16)
	_, _ = rand.Read(nonce)
	hello := newEnvelope(protocol.PacketHello)
	hello.Payload = mustJSON(map[string]any{
		"device_id":    c.cfg.DeviceID,
		"client_nonce": hex.EncodeToString(nonce),
	})
	if err := writeRaw(hello); err != nil {
		conn.Close()
		c.conn = nil
		return nil, fmt.Errorf("boltun/client: send HELLO: %w", err)
	}

	// Block until WELCOME or ERROR (bounded).
	type res struct {
		w   *Welcome
		err error
	}
	ch := make(chan res, 1)
	go func() {
		conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		for {
			_, raw, err := conn.ReadMessage()
			if err != nil {
				ch <- res{nil, err}
				return
			}
			var p protocol.Packet
			if err := json.Unmarshal(raw, &p); err != nil {
				continue
			}
			switch p.Type {
			case protocol.PacketWelcome:
				var w Welcome
				_ = json.Unmarshal(p.Payload, &w)
				ch <- res{&w, nil}
				return
			case protocol.PacketError:
				var e ServerError
				_ = json.Unmarshal(p.Payload, &e)
				ch <- res{nil, fmt.Errorf("%w: %s (%s)", ErrServerRejected, e.Message, e.Code)}
				return
			}
		}
	}()
	r := <-ch
	if r.err != nil {
		conn.Close()
		c.conn = nil
		return nil, r.err
	}

	c.pingInterval = time.Duration(r.w.PingIntervalSec) * time.Second
	if c.pingInterval <= 0 {
		c.pingInterval = 25 * time.Second
	}

	go c.readLoop()
	go c.pingLoop()
	go c.writeLoop()

	c.handler.OnWelcome(*r.w)
	return r.w, nil
}

// Connected reports session liveness.
func (c *Client) Connected() bool {
	c.connMu.Lock()
	defer c.connMu.Unlock()
	return c.conn != nil
}

// Close terminates the session. Idempotent.
func (c *Client) Close() error {
	var err error
	c.closedOnce.Do(func() {
		c.connMu.Lock()
		if c.conn != nil {
			err = c.conn.Close()
			c.conn = nil
		}
		c.connMu.Unlock()
		c.closeErr = err
		close(c.done)
	})
	return err
}

// SendMessage routes an opaque E2E payload to recipient. Returns the msg_id
// used for ack correlation.
func (c *Client) SendMessage(recipient string, payload json.RawMessage) (string, error) {
	return c.send(protocol.PacketMessage, recipient, payload)
}

// SendPairRequest forwards a pairing packet (opaque payload).
func (c *Client) SendPairRequest(recipient string, payload json.RawMessage) (string, error) {
	return c.send(protocol.PairRequest, recipient, payload)
}

func (c *Client) send(t protocol.PacketType, to string, payload json.RawMessage) (string, error) {
	if !c.Connected() {
		return "", ErrNotConnected
	}
	msgID := newMsgID()
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

// RequestSync asks the server for the offline queue stored for this device.
// Responses arrive as OnMessage callbacks followed by OnClosed-free flow;
// every delivered message must be STORE_ACKed via AckStored once durably
// persisted locally (at-least-once semantics — dedupe by MsgID).
func (c *Client) RequestSync() error {
	if !c.Connected() {
		return ErrNotConnected
	}
	p := newEnvelope(protocol.PacketSyncRequest)
	p.MsgID = newMsgID()
	p.From = c.cfg.DeviceID
	select {
	case c.sendCh <- p:
		return nil
	case <-c.done:
		return ErrNotConnected
	}
}

// AckStored confirms durable receipt of a synced message so the server can
// delete it from the offline store.
func (c *Client) AckStored(refMsgID string) error {
	if !c.Connected() {
		return ErrNotConnected
	}
	p := newEnvelope(protocol.PacketStoreAck)
	p.MsgID = newMsgID()
	p.From = c.cfg.DeviceID
	p.Payload = mustJSON(protocol.StoreAckPayload{RefMsgID: refMsgID})
	select {
	case c.sendCh <- p:
		return nil
	case <-c.done:
		return ErrNotConnected
	}
}

// ---- internals ----

func (c *Client) writeLoop() {
	for {
		select {
		case p := <-c.sendCh:
			if err := c.writePacket(p); err != nil {
				c.shutdown(err)
				return
			}
		case <-c.done:
			return
		}
	}
}

func (c *Client) writePacket(p *protocol.Packet) error {
	raw, err := protocol.Encode(p)
	if err != nil {
		return err
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	c.connMu.Lock()
	conn := c.conn
	c.connMu.Unlock()
	if conn == nil {
		return ErrNotConnected
	}
	conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	return conn.WriteMessage(websocket.TextMessage, raw)
}

func (c *Client) pingLoop() {
	t := time.NewTicker(c.pingInterval)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			p := newEnvelope(protocol.PacketPing)
			p.MsgID = newMsgID()
			if err := c.writePacket(p); err != nil {
				c.shutdown(err)
				return
			}
		case <-c.done:
			return
		}
	}
}

func (c *Client) readLoop() {
	for {
		c.connMu.Lock()
		conn := c.conn
		c.connMu.Unlock()
		if conn == nil {
			return // session closed concurrently; shutdown already ran
		}
		conn.SetReadDeadline(time.Now().Add(90 * time.Second))
		_, raw, err := conn.ReadMessage()
		if err != nil {
			c.shutdown(err)
			return
		}
		c.handleInbound(raw)
	}
}

func (c *Client) handleInbound(raw []byte) {
	var p protocol.Packet
	if err := json.Unmarshal(raw, &p); err != nil {
		return
	}
	switch p.Type {
	case protocol.PacketPong:
		// keepalive only
	case protocol.PacketWelcome:
		// duplicate welcome — ignore
	case protocol.PacketMessage:
		m := Message{MsgID: p.MsgID, From: p.From, To: p.To, Type: string(p.Type), TS: p.TS, Payload: p.Payload}
		if !c.KeepDuplicates && !c.remember(m.MsgID) {
			return // duplicate delivery, drop silently
		}
		c.handler.OnMessage(m)
	case protocol.PacketMessageAck:
		var a Ack
		_ = json.Unmarshal(p.Payload, &a)
		c.handler.OnAck(a)
	case protocol.PacketDeliveryStat, protocol.FileOffer, protocol.FileChunk,
		protocol.FileComplete, protocol.PairRequest, protocol.PairAccept,
		protocol.PairReject, protocol.CallOffer, protocol.CallAnswer,
		protocol.CallICE, protocol.CallReject, protocol.CallEnd:
		m := Message{MsgID: p.MsgID, From: p.From, To: p.To, Type: string(p.Type), TS: p.TS, Payload: p.Payload}
		if !c.KeepDuplicates && !c.remember(m.MsgID) {
			return
		}
		c.handler.OnMessage(m)
	case protocol.PacketSyncResponse:
		var sr protocol.SyncResponsePayload
		_ = json.Unmarshal(p.Payload, &sr)
		for _, sm := range sr.Messages {
			m := Message{MsgID: sm.MsgID, From: sm.From, Type: sm.Type, TS: sm.TS, Payload: sm.Payload}
			if !c.KeepDuplicates && !c.remember(m.MsgID) {
				continue
			}
			c.handler.OnMessage(m)
		}
	case protocol.PacketError:
		var e ServerError
		_ = json.Unmarshal(p.Payload, &e)
		c.handler.OnError(e)
	}
}

// remember records a msg_id, returning false if already seen.
func (c *Client) remember(msgID string) bool {
	if msgID == "" {
		return true
	}
	c.seenMu.Lock()
	defer c.seenMu.Unlock()
	if c.seen[msgID] {
		return false
	}
	c.seen[msgID] = true
	return true
}

func (c *Client) shutdown(reason error) {
	c.closedOnce.Do(func() {
		c.connMu.Lock()
		if c.conn != nil {
			_ = c.conn.Close()
			c.conn = nil
		}
		c.connMu.Unlock()
		c.closeErr = reason
		close(c.done)
		c.handler.OnClosed(reason)
	})
}

func mustJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		return json.RawMessage(`{}`)
	}
	return b
}
