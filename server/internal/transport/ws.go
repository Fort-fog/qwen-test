// Package transport wires WebSocket connections to the relay.
package transport

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"github.com/boltun/server/internal/config"
	"github.com/boltun/server/internal/devices"
	"github.com/boltun/server/internal/protocol"
	"github.com/boltun/server/internal/relay"
)

type Server struct {
	cfg      *config.Config
	relay    *relay.Relay
	logger   *log.Logger
	upgrader websocket.Upgrader
	sem      chan struct{} // connection limiter
	httpSrv  *http.Server
}

func New(cfg *config.Config, r *relay.Relay, logger *log.Logger) *Server {
	return &Server{
		cfg:    cfg,
		relay:  r,
		logger: logger,
		upgrader: websocket.Upgrader{
			ReadBufferSize:  4096,
			WriteBufferSize: 4096,
			Error: func(w http.ResponseWriter, r *http.Request, status int, reason error) {
				logger.Printf("ws upgrade error: status=%d reason=%v", status, reason)
			},
			// Clients are native apps (no browser origin model). For a
			// browser-based client later, restrict this to an allow-list.
			CheckOrigin: func(r *http.Request) bool { return true },
		},
		sem: make(chan struct{}, cfg.MaxConnections),
	}
}

// Handler returns the mux with /ws and /healthz routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", s.handleWS)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"status":      "ok",
			"online":      s.relay.Registry().Count(),
			"protocol":    protocol.ProtocolVersion,
			"e2ee_active": false,
			"dev_mode":    s.cfg.DevMode,
		})
	})
	return mux
}

// ListenAndServe starts the HTTP(S) server. Shutdown via Shutdown(ctx).
func (s *Server) ListenAndServe() error {
	s.httpSrv = &http.Server{
		Addr:         s.cfg.ListenAddr,
		Handler:      s.Handler(),
		ReadTimeout:  s.cfg.ReadTimeout,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
	if s.cfg.DevMode {
		s.logger.Printf("WARNING: DEV MODE — plain WS without TLS. Local development only, never expose publicly.")
		return s.httpSrv.ListenAndServe()
	}
	return s.httpSrv.ListenAndServeTLS(s.cfg.TLSCertFile, s.cfg.TLSKeyFile)
}

// Shutdown gracefully stops accepting new connections and waits for active
// handlers to finish (ctx-bound).
func (s *Server) Shutdown(ctx context.Context) error {
	if s.httpSrv == nil {
		return nil
	}
	return s.httpSrv.Shutdown(ctx)
}

var errConnLimit = errors.New("transport: connection limit reached")

func (s *Server) handleWS(w http.ResponseWriter, r *http.Request) {
	select {
	case s.sem <- struct{}{}:
		defer func() { <-s.sem }()
	default:
		http.Error(w, "connection limit reached", http.StatusServiceUnavailable)
		return
	}

	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		return // upgrader already reported
	}
	s.serveConn(conn)
}

const writeQueueSize = 64

func (s *Server) serveConn(conn *websocket.Conn) {
	defer conn.Close()
	send := make(chan []byte, writeQueueSize)
	done := make(chan struct{})
	var closeOnce sync.Once
	closeConn := func() { closeOnce.Do(func() { close(done) }) }

	// --- writer goroutine: single writer as required by gorilla/websocket
	go func() {
		defer conn.Close()
		for {
			select {
			case raw := <-send:
				_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
				if err := conn.WriteMessage(websocket.TextMessage, raw); err != nil {
					return
				}
			case <-done:
				_ = conn.WriteControl(websocket.CloseMessage,
					websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""),
					time.Now().Add(3*time.Second))
				return
			}
		}
	}()

	var session *devices.Session

	// application-level PING keepalive
	pingerDone := make(chan struct{})
	go func() {
		t := time.NewTicker(s.cfg.PingInterval)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				p := &protocol.Packet{
					Version: protocol.ProtocolVersion,
					Type:    protocol.PacketPing,
					From:    "server",
					TS:      time.Now().UnixMilli(),
				}
				raw, _ := protocol.Encode(p)
				select {
				case send <- raw:
				default:
				}
			case <-pingerDone:
				return
			}
		}
	}()
	defer close(pingerDone)

	conn.SetReadLimit(int64(s.cfg.MaxPacketBytes) + 4096)
	conn.SetCloseHandler(func(code int, text string) error {
		closeConn()
		return nil
	})
	// gorilla invokes the close handler only when a Close frame is *received*.
	// If the client simply drops the TCP connection (conn.Close() on its side),
	// ReadMessage fails without ever calling the handler, which would leave the
	// writer goroutine blocked forever and delay session cleanup. Treating any
	// read-loop exit as a connection close fixes both problems.
	defer closeConn()

	for {
		_ = conn.SetReadDeadline(time.Now().Add(s.cfg.ReadTimeout))
		_, raw, err := conn.ReadMessage()
		if err != nil {
			break
		}
		if len(raw) > s.cfg.MaxPacketBytes {
			s.replyErr(send, protocol.ErrCodeTooLarge, "packet exceeds configured maximum", "")
			continue
		}

		p, err := protocol.Decode(raw)
		if err != nil {
			code := protocol.ErrCodeMalformed
			if errors.Is(err, protocol.ErrUnknownType) {
				code = protocol.ErrCodeNotSupported
			}
			s.replyErr(send, code, err.Error(), "")
			continue
		}

		// Server-only types must not arrive from clients.
		if protocol.ServerOnlyTypes[p.Type] {
			s.replyErr(send, protocol.ErrCodeUnauthorized, "packet type is server-only", p.MsgID)
			continue
		}
		if !protocol.ClientToServerTypes[p.Type] {
			s.replyErr(send, protocol.ErrCodeNotSupported, "packet type not allowed client->server", p.MsgID)
			continue
		}

		switch p.Type {
		case protocol.PacketHello:
			if session != nil {
				s.replyErr(send, protocol.ErrCodeUnauthorized, "session already established", p.MsgID)
				continue
			}
			resp, sess := s.relay.HandleHello(send, p.Payload)
			rawOut, _ := protocol.Encode(resp)
			send <- rawOut
			session = sess
		default:
			if session == nil {
				s.replyErr(send, protocol.ErrCodeUnauthorized, "HELLO required before this packet type", p.MsgID)
				continue
			}
			s.relay.Registry().Touch(session.SessionID)
			s.relay.Dispatch(session, p, send)
		}
	}

	if session != nil {
		s.relay.Registry().Unregister(session.SessionID)
		s.logger.Printf("session closed device=%s session=%s", session.DeviceID, short(session.SessionID))
	}
	closeConn()
}

func (s *Server) replyErr(send chan []byte, code protocol.ErrorCode, msg, ref string) {
	p := &protocol.Packet{
		Version: protocol.ProtocolVersion,
		Type:    protocol.PacketError,
		From:    "server",
		Payload: mustJSON(protocol.ErrorPayload{Code: code, Message: msg, RefMsgID: ref}),
	}
	raw, _ := protocol.Encode(p)
	select {
	case send <- raw:
	default:
	}
}

func mustJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		b = []byte(`{"code":"INTERNAL_ERROR","message":"payload marshal failed"}`)
	}
	return b
}

func short(s string) string {
	if len(s) > 8 {
		return s[:8]
	}
	return s
}
