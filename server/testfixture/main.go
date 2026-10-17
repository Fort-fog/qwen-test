// BOLTUN cross-language test fixture: serves the REAL relay stack
// (transport + relay + store + devices registry -- same wiring as
// cmd/boltun-server) on 127.0.0.1 with an OS-assigned port and prints
// "LISTENING <port>" on stdout. Used by the Dart integration test to run a
// genuine Go<->Dart E2E exchange over WebSocket. Test-only binary.
package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/boltun/server/internal/config"
	"github.com/boltun/server/internal/devices"
	"github.com/boltun/server/internal/protocol"
	"github.com/boltun/server/internal/relay"
	"github.com/boltun/server/internal/store"
	"github.com/boltun/server/internal/transport"
)

func main() {
	cfg := &config.Config{
		DevMode:        true,
		ListenAddr:     "127.0.0.1:0",
		MaxConnections: 32,
		MaxPacketBytes: protocol.MaxPacketSize,
		ReadTimeout:    30 * time.Second, // generous: external test driver may pause
		PingInterval:   25 * time.Second,
	}
	reg := devices.NewRegistry()
	st, err := store.Open("") // in-memory only; nothing touches disk
	if err != nil {
		log.Fatal(err)
	}
	rly := relay.New(reg, st, log.New(io.Discard, "", 0), cfg.MaxPacketBytes)
	srv := transport.New(cfg, rly, log.New(io.Discard, "", 0))

	ln, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		log.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	fmt.Printf("LISTENING %d\n", port)

	httpSrv := &http.Server{Handler: srv.Handler()}
	go func() { _ = httpSrv.Serve(ln) }()

	// Exit when the driver closes our stdin pipe, or after a hard safety
	// timeout so no orphaned server can linger.
	intr := make(chan struct{})
	go func() {
		b := make([]byte, 1)
		for {
			n, err := os.Stdin.Read(b)
			if n == 0 || err != nil {
				close(intr)
				return
			}
		}
	}()
	select {
	case <-intr:
	case <-time.After(90 * time.Second):
	}
	_ = ln.Close()
	os.Exit(0)
}
