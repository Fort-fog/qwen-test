// BOLTUN smoke client: connects to a running relay via the reusable
// internal/client package, performs HELLO/WELCOME, sends one MESSAGE and
// waits for MESSAGE_ACK (and any inbound MESSAGE) before exiting.
//
// Usage: go run ./cmd/boltun-smoke <ws_url> <device_id> <peer_device_id>
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/boltun/server/internal/client"
)

type handler struct {
	ackd     chan string
	inbox    chan client.Message
	welcomeC chan client.Welcome
}

func (h *handler) OnWelcome(w client.Welcome) {
	select {
	case h.welcomeC <- w:
	default:
	}
}
func (h *handler) OnMessage(m client.Message) {
	select {
	case h.inbox <- m:
	default:
	}
}
func (h *handler) OnAck(a client.Ack) {
	select {
	case h.ackd <- a.Stage:
	default:
	}
}
func (h *handler) OnError(e client.ServerError) {
	fmt.Printf("SERVER ERROR: %s (%s)\n", e.Message, e.Code)
}
func (h *handler) OnClosed(err error) { fmt.Printf("closed: %v\n", err) }

func main() {
	if len(os.Args) != 4 {
		fmt.Fprintln(os.Stderr, "usage: boltun-smoke <ws_url> <device_id> <peer_device_id>")
		os.Exit(2)
	}
	url, dev, peer := os.Args[1], os.Args[2], os.Args[3]
	h := &handler{
		ackd:     make(chan string, 4),
		inbox:    make(chan client.Message, 16),
		welcomeC: make(chan client.Welcome, 1),
	}
	c, err := client.New(client.Config{URL: url, DeviceID: dev}, h)
	if err != nil {
		fmt.Fprintln(os.Stderr, "config:", err)
		os.Exit(1)
	}
	w, err := c.Connect()
	if err != nil {
		fmt.Fprintln(os.Stderr, "connect:", err)
		os.Exit(1)
	}
	fmt.Printf("[%s] WELCOME ok: server_time=%d pending=%d ping=%ds\n",
		dev, w.ServerTime, w.PendingMessages, w.PingIntervalSec)

	payload, _ := json.Marshal(map[string]string{"text": "hello from boltun-smoke (TEST PACKET, NO E2E YET)"})
	msgID, err := c.SendMessage(peer, payload)
	if err != nil {
		fmt.Fprintln(os.Stderr, "send:", err)
		os.Exit(1)
	}
	fmt.Printf("[%s] sent msg_id=%s to %s\n", dev, msgID, peer)

	select {
	case stage := <-h.ackd:
		fmt.Printf("[%s] ack stage=%s\n", dev, stage)
	case <-time.After(5 * time.Second):
		fmt.Fprintln(os.Stderr, "no ack within 5s")
		os.Exit(1)
	}
	// Drain any inbound messages briefly, then exit cleanly.
	for {
		select {
		case m := <-h.inbox:
			fmt.Printf("[%s] inbound from=%s msg_id=%s\n", dev, m.From, m.MsgID)
		case <-time.After(500 * time.Millisecond):
			c.Close()
			fmt.Println("SMOKE CLIENT OK")
			return
		}
	}
}
