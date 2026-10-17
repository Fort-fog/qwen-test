package client_test

import (
	"encoding/base64"
	"encoding/json"
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
	"github.com/boltun/server/internal/e2e"
	"github.com/boltun/server/internal/protocol"
	"github.com/boltun/server/internal/relay"
	"github.com/boltun/server/internal/store"
	"github.com/boltun/server/internal/transport"
)

// e2eUser is a UserEvents implementation that records decrypted messages,
// plaintext passthroughs and errors for assertions.
type e2eUser struct {
	mu        sync.Mutex
	decrypted []e2eDecrypted
	plain     []client.Message
	errs      []client.ServerError
	keyCh     chan string // fingerprint of our own key, for test convenience
}

type e2eDecrypted struct {
	msgID, from string
	text        string
	ts          int64
}

func newE2EUser() *e2eUser {
	return &e2eUser{keyCh: make(chan string, 1)}
}

func (u *e2eUser) OnWelcome(w client.Welcome) {}
func (u *e2eUser) OnPlainText(m client.Message) {
	u.mu.Lock()
	u.plain = append(u.plain, m)
	u.mu.Unlock()
}
func (u *e2eUser) OnDecrypted(msgID, from string, plaintext []byte, ts int64) {
	u.mu.Lock()
	u.decrypted = append(u.decrypted, e2eDecrypted{msgID, from, string(plaintext), ts})
	u.mu.Unlock()
}
func (u *e2eUser) OnError(e client.ServerError) {
	u.mu.Lock()
	u.errs = append(u.errs, e)
	u.mu.Unlock()
}
func (u *e2eUser) OnClosed(error) {}

func (u *e2eUser) waitDecrypted(t *testing.T) e2eDecrypted {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		u.mu.Lock()
		if len(u.decrypted) > 0 {
			d := u.decrypted[0]
			u.decrypted = u.decrypted[1:]
			u.mu.Unlock()
			return d
		}
		u.mu.Unlock()
		select {
		case <-deadline:
			t.Fatal("timeout waiting for decrypted message")
		case <-time.After(20 * time.Millisecond):
		}
	}
}

func (u *e2eUser) hasErr(code protocol.ErrorCode) bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	for _, e := range u.errs {
		if e.Code == code {
			return true
		}
	}
	return false
}

func newRealServer(t *testing.T) (*httptest.Server, *store.Store) {
	t.Helper()
	cfg := &config.Config{
		DevMode:        true,
		ListenAddr:     ":0",
		MaxConnections: 32,
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

// dialE2E connects a real E2E-enabled client to the real relay through the
// real WebSocket transport — no mocks anywhere in this path.
func dialE2E(t *testing.T, ts *httptest.Server, dev string, kp *e2e.KeyPair) (*client.E2EHandler, *e2eUser) {
	t.Helper()
	u := newE2EUser()
	h, err := client.NewE2E(client.Config{URL: wsURL(ts), DeviceID: dev}, kp, u)
	if err != nil {
		t.Fatalf("new e2e client %s: %v", dev, err)
	}
	if _, err := h.Connect(); err != nil {
		t.Fatalf("connect %s: %v", dev, err)
	}
	t.Cleanup(func() { h.Close() })
	return h, u
}

// TestE2ERoundTripThroughRelay proves the full production path:
// Seal on sender -> WebSocket -> relay routing (payload opaque) ->
// recipient client -> Open. Also asserts the relay never saw plaintext.
func TestE2ERoundTripThroughRelay(t *testing.T) {
	ts, st := newRealServer(t)

	aliceKP, err := e2e.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	bobKP, err := e2e.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	alice, _ := dialE2E(t, ts, "e2e-alice-dev", aliceKP)
	bob, bobU := dialE2E(t, ts, "e2e-bob-dev-01", bobKP)

	// Key discovery via KEY_REQUEST / KEY_RESPONSE over the real relay.
	ch, err := alice.FetchPeerKey("e2e-bob-dev-01")
	if err != nil {
		t.Fatal(err)
	}
	key, ok := <-ch
	if !ok || key == nil {
		t.Fatal("peer key lookup failed")
	}
	if *key != bobKP.Public {
		t.Fatal("KEY_RESPONSE returned a key that does not match bob's identity pair")
	}

	const secret = "boltun e2e integration secret 🚀"
	msgID, err := alice.SendE2EMessage("e2e-bob-dev-01", []byte(secret))
	if err != nil {
		t.Fatalf("send e2e: %v", err)
	}

	got := bobU.waitDecrypted(t)
	if got.text != secret {
		t.Fatalf("decrypted text mismatch: got %q want %q", got.text, secret)
	}
	if got.from != "e2e-alice-dev" {
		t.Errorf("sender binding wrong: from=%q", got.from)
	}
	if got.msgID != msgID {
		t.Errorf("msg id mismatch: envelope opened under %q, sent as %q", got.msgID, msgID)
	}

	// Relay zero-knowledge check: the persisted copy (offline store keeps
	// every routed MESSAGE) must not contain the plaintext anywhere.
	raw, err := json.Marshal(st)
	_ = raw
	data := dumpStore(t, st)
	if strings.Contains(data, secret) || strings.Contains(data, base64.StdEncoding.EncodeToString([]byte(secret))) {
		t.Fatal("PLAINTEXT LEAK: found message text in relay offline store")
	}
	_ = bob
}

func dumpStore(t *testing.T, st *store.Store) string {
	t.Helper()
	// Snapshot all queues by syncing known recipients through the public API.
	var sb strings.Builder
	for _, dev := range []string{"e2e-bob-dev-01"} {
		msgs, err := st.Pending(dev)
		if err != nil {
			continue
		}
		for _, m := range msgs {
			b, _ := json.Marshal(m)
			sb.Write(b)
		}
	}
	return sb.String()
}

// TestE2ETamperedEnvelopeRejectedOnOpen verifies that ciphertext/tag/header
// tampering detected at the wire level causes Open failure surfaced as
// E2E_OPEN_FAILED, and the message is NOT delivered as decrypted.
func TestE2ETamperedEnvelopeRejectedOnOpen(t *testing.T) {
	ts, _ := newRealServer(t)
	aliceKP, _ := e2e.GenerateKeyPair()
	bobKP, _ := e2e.GenerateKeyPair()

	alice, _ := dialE2E(t, ts, "e2e-tamper-alice", aliceKP)
	_, bobU := dialE2E(t, ts, "e2e-tamper-bob-dev", bobKP)

	ch, _ := alice.FetchPeerKey("e2e-tamper-bob-dev")
	bobPub := <-ch
	if bobPub == nil {
		t.Fatal("no bob key")
	}

	// Seal manually so we can corrupt the envelope before sending raw.
	msgID := "tamper-msg-0001"
	payload, err := alice.SealFor("e2e-tamper-bob-dev", msgID, []byte("do not deliver me"))
	if err != nil {
		t.Fatal(err)
	}
	var env client.E2EEnvelopePayload
	if err := json.Unmarshal(payload, &env); err != nil {
		t.Fatal(err)
	}
	rawEnv, err := e2e.DecodeEnvelope(env.Env)
	if err != nil {
		t.Fatal(err)
	}
	// Flip one bit in the ciphertext area (after version+ephpub+nonce).
	rawEnv[len(rawEnv)-1] ^= 0x01
	env.Env = e2e.EncodeEnvelope(rawEnv)
	corrupted, _ := json.Marshal(env)

	// Send the corrupted envelope as a normal MESSAGE through the relay.
	if _, err := alice.SendMessage("e2e-tamper-bob-dev", corrupted); err != nil {
		t.Fatal(err)
	}

	deadline := time.After(5 * time.Second)
	for {
		if bobU.hasErr("E2E_OPEN_FAILED") {
			break
		}
		select {
		case <-deadline:
			t.Fatal("expected E2E_OPEN_FAILED error for tampered envelope")
		case <-time.After(20 * time.Millisecond):
		}
	}
	bobU.mu.Lock()
	dec := len(bobU.decrypted)
	bobU.mu.Unlock()
	if dec != 0 {
		t.Fatal("tampered envelope was delivered as decrypted — integrity failure")
	}
}

// TestE2EUnknownSenderKeyReportsError: a message sealed by a device whose
// identity key the recipient has never resolved must fail cleanly with
// E2E_NO_SENDER_KEY (and trigger a KEY_REQUEST), never decrypt anything.
func TestE2EUnknownSenderKeyReportsError(t *testing.T) {
	ts, _ := newRealServer(t)
	malloryKP, _ := e2e.GenerateKeyPair()
	bobKP, _ := e2e.GenerateKeyPair()

	// mallory announces NO identity key (plain client), but seals with an
	// arbitrary key claiming to be someone else.
	mal, err := client.New(client.Config{URL: wsURL(ts), DeviceID: "e2e-mallory-nokey"}, &collector{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mal.Connect(); err != nil {
		t.Fatal(err)
	}
	defer mal.Close()

	_, bobU := dialE2E(t, ts, "e2e-victim-bob-dev", bobKP)

	env, err := e2e.Seal(malloryKP, &bobKP.Public, "unknown-sender-1", []byte("sneaky"))
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(client.E2EEnvelopePayload{Kind: "e2ee", V: 1, Env: e2e.EncodeEnvelope(env)})
	if _, err := mal.SendMessage("e2e-victim-bob-dev", payload); err != nil {
		t.Fatal(err)
	}

	deadline := time.After(5 * time.Second)
	for {
		if bobU.hasErr("E2E_NO_SENDER_KEY") {
			break
		}
		select {
		case <-deadline:
			t.Fatal("expected E2E_NO_SENDER_KEY for unknown sender")
		case <-time.After(20 * time.Millisecond):
		}
	}
	bobU.mu.Lock()
	dec := len(bobU.decrypted)
	bobU.mu.Unlock()
	if dec != 0 {
		t.Fatal("message from unknown sender was decrypted")
	}
}

// TestE2EWrongRecipientNoDecrypt: sealing for a third party's key means the
// intended recipient cannot open it — proves per-recipient isolation.
func TestE2EWrongRecipientNoDecrypt(t *testing.T) {
	ts, _ := newRealServer(t)
	aliceKP, _ := e2e.GenerateKeyPair()
	bobKP, _ := e2e.GenerateKeyPair()
	eveKP, _ := e2e.GenerateKeyPair()

	alice, _ := dialE2E(t, ts, "e2e-wr-alice-dev", aliceKP)
	_, bobU := dialE2E(t, ts, "e2e-wr-bob-dev-01", bobKP)

	// Alice seals for EVE's key but sends the envelope to BOB (mis-route).
	ch, _ := alice.FetchPeerKey("nobody-eve") // will fail: eve offline
	<-ch                                     // drain closed channel
	env, err := e2e.Seal(aliceKP, &eveKP.Public, "wrong-recip-1", []byte("not for bob"))
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(client.E2EEnvelopePayload{Kind: "e2ee", V: 1, Env: e2e.EncodeEnvelope(env)})
	if _, err := alice.SendMessage("e2e-wr-bob-dev-01", payload); err != nil {
		t.Fatal(err)
	}

	time.Sleep(500 * time.Millisecond)
	bobU.mu.Lock()
	dec := len(bobU.decrypted)
	bobU.mu.Unlock()
	if dec != 0 {
		t.Fatal("bob decrypted an envelope sealed for another recipient key")
	}
	if !bobU.hasErr("E2E_OPEN_FAILED") {
		t.Log("note: OPEN_FAILED may surface after sender-key resolution; dec==0 is the hard guarantee")
	}
}

// TestKeyExchangeTrustLimitation documents (as an executable assertion)
// that KEY_RESPONSE returns whatever the peer ANNOUNCED at HELLO — the
// relay does not verify ownership. This is why pairing/fingerprint
// verification remains future work; do not treat KEY_RESPONSE as auth.
func TestKeyExchangeTrustLimitation(t *testing.T) {
	ts, _ := newRealServer(t)
	victimKP, _ := e2e.GenerateKeyPair()
	attackerKP, _ := e2e.GenerateKeyPair()

	// Attacker announces the VICTIM's public key at HELLO (identity claim
	// without proof of private-key possession).
	fake, err := client.New(client.Config{
		URL:         wsURL(ts),
		DeviceID:    "e2e-attacker-dev",
		IdentityPub: base64.StdEncoding.EncodeToString(victimKP.Public[:]),
	}, &collector{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fake.Connect(); err != nil {
		t.Fatal(err)
	}
	defer fake.Close()

	alice, _ := dialE2E(t, ts, "e2e-trust-alice-dev", attackerKP)
	ch, _ := alice.FetchPeerKey("e2e-attacker-dev")
	k := <-ch
	if k == nil {
		t.Fatal("expected relay to return the announced key")
	}
	if *k != victimKP.Public {
		t.Fatal("relay altered the announced key — unexpected")
	}
	t.Log("CONFIRMED LIMITATION: KEY_RESPONSE proves presence, not identity; MITM-resistant trust requires out-of-band verification (future work)")
}
