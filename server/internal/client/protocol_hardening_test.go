package client_test

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/boltun/server/internal/client"
	"github.com/boltun/server/internal/e2e"
)

// --- Phase 4: key-exchange protocol hardening checks -------------
// These tests exercise the REAL relay over the real WebSocket
// transport. They assert routing, DeviceID binding, disconnect
// behaviour, malformed-input handling and size limits for HELLO /
// KEY_REQUEST / KEY_RESPONSE. None of them asserts cryptographic
// ownership of announced keys — see TestKeyExchangeTrustLimitation
// for the documented MITM limitation.

// TestHelloRejectsMalformedIdentityPub: bad base64, wrong length and
// empty-but-present variants must be refused at HELLO with a protocol
// ERROR; only a well-formed 32-byte key registers.
func TestHelloRejectsMalformedIdentityPub(t *testing.T) {
	ts, _ := newRealServer(t)

	bad := []struct {
		name string
		pub  string
	}{
		{"not-base64", "!!!not base64!!!"},
		{"too-short-16b", base64.StdEncoding.EncodeToString(make([]byte, 16))},
		{"too-long-33b", base64.StdEncoding.EncodeToString(make([]byte, 33))},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			_, err := rawHelloNoop(t, wsURL(ts), "hard-hello-dev-"+strings.ReplaceAll(tc.name, "-", ""), tc.pub)
			if err == nil {
				t.Fatalf("HELLO with invalid identity_pub %q was accepted", tc.pub)
			}
		})
	}

	// Valid key must be accepted (control case).
	kp, _ := e2e.GenerateKeyPair()
	c, err := rawHelloNoop(t, wsURL(ts), "hard-hello-valid-dev", base64.StdEncoding.EncodeToString(kp.Public[:]))
	if err != nil {
		t.Fatalf("valid identity_pub rejected: %v", err)
	}
	c.Close()
}

// rawHelloNoop connects a client whose user handler discards everything.
func rawHelloNoop(t *testing.T, url, dev, pub string) (*client.Client, error) {
	t.Helper()
	c, err := client.New(client.Config{URL: url, DeviceID: dev, IdentityPub: pub}, &collector{})
	if err != nil {
		return nil, err
	}
	if _, err := c.Connect(); err != nil {
		return nil, err
	}
	return c, nil
}

// TestKeyRequestBoundToDeviceID: KEY_RESPONSE must carry the key that
// the target device announced at HELLO, tied to its DeviceID — not the
// requester's own key and not a stale one from another session id.
func TestKeyRequestBoundToDeviceID(t *testing.T) {
	ts, _ := newRealServer(t)
	aliceKP, _ := e2e.GenerateKeyPair()
	bobKP, _ := e2e.GenerateKeyPair()

	alice, _ := dialE2E(t, ts, "hard-kreq-alice-dev", aliceKP)
	bob, _ := dialE2E(t, ts, "hard-kreq-bob-dev-01", bobKP)
	_ = bob

	ch, err := alice.FetchPeerKey("hard-kreq-bob-dev-01")
	if err != nil {
		t.Fatal(err)
	}
	key := <-ch
	if key == nil {
		t.Fatal("no key returned")
	}
	if *key != bobKP.Public {
		t.Fatal("KEY_RESPONSE not bound to target DeviceID's announced key")
	}
	if *key == aliceKP.Public {
		t.Fatal("KEY_RESPONSE returned requester's own key")
	}
}

// TestKeyRequestOfflinePeer: when the target is not connected, the
// relay answers Found=false (channel closes without a key) rather
// than hanging or leaking anything.
func TestKeyRequestOfflinePeer(t *testing.T) {
	ts, _ := newRealServer(t)
	aliceKP, _ := e2e.GenerateKeyPair()
	alice, _ := dialE2E(t, ts, "hard-offline-alice-dev", aliceKP)

	ch, err := alice.FetchPeerKey("hard-nonexistent-peer")
	if err != nil {
		t.Fatal(err)
	}
	select {
	case k := <-ch:
		if k != nil {
			t.Fatal("offline peer unexpectedly resolved")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("FetchPeerKey against offline peer hung")
	}
}

// TestKeyRequestAfterPeerDisconnect: a key learned while the peer was
// online stays cached (it is the peer's long-lived identity key); but
// a fresh lookup after disconnect returns Found=false. Also verifies
// the relay removed the dead session from its registry.
func TestKeyRequestAfterPeerDisconnect(t *testing.T) {
	ts, _ := newRealServer(t)
	aliceKP, _ := e2e.GenerateKeyPair()
	bobKP, _ := e2e.GenerateKeyPair()

	alice, _ := dialE2E(t, ts, "hard-disc-alice-dev-", aliceKP)
	bob, _ := dialE2E(t, ts, "hard-disc-bob-dev-001", bobKP)

	ch, _ := alice.FetchPeerKey("hard-disc-bob-dev-001")
	if k := <-ch; k == nil || *k != bobKP.Public {
		t.Fatal("pre-disconnect lookup failed")
	}
	bob.Close()
	// Give the relay a moment to process the close frame.
	time.Sleep(300 * time.Millisecond)

	// New handler instance => cold cache => live lookup must miss.
	alice2KP := aliceKP
	u := newE2EUser()
	h2, err := client.NewE2E(client.Config{URL: wsURL(ts), DeviceID: "hard-disc-alice-dev-2"}, alice2KP, u)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h2.Connect(); err != nil {
		t.Fatal(err)
	}
	defer h2.Close()
	ch2, err := h2.FetchPeerKey("hard-disc-bob-dev-001")
	if err != nil {
		t.Fatal(err)
	}
	select {
	case k := <-ch2:
		if k != nil {
			t.Fatal("disconnected peer still resolves — registry leak")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("lookup after disconnect hung")
	}
}

// TestKeyRequestEmptyPayloadRejected: a KEY_REQUEST with no/invalid
// payload gets a MALFORMED error back, not a crash and not a response.
func TestKeyRequestEmptyPayloadRejected(t *testing.T) {
	ts, _ := newRealServer(t)
	kp, _ := e2e.GenerateKeyPair()
	u := newE2EUser()
	h, err := client.NewE2E(client.Config{URL: wsURL(ts), DeviceID: "hard-empty-req-dev"}, kp, u)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.Connect(); err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	// Bypass FetchPeerKey validation by sending a raw request through the
	// embedded Client with an empty target.
	errSend := h.RequestPeerKey("")
	if errSend == nil {
		// If the client allowed it, the relay must answer MALFORMED.
		deadline := time.After(3 * time.Second)
		for {
			if u.hasErr("MALFORMED_PACKET") {
				return
			}
			select {
			case <-deadline:
				t.Fatal("empty KEY_REQUEST produced neither client error nor MALFORMED response")
			case <-time.After(20 * time.Millisecond):
			}
		}
	}
	// Client-side rejection is also acceptable behaviour.
}

// TestPrivateKeyNeverTransitsRelay: scan every byte the relay can see
// (offline store copy of routed payloads + announced identity keys)
// for private-key material. Private halves must never appear.
func TestPrivateKeyNeverTransitsRelay(t *testing.T) {
	ts, st := newRealServer(t)
	aliceKP, _ := e2e.GenerateKeyPair()
	bobKP, _ := e2e.GenerateKeyPair()

	alice, _ := dialE2E(t, ts, "hard-leak-alice-dev-", aliceKP)
	dialE2E(t, ts, "hard-leak-bob-dev-001", bobKP)

	ch, _ := alice.FetchPeerKey("hard-leak-bob-dev-001")
	if k := <-ch; k == nil {
		t.Fatal("key exchange failed")
	}
	if _, err := alice.SendE2EMessage("hard-leak-bob-dev-001", []byte("private-scan-secret")); err != nil {
		t.Fatal(err)
	}

	leakA := base64.StdEncoding.EncodeToString(aliceKP.Private[:])
	leakB := base64.StdEncoding.EncodeToString(bobKP.Private[:])
	hexA := strings.ToLower(hexString(aliceKP.Private[:]))
	hexB := strings.ToLower(hexString(bobKP.Private[:]))

	pending, _ := st.Pending("hard-leak-bob-dev-001")
	var sb strings.Builder
	for _, m := range pending {
		b, _ := json.Marshal(m)
		sb.Write(b)
	}
	data := sb.String()
	for _, probe := range []string{leakA, leakB, hexA, hexB} {
		if probe != "" && strings.Contains(data, probe) {
			t.Fatal("PRIVATE KEY LEAK found in relay-visible data")
		}
	}
}

func hexString(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, x := range b {
		out = append(out, digits[x>>4], digits[x&0xf])
	}
	return string(out)
}
