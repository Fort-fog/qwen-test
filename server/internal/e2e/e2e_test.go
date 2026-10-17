package e2e

import (
	"bytes"
	"strings"
	"testing"
)

func TestSealOpenRoundTrip(t *testing.T) {
	alice, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	bob, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	msgID := "0102030405060708090a0b0c"
	plain := []byte("secret boltun message 🚀")

	env, err := Seal(alice, &bob.Public, msgID, plain)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	got, err := Open(bob, env, msgID, &alice.Public)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("roundtrip mismatch: got %q", got)
	}
}

func TestOpenWrongKeyFails(t *testing.T) {
	alice, _ := GenerateKeyPair()
	bob, _ := GenerateKeyPair()
	eve, _ := GenerateKeyPair()

	env, err := Seal(alice, &bob.Public, "m1", []byte("hi"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(eve, env, "m1", &alice.Public); err == nil {
		t.Fatal("expected failure opening with wrong recipient key")
	}
}

func TestOpenTamperedAADMsgIDFails(t *testing.T) {
	alice, _ := GenerateKeyPair()
	bob, _ := GenerateKeyPair()
	env, _ := Seal(alice, &bob.Public, "m1", []byte("hi"))
	if _, err := Open(bob, env, "m2", &alice.Public); err == nil {
		t.Fatal("expected auth failure when replayed under different msg_id")
	}
}

func TestOpenSpoofedSenderFails(t *testing.T) {
	alice, _ := GenerateKeyPair()
	bob, _ := GenerateKeyPair()
	eve, _ := GenerateKeyPair()
	env, _ := Seal(alice, &bob.Public, "m1", []byte("hi"))
	// Eve claims she sent Alice's ciphertext to Bob.
	if _, err := Open(bob, env, "m1", &eve.Public); err == nil {
		t.Fatal("expected auth failure with spoofed sender identity")
	}
}

func TestOpenBitFlipFails(t *testing.T) {
	alice, _ := GenerateKeyPair()
	bob, _ := GenerateKeyPair()
	env, _ := Seal(alice, &bob.Public, "m1", []byte("hello world 1234567890"))
	env[len(env)-1] ^= 0x01
	if _, err := Open(bob, env, "m1", &alice.Public); err == nil {
		t.Fatal("expected GCM tag failure on bit flip")
	}
}

func TestShortEnvelope(t *testing.T) {
	alice, _ := GenerateKeyPair()
	bob, _ := GenerateKeyPair()
	if _, err := Open(bob, []byte{0, 1, 2}, "m1", &alice.Public); err != ErrShortEnvelope {
		t.Fatalf("want ErrShortEnvelope, got %v", err)
	}
}

func TestBadVersion(t *testing.T) {
	alice, _ := GenerateKeyPair()
	bob, _ := GenerateKeyPair()
	env, _ := Seal(alice, &bob.Public, "m1", []byte("hi"))
	env[0] = 9
	if _, err := Open(bob, env, "m1", &alice.Public); err != ErrBadVersion {
		t.Fatalf("want ErrBadVersion, got %v", err)
	}
}

func TestCiphertextDoesNotLeakPlaintext(t *testing.T) {
	alice, _ := GenerateKeyPair()
	bob, _ := GenerateKeyPair()
	secret := "TOP-SECRET-KERNEL-PANIC-DATA"
	env, _ := Seal(alice, &bob.Public, "m1", []byte(secret))
	if strings.Contains(string(env), secret) {
		t.Fatal("plaintext found in envelope")
	}
}

func TestKeyPairFromPrivateDeterministic(t *testing.T) {
	kp, _ := GenerateKeyPair()
	kp2, err := KeyPairFromPrivate(kp.Private[:])
	if err != nil {
		t.Fatal(err)
	}
	if kp2.Public != kp.Public {
		t.Fatal("public key must be derived deterministically from private")
	}
}

func TestBase64Helpers(t *testing.T) {
	alice, _ := GenerateKeyPair()
	bob, _ := GenerateKeyPair()
	env, _ := Seal(alice, &bob.Public, "m1", []byte("ping"))
	s := EncodeEnvelope(env)
	back, err := DecodeEnvelope(s)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back, env) {
		t.Fatal("base64 roundtrip broken")
	}
}

// TestDeriveKeySymmetry is a regression test for the original bug: the
// sender and recipient derived DIFFERENT HKDF keys because the info string
// mixed role-dependent values (ephemeral pub vs sender identity pub) in
// inconsistent order. Seal/Open roundtrip passing implicitly covers this,
// but we assert key equality directly to pin the invariant down.
func TestDeriveKeySymmetry(t *testing.T) {
	alice, _ := GenerateKeyPair()
	bob, _ := GenerateKeyPair()
	eph, _ := GenerateKeyPair()
	msgID := "regression-symmetry"

	// Sender side: ECDH(ephPriv, bobPub)
	sShared, err := ecdh(&eph.Private, &bob.Public)
	if err != nil {
		t.Fatal(err)
	}
	k1, err := deriveKey(&sShared, &eph.Public, &alice.Public, &bob.Public, msgID)
	if err != nil {
		t.Fatal(err)
	}

	// Recipient side: ECDH(bobPriv, ephPub) — must equal sShared
	rShared, err := ecdh(&bob.Private, &eph.Public)
	if err != nil {
		t.Fatal(err)
	}
	if rShared != sShared {
		t.Fatal("ECDH not symmetric")
	}
	k2, err := deriveKey(&rShared, &eph.Public, &alice.Public, &bob.Public, msgID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(k1, k2) {
		t.Fatalf("derived keys differ: %x vs %x", k1[:4], k2[:4])
	}
}
