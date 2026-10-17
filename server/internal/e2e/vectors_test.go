package e2e

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestGenerateCrossLanguageVectors produces deterministic E2E test vectors
// used to verify Go <-> Dart interoperability of Seal/Open. The fixed
// "private" keys below are TEST-ONLY fixtures and must never be used in
// production. Output: testdata/e2e_vectors.json at the module root.
func TestGenerateCrossLanguageVectors(t *testing.T) {
	const (
		senderPrivHex = "1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f"
		recipPrivHex  = "2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a"
		ephPrivHex    = "3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b3b"
		msgID         = "0102030405060708090a0b0c0d0e0f10"
		nonceHex      = "4c4c4c4c4c4c4c4c4c4c4c4c"
		plaintext     = "boltun e2e vector one"
	)

	unhex := func(s string) *[32]byte {
		b, err := hex.DecodeString(s)
		if err != nil || len(b) != 32 {
			t.Fatalf("bad hex key %q", s)
		}
		var a [32]byte
		copy(a[:], b)
		return &a
	}

	sender, err := KeyPairFromPrivate(unhex(senderPrivHex)[:])
	if err != nil {
		t.Fatal(err)
	}
	recip, err := KeyPairFromPrivate(unhex(recipPrivHex)[:])
	if err != nil {
		t.Fatal(err)
	}
	eph, err := KeyPairFromPrivate(unhex(ephPrivHex)[:])
	if err != nil {
		t.Fatal(err)
	}

	shared, err := ecdh(&eph.Private, &recip.Public)
	if err != nil {
		t.Fatal(err)
	}
	key, err := deriveKey(&shared, &eph.Public, &sender.Public, &recip.Public, msgID)
	if err != nil {
		t.Fatal(err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := hex.DecodeString(nonceHex)
	if err != nil {
		t.Fatal(err)
	}
	aad := aadBytes(sender.Public[:], recip.Public[:], msgID)
	ct := gcm.Seal(nil, nonce, []byte(plaintext), aad)

	env := make([]byte, 0, 1+32+len(nonce)+len(ct))
	env = append(env, envelopeVersion)
	env = append(env, eph.Public[:]...)
	env = append(env, nonce...)
	env = append(env, ct...)

	// Sanity: Open must recover the plaintext from the deterministic envelope.
	got, err := Open(recip, env, msgID, &sender.Public)
	if err != nil {
		t.Fatalf("Open(deterministic envelope): %v", err)
	}
	if string(got) != plaintext {
		t.Fatalf("roundtrip mismatch: %q", got)
	}

	out := map[string]string{
		"scheme":                      "boltun-e2e-v1",
		"kdf":                         `HKDF-SHA256(ikm=X25519(eph_priv, recip_pub), salt=eph_pub[32], info="boltun-e2e-v1|"+hex(sender_pub)+"|"+hex(recip_pub)+"|"+msg_id, L=32)`,
		"aad_format":                  `"boltun-aad-v1|"+hex(sender_pub)+"|"+hex(recip_pub)+"|"+msg_id`,
		"envelope_layout":             "[1B version=0x00][32B ephemeral pub][12B nonce][ciphertext||16B GCM tag]",
		"transport_payload_json":      `{"kind":"e2ee","v":1,"env":"base64std(envelope)"}`,
		"sender_identity_priv_hex":    senderPrivHex,
		"sender_identity_pub_hex":     hex.EncodeToString(sender.Public[:]),
		"recipient_identity_priv_hex": recipPrivHex,
		"recipient_identity_pub_hex":  hex.EncodeToString(recip.Public[:]),
		"ephemeral_priv_hex":          ephPrivHex,
		"ephemeral_pub_hex":           hex.EncodeToString(eph.Public[:]),
		"msg_id":                      msgID,
		"nonce_hex":                   nonceHex,
		"plaintext_utf8":              plaintext,
		"derived_key_hex":             hex.EncodeToString(key),
		"envelope_hex":                hex.EncodeToString(env),
		"envelope_b64":                EncodeEnvelope(env),
	}

	dir := filepath.Join("..", "..", "testdata")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(filepath.Join(dir, "e2e_vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote %s/e2e_vectors.json", dir)
}
