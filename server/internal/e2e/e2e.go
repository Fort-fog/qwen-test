// Package e2e implements the BOLTUN end-to-end encryption envelope.
//
// Design (protocol v1, "e2ee" payload):
//   - Each device owns a long-lived X25519 key pair. The private key never
//     leaves the device; the relay only ever sees public keys and opaque
//     envelopes.
//   - A message is encrypted for the recipient's identity public key using
//     an ephemeral X25519 sender key pair + HKDF-SHA256 derived AES-256-GCM
//     key (ECIES-style). Fresh ephemeral keys per message give per-message
//     forward secrecy against a later identity-key compromise.
//   - Envelope wire format (base64 inside the JSON payload object):
//     [1B version][32B ephemeral pub][12B nonce][N B ciphertext||tag]
//   - Additional authenticated data binds sender identity pub, recipient
//     identity pub and msg_id, preventing stripping / re-routing /
//     replay-under-another-msg-id attacks.
//
// This package is client-side only by architecture: the relay must remain
// zero-knowledge and never imports it for traffic processing.
package e2e

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"io"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

func sha256New() hash.Hash { return sha256.New() }

// KeyPair is a device identity key pair (X25519).
type KeyPair struct {
	Private [32]byte
	Public  [32]byte
}

const envelopeVersion byte = 0

var (
	ErrShortEnvelope  = errors.New("e2e: envelope too short")
	ErrBadVersion     = errors.New("e2e: unsupported envelope version")
	ErrKeyMismatch    = errors.New("e2e: recipient key mismatch")
	ErrOpenAuthFailed = errors.New("e2e: authentication tag check failed")
)

// GenerateKeyPair creates a fresh identity key pair from CSPRNG entropy.
func GenerateKeyPair() (*KeyPair, error) {
	kp := &KeyPair{}
	if _, err := rand.Read(kp.Private[:]); err != nil {
		return nil, fmt.Errorf("e2e: entropy: %w", err)
	}
	pub, err := curve25519.X25519(kp.Private[:], curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("e2e: pubkey: %w", err)
	}
	copy(kp.Public[:], pub)
	return kp, nil
}

// KeyPairFromPrivate rebuilds a key pair from a stored 32-byte private key.
func KeyPairFromPrivate(priv []byte) (*KeyPair, error) {
	if len(priv) != 32 {
		return nil, errors.New("e2e: private key must be 32 bytes")
	}
	kp := &KeyPair{}
	copy(kp.Private[:], priv)
	pub, err := curve25519.X25519(kp.Private[:], curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	copy(kp.Public[:], pub)
	return kp, nil
}

// deriveKey is the single canonical KDF used by BOTH peers. It takes the
// raw X25519 shared secret (identical on both sides by ECDH symmetry) plus
// values known to both parties:
//   - salt = ephemeral public key (32B, carried in the envelope header);
//   - info = "boltun-e2e-v1|<sender identity pub>|<recipient identity pub>|<msgID>"
//
// The roles inside info are fixed (sender first, recipient second) and
// reconstructible by both peers, so Seal and Open derive the same AES-256
// key. Identity binding is additionally enforced via AAD on the GCM tag.
func deriveKey(sharedSecret, ephemPub, senderPub, recipientPub *[32]byte, msgID string) ([]byte, error) {
	info := fmt.Sprintf("boltun-e2e-v1|%x|%x|%s", senderPub[:], recipientPub[:], msgID)
	key := make([]byte, 32)
	hk := hkdf.New(sha256New, sharedSecret[:], ephemPub[:], []byte(info))
	if _, err := io.ReadFull(hk, key); err != nil {
		return nil, fmt.Errorf("e2e: hkdf: %w", err)
	}
	return key, nil
}

// ecdh computes the raw X25519 shared secret.
func ecdh(priv, pub *[32]byte) ([32]byte, error) {
	var out [32]byte
	s, err := curve25519.X25519(priv[:], pub[:])
	if err != nil {
		return out, fmt.Errorf("e2e: ecdh: %w", err)
	}
	copy(out[:], s)
	return out, nil
}

// Seal encrypts plaintext for recipientPub on behalf of sender.
// Returns the raw envelope bytes (caller base64-encodes into payload).
func Seal(sender *KeyPair, recipientPub *[32]byte, msgID string, plaintext []byte) ([]byte, error) {
	eph, err := GenerateKeyPair()
	if err != nil {
		return nil, err
	}
	shared, err := ecdh(&eph.Private, recipientPub)
	if err != nil {
		return nil, err
	}
	key, err := deriveKey(&shared, &eph.Public, &sender.Public, recipientPub, msgID)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize()) // 12
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("e2e: nonce: %w", err)
	}
	aad := aadBytes(sender.Public[:], recipientPub[:], msgID)
	ct := gcm.Seal(nil, nonce, plaintext, aad)

	env := make([]byte, 0, 1+32+len(nonce)+len(ct))
	env = append(env, envelopeVersion)
	env = append(env, eph.Public[:]...)
	env = append(env, nonce...)
	env = append(env, ct...)
	return env, nil
}

// Open decrypts an envelope produced by Seal. senderPub is the claimed
// sender identity key (from the authenticated session binding on the wire);
// aad verification fails if it was tampered with.
func Open(recipient *KeyPair, envelope []byte, msgID string, senderPub *[32]byte) ([]byte, error) {
	if len(envelope) < 1+32+12+16 {
		return nil, ErrShortEnvelope
	}
	if envelope[0] != envelopeVersion {
		return nil, ErrBadVersion
	}
	var ephPub [32]byte
	copy(ephPub[:], envelope[1:33])
	nonce := envelope[33:45]
	ct := envelope[45:]

	shared, err := ecdh(&recipient.Private, &ephPub)
	if err != nil {
		return nil, err
	}
	key, err := deriveKey(&shared, &ephPub, senderPub, &recipient.Public, msgID)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	aad := aadBytes(senderPub[:], recipient.Public[:], msgID)
	plain, err := gcm.Open(nil, nonce, ct, aad)
	if err != nil {
		return nil, ErrOpenAuthFailed
	}
	return plain, nil
}

func aadBytes(senderPub, recipientPub []byte, msgID string) []byte {
	return []byte(fmt.Sprintf("boltun-aad-v1|%x|%x|%s", senderPub, recipientPub, msgID))
}

// --- Base64 helpers for the JSON payload layer ---

// EncodeEnvelope -> base64 std string for transport.
func EncodeEnvelope(env []byte) string { return base64.StdEncoding.EncodeToString(env) }

// DecodeEnvelope parses transport base64 back to raw bytes.
func DecodeEnvelope(s string) ([]byte, error) { return base64.StdEncoding.DecodeString(s) }
