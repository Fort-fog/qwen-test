
## Pairing & OOB verification status (2026-10)

### What is implemented (client, commit 7497583)
- `KeyFingerprint` — SHA-256-based short code ("XXX-XXX" hex) over the
  base64 identity public key with domain prefix `boltun-fp-v1|`.
  Deterministic; both sides compute it independently from the pub key.
- `PeerTrustStore` — TOFU pin registry keyed by DeviceID:
  * relay-supplied KEY_RESPONSE keys are pinned as **unverified**;
  * re-lookup of a pinned device with a different key returns
    `KeyChangeConflict`, keeps the OLD pin, and surfaces
    `E2E_KEY_CHANGE:<dev>:<oldfp>-><newfp>` via session lastError;
  * trust is granted ONLY after out-of-band confirmation of the exact
    fingerprint (`confirmFingerprint`); wrong/stale codes are refused;
  * explicit re-pair (`replaceAfterConflict`) requires acknowledging the
    old fingerprint and restarts the peer as unverified;
  * export/import persists PUBLIC pins only — no private material ever
    enters this store.
- `BoltunSession._processKeyResponse` wires the above into the live
  protocol path (no silent key overwrite anywhere).

### Honest limitations
1. **First-contact MITM is NOT prevented by TOFU alone.** Until the user
   compares fingerprints over an independent channel (QR scan or read
   aloud), the relay can substitute a key and the client cannot tell.
   The API makes "trusted" impossible without that check; UI must render
   the comparison step before any "verified" badge.
2. There is no Ed25519 signing-key layer in the current wire format:
   KEY_RESPONSE authenticity rests on transport TLS + OOB fingerprint.
   A signed-response extension (e.g. Signal-style double-signed identity)
   requires a protocol change and is deliberately NOT claimed here.
3. QR rendering/scanning is UI work — not implemented (no UI in this repo
   yet); `exportJson()` payload is the natural QR content once UI lands.
4. Replay protection for KEY_RESPONSE relies on the existing nonce/msg-id
   correlation in RelayClient.requestPeerKey; a delayed duplicate answer
   for a NEW request is handled by target+nonce binding at the client.
