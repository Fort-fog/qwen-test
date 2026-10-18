/// BOLTUN E2E envelope — Dart port of `server/internal/e2e/e2e.go`.
///
/// Protocol "boltun-e2e-v1" (see docs/protocol/e2e-v1.md). This file must
/// stay byte-compatible with the Go implementation; do not change formats.
library;

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:cryptography/dart.dart';

class E2eException implements Exception {
  final String message;
  E2eException(this.message);
  @override
  String toString() => 'E2eException: $message';
}

const int _envelopeVersion = 0x00;
const int _ephPubLen = 32;
const int _nonceLen = 12;
const int _tagLen = 16;
const int _minEnvelopeLen = 1 + _ephPubLen + _nonceLen + _tagLen;

final Random _rng = Random.secure();

String _hex(List<int> b) =>
    b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();

Uint8List _unhex(String h) {
  final out = Uint8List(h.length ~/ 2);
  for (var i = 0; i < out.length; i++) {
    out[i] = int.parse(h.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return out;
}

Uint8List _randomBytes(int n) {
  final b = Uint8List(n);
  for (var i = 0; i < n; i++) {
    b[i] = _rng.nextInt(256);
  }
  return b;
}

final X25519 _x25519 = DartX25519();

/// Long-lived X25519 device identity key pair. Private bytes never leave
/// the device; only [publicBytes] is ever transmitted.
class IdentityKeyPair {
  final Uint8List privateBytes; // 32B raw seed
  final Uint8List publicBytes; // 32B X25519 public key
  IdentityKeyPair(this.privateBytes, this.publicBytes) {
    if (privateBytes.length != 32 || publicBytes.length != 32) {
      throw E2eException('key material must be 32 bytes');
    }
  }

  static Future<IdentityKeyPair> generate() => fromPrivate(_randomBytes(32));

  static Future<IdentityKeyPair> fromPrivate(Uint8List priv) async {
    if (priv.length != 32) {
      throw E2eException('e2e: private key must be 32 bytes');
    }
    final kp = await _x25519.newKeyPairFromSeed(priv);
    return IdentityKeyPair(
      Uint8List.fromList(priv),
      Uint8List.fromList((await kp.extractPublicKey()).bytes),
    );
  }

  static Future<IdentityKeyPair> fromPrivateHex(String hex) =>
      fromPrivate(_unhex(hex));

  /// SECURITY: the default Object.toString() would print the field list and
  /// could leak `privateBytes` into crash logs / debug output. Override it so
  /// only public material is ever rendered.
  @override
  String toString() => 'IdentityKeyPair(publicOnly)';
}

Future<Uint8List> _ecdh(Uint8List priv, Uint8List pub) async {
  final kp = await _x25519.newKeyPairFromSeed(priv);
  final secret = await _x25519.sharedSecretKey(
    keyPair: kp,
    remotePublicKey: SimplePublicKey(pub, type: KeyPairType.x25519),
  );
  return Uint8List.fromList(await secret.extractBytes());
}

/// Canonical KDF shared by Seal and Open (mirrors Go deriveKey):
///   HKDF-SHA256(ikm = X25519 shared secret,
///               salt = ephemeral pub (32B),
///               info = "boltun-e2e-v1|<hex sender>|<hex recip>|<msg id>",
///               L = 32)
Future<Uint8List> deriveKey(
  Uint8List sharedSecret,
  Uint8List ephemPub,
  Uint8List senderPub,
  Uint8List recipientPub,
  String msgId,
) async {
  final info = utf8.encode(
    'boltun-e2e-v1|${_hex(senderPub)}|${_hex(recipientPub)}|$msgId',
  );
  final hkdf = DartHkdf(hmac: Hmac.sha256(), outputLength: 32);
  final out = await hkdf.deriveKey(
    secretKey: SecretKey(sharedSecret),
    nonce: ephemPub, // library uses `nonce` as the RFC 5869 salt
    info: info,
  );
  return Uint8List.fromList(await out.extractBytes());
}

Uint8List aadBytes(Uint8List senderPub, Uint8List recipientPub, String msgId) =>
    Uint8List.fromList(
      utf8.encode(
        'boltun-aad-v1|${_hex(senderPub)}|${_hex(recipientPub)}|$msgId',
      ),
    );

/// Encrypts [plaintext] for [recipientPub] on behalf of [sender].
/// Returns raw envelope: `[1B ver=0][32B eph pub][12B nonce][ct||16B tag]`.
///
/// Optional [ephPriv]/[nonce] allow deterministic runs for cross-language
/// test vectors; production calls omit them (fresh CSPRNG values).
Future<Uint8List> seal(
  IdentityKeyPair sender,
  Uint8List recipientPub,
  String msgId,
  Uint8List plaintext, {
  Uint8List? ephPriv,
  Uint8List? nonce,
}) async {
  if (recipientPub.length != 32) {
    throw E2eException('recipient pub must be 32 bytes');
  }
  final useEphPriv = ephPriv ?? _randomBytes(32);
  final ephKp = await _x25519.newKeyPairFromSeed(useEphPriv);
  final ephPub = Uint8List.fromList((await ephKp.extractPublicKey()).bytes);
  final shared = await _ecdh(useEphPriv, recipientPub);
  final key = await deriveKey(
    shared,
    ephPub,
    sender.publicBytes,
    recipientPub,
    msgId,
  );
  final useNonce = nonce ?? _randomBytes(_nonceLen);
  if (useNonce.length != _nonceLen) {
    throw E2eException('nonce must be 12 bytes');
  }
  final box = await AesGcm.with256bits().encrypt(
    plaintext,
    secretKey: SecretKey(key),
    nonce: useNonce,
    aad: aadBytes(sender.publicBytes, recipientPub, msgId),
  );
  final ctTag = Uint8List.fromList(box.cipherText + box.mac.bytes);
  final env = Uint8List(1 + _ephPubLen + _nonceLen + ctTag.length);
  env[0] = _envelopeVersion;
  env.setRange(1, 1 + _ephPubLen, ephPub);
  env.setRange(1 + _ephPubLen, 1 + _ephPubLen + _nonceLen, useNonce);
  env.setRange(1 + _ephPubLen + _nonceLen, env.length, ctTag);
  return env;
}

/// Decrypts an envelope produced by [seal]. Throws [E2eException] on short
/// or version-mismatched envelopes and on authentication-tag failure
/// (wrong key, tampered ciphertext/tag, or AAD-bound field mismatch).
Future<Uint8List> open(
  IdentityKeyPair recipient,
  Uint8List envelope,
  String msgId,
  Uint8List senderPub,
) async {
  if (envelope.length < _minEnvelopeLen) {
    throw E2eException('e2e: envelope too short');
  }
  if (envelope[0] != _envelopeVersion) {
    throw E2eException('e2e: unsupported envelope version');
  }
  if (senderPub.length != 32) {
    throw E2eException('sender pub must be 32 bytes');
  }
  final ephPub = Uint8List.sublistView(envelope, 1, 1 + _ephPubLen);
  final nonce = Uint8List.sublistView(
    envelope,
    1 + _ephPubLen,
    1 + _ephPubLen + _nonceLen,
  );
  final ctTag = Uint8List.sublistView(envelope, 1 + _ephPubLen + _nonceLen);
  if (ctTag.length < _tagLen) {
    throw E2eException('e2e: envelope too short');
  }
  final shared = await _ecdh(recipient.privateBytes, ephPub);
  final key = await deriveKey(
    shared,
    ephPub,
    senderPub,
    recipient.publicBytes,
    msgId,
  );
  try {
    final clear = await (AesGcm.with256bits() as DartAesGcm).decrypt(
      SecretBox(
        ctTag.sublist(0, ctTag.length - _tagLen),
        nonce: nonce,
        mac: Mac(ctTag.sublist(ctTag.length - _tagLen)),
      ),
      secretKey: SecretKey(key),
      aad: aadBytes(senderPub, recipient.publicBytes, msgId),
    );
    return Uint8List.fromList(clear);
  } catch (_) {
    throw E2eException('e2e: authentication tag check failed');
  }
}

String encodeEnvelope(Uint8List env) => base64.encode(env);
Uint8List decodeEnvelope(String s) => Uint8List.fromList(base64.decode(s));

/// Test-only helper: raw ECDH from private seed to remote public key.
Future<Uint8List> deriveSharedForTest(Uint8List priv, Uint8List pub) =>
    _ecdh(priv, pub);
