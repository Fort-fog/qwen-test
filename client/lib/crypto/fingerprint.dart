import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

/// Short-authenticatable fingerprints of E2E identity keys.
///
/// A fingerprint is a human/QR-comparable commitment to a peer's X25519
/// identity public key, used for out-of-band verification during first
/// pairing (compare codes over an independent channel, or scan a QR).
///
/// Construction (verified primitive: SHA-256 from `cryptography`, no
/// hand-rolled hashing):
///   digest = SHA-256(utf8("boltun-fp-v1|" + base64std(identity_pub)))
///   fp     = first 6 hex chars of the digest, grouped "XXX-XXX"
///            (~2^24 space — deliberately short like Signal safety numbers'
///            visual check; full cryptographic binding lives in the
///            envelope AAD and PeerTrustStore pinning, not in the code).
class KeyFingerprint {
  static const String prefix = 'boltun-fp-v1|';

  /// Computes the display fingerprint from a raw 32-byte identity pub.
  static Future<String> fromPublicKey(Uint8List pub) async {
    if (pub.length != 32) {
      throw ArgumentError('identity public key must be 32 bytes');
    }
    final hash = await Sha256().hash(
      utf8.encode('$prefix${base64Encode(pub)}'),
    );
    return format(hash.bytes);
  }

  /// Same result from the base64(std) wire representation.
  static Future<String> fromBase64(String b64) =>
      fromPublicKey(base64Decode(b64.trim()));

  /// Deterministic sync variant over an already-computed digest
  /// (used by tests and by callers that hold the SHA-256 bytes).
  static String format(List<int> digest) {
    final hex = digest
        .take(3)
        .map((b) => b.toRadixString(16).padLeft(2, '0'))
        .join()
        .toUpperCase();
    return '${hex.substring(0, 3)}-${hex.substring(3)}';
  }
}
