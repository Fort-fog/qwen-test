/// Peer trust registry (TOFU + out-of-band fingerprint verification).
///
/// Threat model (see docs/SECURITY.md and docs/protocol/e2e-v1.md §9):
///  * The relay publishes peers' X25519 identity keys via KEY_RESPONSE.
///    A correctly *formed* key proves NOTHING about who owns it — the
///    relay can substitute its own key at first contact (MITM).
///  * Therefore a key learned through the relay is only ever stored here
///    in [PeerTrust.unverified] state. It may be used to seal/open, but
///    callers that need authenticity (pairing UI, "safety number" banner)
///    must check [isVerified].
///  * TOFU: once a peer is pinned (verified OR simply first-seen), an
///    unexpected key change is a hard signal — [register] returns
///    [KeyChangeConflict] and the OLD pin is kept until the user
///    explicitly re-verifies via [confirmFingerprint].
///
/// Storage note: this map holds PUBLIC material only (pub keys +
/// fingerprints). No private key ever enters this class. Persisting the
/// pins across restarts is the platform SecureStorage backend's job;
/// in-memory here keeps the pure-Dart test story intact.
library;

import 'dart:convert';
import 'dart:typed_data';

import '../crypto/fingerprint.dart';

enum PeerTrust { unverified, verified }

/// Outcome of registering a freshly learned peer key.
sealed class TrustOutcome {}

class FirstContact extends TrustOutcome {
  FirstContact(this.fingerprint);
  final String fingerprint; // show out-of-band before trusting
}

class Unchanged extends TrustOutcome {
  Unchanged(this.fingerprint);
  final String fingerprint;
}

/// Peer already pinned with a DIFFERENT key — possible MITM or re-pair.
class KeyChangeConflict extends TrustOutcome {
  KeyChangeConflict({
    required this.oldFingerprint,
    required this.newFingerprint,
  });
  final String oldFingerprint;
  final String newFingerprint;
}

class _Pin {
  _Pin(this.pub, this.fingerprint, this.trust);
  final Uint8List pub;
  final String fingerprint;
  PeerTrust trust;
}

class PeerTrustStore {
  final Map<String, _Pin> _pins = {};

  /// Registers a key learned from the relay for [deviceId].
  /// Never overwrites an existing pin silently.
  Future<TrustOutcome> register(String deviceId, Uint8List pub) async {
    if (pub.length != 32) {
      throw ArgumentError('identity public key must be 32 bytes');
    }
    final fp = await KeyFingerprint.fromPublicKey(pub);
    final existing = _pins[deviceId];
    if (existing == null) {
      _pins[deviceId] = _Pin(Uint8List.fromList(pub), fp, PeerTrust.unverified);
      return FirstContact(fp);
    }
    if (_constantTimeEquals(existing.pub, pub)) {
      return Unchanged(existing.fingerprint);
    }
    // Key changed: keep the old pin, surface the conflict.
    return KeyChangeConflict(
      oldFingerprint: existing.fingerprint,
      newFingerprint: fp,
    );
  }

  /// Out-of-band confirmation: the user compared [observedFingerprint]
  /// (scanned QR / read aloud over an independent channel) with what the
  /// peer displays. Only then is the pin marked verified.
  /// Returns false when there is no such device or the fingerprint does
  /// not match the pinned key (stale/mismatched code -> refuse).
  bool confirmFingerprint(String deviceId, String observedFingerprint) {
    final pin = _pins[deviceId];
    if (pin == null) return false;
    if (pin.fingerprint != observedFingerprint.toUpperCase()) return false;
    pin.trust = PeerTrust.verified;
    return true;
  }

  /// Explicit re-pair after a conflict: replaces the pin, starts UNVERIFIED
  /// again (the user must repeat out-of-band verification).
  Future<String> replaceAfterConflict(
    String deviceId,
    Uint8List pub,
    String acknowledgedOldFp,
  ) async {
    final pin = _pins[deviceId];
    if (pin != null && pin.fingerprint != acknowledgedOldFp.toUpperCase()) {
      throw StateError('conflict acknowledgement does not match the pin');
    }
    if (pub.length != 32) {
      throw ArgumentError('identity public key must be 32 bytes');
    }
    final fp = await KeyFingerprint.fromPublicKey(pub);
    _pins[deviceId] = _Pin(Uint8List.fromList(pub), fp, PeerTrust.unverified);
    return fp;
  }

  bool isVerified(String deviceId) =>
      _pins[deviceId]?.trust == PeerTrust.verified;

  /// Pinned key for [deviceId], or null when unknown.
  Uint8List? pinnedKey(String deviceId) => _pins[deviceId]?.pub;

  String? fingerprintOf(String deviceId) => _pins[deviceId]?.fingerprint;

  /// Fingerprint this device would display for its own identity pub.
  static Future<String> selfFingerprint(Uint8List myPub) =>
      KeyFingerprint.fromPublicKey(myPub);

  /// JSON export/import of pins (public data only) so a real app can
  /// persist them alongside the identity key. Format is versioned.
  String exportJson() => jsonEncode({
    'v': 1,
    'peers': _pins.entries
        .map(
          (e) => {
            'device_id': e.key,
            'identity_pub': base64.encode(e.value.pub),
            'fingerprint': e.value.fingerprint,
            'trust': e.value.trust.name,
          },
        )
        .toList(),
  });

  void importJson(String s) {
    final m = jsonDecode(s) as Map<String, dynamic>;
    if (m['v'] != 1) throw FormatException('unsupported trust export v');
    for (final raw in (m['peers'] as List).cast<Map<String, dynamic>>()) {
      final pub = base64.decode(raw['identity_pub'] as String);
      if (pub.length != 32) continue; // skip corrupt entries, never trust them
      _pins[raw['device_id'] as String] = _Pin(
        Uint8List.fromList(pub),
        raw['fingerprint'] as String,
        raw['trust'] == PeerTrust.verified.name
            ? PeerTrust.verified
            : PeerTrust.unverified,
      );
    }
  }

  static bool _constantTimeEquals(Uint8List a, Uint8List b) {
    if (a.length != b.length) return false;
    var diff = 0;
    for (var i = 0; i < a.length; i++) {
      diff |= a[i] ^ b[i];
    }
    return diff == 0;
  }
}
