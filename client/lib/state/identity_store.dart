/// Abstraction over protected storage for this device's E2E identity key.
///
/// SECURITY LIMITATION (must stay visible until resolved): the current
/// implementation ([InMemoryIdentityStore]) keeps the private key in process
/// memory only and does NOT persist it across restarts. A production app
/// must plug a platform secure-storage backend (flutter_secure_storage:
/// Keychain / Keystore) into [IdentityStore] — do not fall back to plain
/// SharedPreferences or files for private material.
library;

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import '../crypto/e2e.dart';

/// Explicit failure to safely load an existing identity. Thrown by secure
/// stores when the backend errors or the stored entry is corrupt. Callers
/// MUST surface this to the operator — never auto-generate a replacement
/// identity after this error, because peers may have pinned the old key.
class IdentityLoadException implements Exception {
  IdentityLoadException(this.message);
  final String message;
  @override
  String toString() => 'IdentityLoadException: $message';
}

/// Pluggable persistence boundary for the long-lived X25519 identity key.
abstract class IdentityStore {
  /// Returns the device's identity key pair, creating and persisting a new
  /// one when nothing is stored yet.
  /// Throws [IdentityLoadException] when an existing identity cannot be
  /// loaded safely (backend error / corrupt entry) — the stored material is
  /// left untouched in that case.
  Future<IdentityKeyPair> loadOrCreate();

  /// Forget the stored key pair (device reset). The relay-side registration
  /// of the old public key simply goes stale; peers re-fetch via KEY_REQUEST.
  Future<void> clear();
}

final Random _rng = Random.secure();

Uint8List _randomBytes(int n) {
  final b = Uint8List(n);
  for (var i = 0; i < n; i++) {
    b[i] = _rng.nextInt(256);
  }
  return b;
}

/// Test/dev-only store: generates a fresh key pair per process and never
/// writes private material anywhere. Because the identity pub changes on
/// every start, peers must re-resolve it via HELLO + KEY_REQUEST each time.
class InMemoryIdentityStore implements IdentityStore {
  IdentityKeyPair? _cached;

  @override
  Future<IdentityKeyPair> loadOrCreate() async {
    return _cached ??= await IdentityKeyPair.fromPrivate(_randomBytes(32));
  }

  @override
  Future<void> clear() async => _cached = null;
}

/// Optional dev fallback that persists the private seed in SharedPreferences.
///
/// WARNING: SharedPreferences is NOT secure storage (plaintext on disk).
/// This class exists only to keep a stable identity across restarts during
/// development/testing; production builds must use a real keystore-backed
/// IdentityStore instead.
class DevSharedPreferencesIdentityStore implements IdentityStore {
  DevSharedPreferencesIdentityStore(
    this._getPrefs, {
    this.keyName = 'boltun.identity.priv_b64',
  });

  final Future<SharedPreferencesLike> Function() _getPrefs;
  final String keyName;

  @override
  Future<IdentityKeyPair> loadOrCreate() async {
    final p = await _getPrefs();
    final stored = p.getString(keyName);
    if (stored != null && stored.isNotEmpty) {
      try {
        return await IdentityKeyPair.fromPrivate(
          Uint8List.fromList(base64.decode(stored)),
        );
      } catch (_) {
        // Corrupt entry: regenerate rather than crash.
      }
    }
    final kp = await IdentityKeyPair.fromPrivate(_randomBytes(32));
    await p.setString(keyName, base64.encode(kp.privateBytes));
    return kp;
  }

  @override
  Future<void> clear() async {
    final p = await _getPrefs();
    await p.remove(keyName);
  }
}

/// Minimal surface of SharedPreferences we depend on (keeps this file
/// testable without pulling Flutter deps into pure-Dart tests).
abstract class SharedPreferencesLike {
  String? getString(String key);
  Future<bool> setString(String key, String value);
  Future<bool> remove(String key);
}
