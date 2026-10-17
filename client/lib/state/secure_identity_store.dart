/// Production secure-storage contract for the E2E identity key.
///
/// Design decision (deliberately NOT one mixed architecture):
///  * The ONLY production mechanism is the platform's native secret store,
///    reached through a Flutter plugin:
///      - Android: `flutter_secure_storage` -> EncryptedSharedPreferences
///        backed by Android Keystore (hardware-backed where available);
///      - iOS:     Keychain with kSecAttrAccessibleWhenUnlockedThisDeviceOnly
///        (Secure Enclave protection when the device has one);
///      - Linux:   libsecret / Secret Service API (GNOME Keyring, KWallet) —
///        NOTE: protection quality depends on the user's keyring setup; it is
///        OS-credential storage, NOT guaranteed hardware security;
///      - Windows: CredentialManager target via wincred (DPAPI per-user).
///  * Strongbox/SQLCipher is intentionally NOT used here: it brings its own
///    key-management problem (where to keep the DB passphrase) and overlaps
///    what the system keystore already provides. If we ever need encrypted
///    bulk message storage, that is a separate decision for the MessageStore,
///    not for this single 32-byte seed.
///  * SharedPreferences/files/logs are NEVER acceptable for private keys.
///    `DevSharedPreferencesIdentityStore` remains clearly named Dev-only.
///
/// Fail-closed rule: if no usable secure backend exists at runtime, the app
/// must NOT silently persist the key anywhere weaker. It keeps an ephemeral
/// in-memory identity (fresh key each launch) and shows a warning banner.
library;

import 'dart:convert';
import 'dart:typed_data';

import '../crypto/e2e.dart';
import 'identity_store.dart';

/// Minimal async surface a platform backend must provide. Implemented by a
/// Flutter adapter around `flutter_secure_storage` (Android/iOS/Linux/Windows
/// all supported by that package >= 9.x) — kept abstract so this file stays
/// pure-Dart testable.
abstract class SecureBackend {
  Future<String?> read(String key);
  Future<void> write(String key, String value);
  Future<void> delete(String key);

  /// True only when the backend is known to protect material beyond plain
  /// disk (Keystore/Keychain/libsecret/wincred). A backend that cannot say
  /// "yes" honestly must return false and the store will refuse to persist.
  bool get isProtected;

  /// Human-readable reason why persistence is unavailable (for the banner).
  String? get unavailableReason => null;
}

/// IdentityStore backed by a [SecureBackend]. Never logs or returns the
/// private seed outside [IdentityKeyPair]; stores exactly one base64 string.
class SecureStorageIdentityStore implements IdentityStore {
  SecureStorageIdentityStore(
    this.backend, {
    this.keyName = 'boltun.identity.seed.b64',
  });

  final SecureBackend backend;
  final String keyName;

  IdentityKeyPair? _cached;

  @override
  Future<IdentityKeyPair> loadOrCreate() async {
    final c = _cached;
    if (c != null) return c;
    final stored = await backend.read(keyName);
    if (stored != null && stored.isNotEmpty) {
      try {
        final kp = await IdentityKeyPair.fromPrivate(
          Uint8List.fromList(base64.decode(stored)),
        );
        _cached = kp;
        return kp;
      } catch (_) {
        // Corrupt entry: regenerate below rather than crash. We deliberately
        // do NOT log the value.
      }
    }
    final kp = await IdentityKeyPair.generate(); // CSPRNG inside e2e module
    if (backend.isProtected) {
      await backend.write(keyName, base64.encode(kp.privateBytes));
    }
    // else: fail closed — keep it in memory only, fresh key next launch.
    _cached = kp;
    return kp;
  }

  @override
  Future<void> clear() async {
    await backend.delete(keyName);
    _cached = null;
  }

  /// Whether the identity will survive an app restart. UI uses this to show
  /// the "no secure storage available" warning instead of pretending safety.
  bool get persistsAcrossRestart => backend.isProtected;
}
