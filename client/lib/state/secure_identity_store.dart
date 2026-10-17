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

  /// True once a failure occurred that could have destroyed or orphaned an
  /// existing trusted identity (unreadable/corrupt entry, failed write).
  /// UI/session bootstrap must surface this instead of silently continuing:
  /// regenerating a new identity while an old one was trusted by peers
  /// breaks TOFU pins and message history.
  bool get hadRecoveryEvent => _recoveryEvent;
  bool _recoveryEvent = false;

  @override
  Future<IdentityKeyPair> loadOrCreate() async {
    final c = _cached;
    if (c != null) return c;

    final String? stored;
    try {
      stored = await backend.read(keyName);
    } catch (e) {
      // Read error: NEVER delete the stored entry and NEVER silently
      // generate a replacement identity — the old key may still be there.
      throw IdentityLoadException(
        'secure storage read failed (${e.runtimeType}); existing identity was '
        'left untouched, no new identity generated',
      );
    }

    if (stored != null && stored.isNotEmpty) {
      try {
        final kp = await IdentityKeyPair.fromPrivate(
          Uint8List.fromList(base64.decode(stored)),
        );
        _cached = kp;
        return kp;
      } catch (_) {
        // Entry exists but is corrupt/unparseable. We do NOT overwrite it:
        // generating a fresh identity would silently orphan any peer trust
        // pinned to the old key. Fail loudly with an explicit error so the
        // operator can decide (restore backup / explicit reset via clear()).
        _recoveryEvent = true;
        throw IdentityLoadException(
          'stored identity entry is corrupt; refusing to auto-replace it. '
          'Explicit identity reset requires calling clear().',
        );
      }
    }

    // No entry at all -> first launch: generate.
    final kp = await IdentityKeyPair.generate(); // CSPRNG inside e2e module
    if (backend.isProtected) {
      try {
        await backend.write(keyName, base64.encode(kp.privateBytes));
      } catch (e) {
        // Write failed: keep working in-memory for this session, but flag
        // persistence as broken so the app warns the user. The key is NOT
        // duplicated anywhere weaker (no prefs/JSON/logs).
        _recoveryEvent = true;
        _writeFailed = true;
      }
    }
    // else: fail closed — keep it in memory only, fresh key next launch.
    _cached = kp;
    return kp;
  }

  /// True when the last generation could not be persisted even though the
  /// backend claims protection (transient keystore error).
  bool get writeFailed => _writeFailed;
  bool _writeFailed = false;

  @override
  Future<void> clear() async {
    await backend.delete(keyName);
    _cached = null;
  }

  @override
  String toString() =>
      'SecureStorageIdentityStore(persisted: '
      '${backend.isProtected})'; // never expose key material

  /// Whether the identity will survive an app restart. UI uses this to show
  /// the "no secure storage available" warning instead of pretending safety.
  bool get persistsAcrossRestart => backend.isProtected;
}
