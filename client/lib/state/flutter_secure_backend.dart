/// Production [SecureBackend] on top of the OFFICIAL public API of
/// `flutter_secure_storage` (verified against sources of 9.2.4 +
/// flutter_secure_storage_platform_interface 1.1.2).
///
/// The adapter talks to `FlutterSecureStorage` / typed platform `Options`
/// classes only — it does NOT reimplement the plugin's internal MethodChannel
/// protocol (`plugins.it_nomads.com/flutter_secure_storage`). All channel
/// plumbing is owned by the platform interface.
///
/// Storage is delegated exclusively to the platform's native secret store:
///  * Android — EncryptedSharedPreferences backed by the Android Keystore
///    (hardware/TEE-backed only where the device supports it — we do NOT
///    claim guaranteed hardware protection);
///  * iOS/macOS — Keychain with accessibility
///    `unlocked_this_device` (ThisDeviceOnly variant: not synced/migrated);
///  * Linux — Secret Service API (GNOME Keyring / KWallet via libsecret);
///    protection quality depends on the user's keyring configuration;
///  * Windows — Credential Manager (per-user DPAPI).
/// SharedPreferences, plain JSON files and logs are never used for the seed.
///
/// Honesty about options in flutter_secure_storage 9.2.4:
///  * iOS `IOSOptions` exposes groupId / accountName / accessibility /
///    synchronizable ONLY. There is NO `biometricOnly` option in this version
///    (that appeared in later major releases) — so this adapter does not
///    offer biometric enforcement on Apple platforms;
///  * `AndroidOptions.encryptedSharedPreferences=true` selects the
///    Keystore-backed implementation (default false would use a weaker
///    legacy mode — we always enable it);
///  * `LinuxOptions` has no tunables; `WindowsOptions` only exposes
///    `useBackwardCompatibility` (kept default false).
///
/// Error policy (matches SecureStorageIdentityStore fail-loud contract):
///  * read errors PROPAGATE as exceptions — the identity store turns them
///    into IdentityLoadException and NEVER deletes/regenerates silently;
///  * write/delete errors propagate so persistence failures are visible;
///  * "storage unavailable" (MissingPluginException / unsupported platform)
///    is reported through [unavailableReason]; reads then return null and
///    writes throw — nothing is persisted anywhere weaker.
library;

import 'package:flutter/services.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

import 'secure_identity_store.dart';

/// Testable seam over the official plugin API. In production code simply
/// construct with no arguments; unit tests inject a fake implementing the
/// same public surface (the plugin's own Dart class resolves per-platform
/// options internally, so this thin wrapper is the idiomatic mock boundary).
abstract interface class SecureStorageApi {
  Future<void> write({required String key, required String value});
  Future<String?> read({required String key});
  Future<void> delete({required String key});
  Future<void> deleteAll();
}

/// Default implementation: delegates to `FlutterSecureStorage` with fixed,
/// audited per-platform options.
class PluginSecureStorageApi implements SecureStorageApi {
  PluginSecureStorageApi({FlutterSecureStorage? storage})
    : _storage =
          storage ??
          const FlutterSecureStorage(
            // Android: Keystore-encrypted SharedPreferences. resetOnError
            // must stay FALSE: auto-reset would silently destroy the
            // identity (loss of trusted pairings) — forbidden by policy.
            aOptions: AndroidOptions(encryptedSharedPreferences: true),
            // iOS/macOS: ThisDeviceOnly accessibility, no iCloud sync.
            iOptions: IOSOptions(
              accessibility: KeychainAccessibility.unlocked_this_device,
              synchronizable: false,
            ),
            mOptions: MacOsOptions(
              accessibility: KeychainAccessibility.unlocked_this_device,
              synchronizable: false,
            ),
            // Linux/Windows: defaults (Secret Service / Credential Manager).
            lOptions: LinuxOptions(),
            wOptions: WindowsOptions(),
          );

  final FlutterSecureStorage _storage;

  @override
  Future<void> write({required String key, required String value}) =>
      _storage.write(key: key, value: value);

  @override
  Future<String?> read({required String key}) => _storage.read(key: key);

  @override
  Future<void> delete({required String key}) => _storage.delete(key: key);

  @override
  Future<void> deleteAll() => _storage.deleteAll();
}

/// Adapter exposing the plugin as our [SecureBackend] contract.
class FlutterSecureBackend implements SecureBackend {
  FlutterSecureBackend({
    SecureStorageApi? api,
    String Function(Object error)? unavailableClassifier,
  }) : _api = api ?? PluginSecureStorageApi(),
       _classify = unavailableClassifier ?? _defaultUnavailableClassifier;

  final SecureStorageApi _api;

  /// Returns a non-null reason when [error] means "secure storage is
  /// unavailable"; null for genuine I/O errors (those propagate loudly).
  final String? Function(Object error) _classify;

  String? _unavailableReason;
  bool _probed = false;

  /// True only after a successful round-trip probe. NOTE: this confirms the
  /// system keystore/keyring was reachable — it is NOT proof of hardware
  /// (TEE/Secure Enclave) protection, which depends on the device.
  @override
  bool get isProtected => _probed && _unavailableReason == null;

  @override
  String? get unavailableReason => _unavailableReason;

  void _markUnavailable(Object error) {
    _probed = true;
    _unavailableReason = _classify(error);
  }

  static String? _defaultUnavailableClassifier(Object error) {
    if (error is MissingPluginException) {
      return 'secure storage plugin is not registered on this platform';
    }
    if (error is PlatformException) {
      final code = error.code.toLowerCase();
      const unavailableCodes = {
        'unsupported_platform',
        'no_secret_service',
        'keyring_unavailable',
        'storage_error',
        'keystore_unavailable',
        'api_not_available',
      };
      if (unavailableCodes.contains(code)) {
        return 'system keystore/keyring unavailable (${error.code}: '
            '${error.message ?? ''})';
      }
      return null; // real I/O error -> surface via exception, keep protected
    }
    return null;
  }

  /// Read failure propagates on purpose: SecureStorageIdentityStore converts
  /// it into IdentityLoadException and refuses to regenerate or delete the
  /// existing identity. Returning null here would look like "first launch".
  @override
  Future<String?> read(String key) async {
    try {
      final value = await _api.read(key: key);
      _probed = true;
      return value;
    } on MissingPluginException catch (e) {
      // No plugin at all: treat as unavailable storage (not a corrupt entry).
      // read() returning null means "no entry", which is safe ONLY because
      // isProtected becomes false and the store keeps the key in memory.
      _markUnavailable(e);
      return null;
    } on PlatformException catch (e) {
      if (_classify(e) != null) {
        _markUnavailable(e);
        return null;
      }
      rethrow; // genuine keystore I/O error -> loud failure upstream
    }
  }

  @override
  Future<void> write(String key, String value) async {
    try {
      await _api.write(key: key, value: value);
      _probed = true;
    } on MissingPluginException catch (e) {
      _markUnavailable(e);
      rethrow;
    } on PlatformException catch (e) {
      if (_classify(e) != null) _markUnavailable(e);
      rethrow;
    }
  }

  @override
  Future<void> delete(String key) async {
    try {
      await _api.delete(key: key);
      _probed = true;
    } on MissingPluginException catch (e) {
      _markUnavailable(e);
      rethrow;
    } on PlatformException catch (e) {
      if (_classify(e) != null) _markUnavailable(e);
      rethrow;
    }
  }

  /// Explicit reset path: wipe entries from the system store.
  Future<void> clearAll() async {
    try {
      await _api.deleteAll();
      _probed = true;
    } on MissingPluginException catch (e) {
      _markUnavailable(e);
    } on PlatformException catch (e) {
      if (_classify(e) != null) {
        _markUnavailable(e);
        return;
      }
      rethrow;
    }
  }
}
