/// Production [SecureBackend] on top of `flutter_secure_storage` (9.x).
///
/// Storage is delegated exclusively to the platform's native secret store:
///  * Android — EncryptedSharedPreferences backed by the Android Keystore
///    (hardware/TEE-backed only where the device supports it — we do NOT
///    claim guaranteed hardware protection);
///  * iOS/macOS — Keychain (`ThisDeviceOnly` accessibility by default);
///  * Linux — Secret Service API (GNOME Keyring / KWallet via libsecret);
///    protection quality depends on the user's keyring configuration;
///  * Windows — Credential Manager (per-user DPAPI).
/// SharedPreferences, plain JSON files and logs are never used for the seed.
///
/// Error policy (matches SecureStorageIdentityStore fail-loud contract):
///  * read errors PROPAGATE as exceptions — the identity store turns them
///    into IdentityLoadException and NEVER deletes/regenerates silently;
///  * write/delete errors propagate so persistence failures are visible;
///  * "plugin not available" (MissingPluginException / unsupported platform)
///    is reported through [unavailableReason]; reads then return null and
///    writes throw — nothing is persisted anywhere weaker.
library;

import 'package:flutter/services.dart';

import 'secure_identity_store.dart';

/// Thin, testable adapter over the plugin's MethodChannel.
///
/// We talk to `com.itfeather/flutter_secure_storage` directly instead of the
/// plugin's Dart class so this file stays unit-testable with a mocked binary
/// messenger and so behavior does not drift across plugin minor versions.
/// The channel protocol below matches flutter_secure_storage_platform_interface
/// ^1.1.x (bundled with flutter_secure_storage 9.x).
class FlutterSecureBackend implements SecureBackend {
  FlutterSecureBackend({
    MethodChannel? channel,
    this.biometricUnlock = false,
    this.accountName = 'boltun',
    this.serviceName = 'boltun.identity',
    this.persistWhileLocked = true,
    String Function(Object error)? unavailableClassifier,
  }) : _channel = channel ?? const MethodChannel(_channelName),
       // Classifier may return null to mean "not an unavailability signal"
       // (e.g. a genuine I/O error) — the nullable type is intentional.
       _classify = unavailableClassifier ?? _defaultUnavailableClassifier;

  static const _channelName = 'com.itfeather/flutter_secure_storage';

  final MethodChannel _channel;

  /// Returns a non-null human-readable reason when [error] means "secure
  /// storage is unavailable"; null for genuine I/O errors (those propagate).
  final String? Function(Object error) _classify;

  /// Android-only hint: require device credential/biometric per entry.
  final bool biometricUnlock;
  final String accountName;
  final String serviceName;
  final bool persistWhileLocked;

  String? _unavailableReason;
  bool _probed = false;

  @override
  bool get isProtected => _probed && _unavailableReason == null;

  @override
  String? get unavailableReason => _unavailableReason;

  Map<String, Object> get _options => <String, Object>{
    'persistent': persistWhileLocked,
    // iOS/macOS: keep material in the Keychain, not in iCloud backup.
    'kSecAttrAccessible': 'kSecAttrAccessibleWhenUnlockedThisDeviceOnly',
    'accountName': accountName,
    'serviceName': serviceName,
    'synchronizable': false,
    if (biometricUnlock) 'biometricOnly': true,
  };

  Future<void> _invoke(String method, [Map<String, Object>? args]) async {
    try {
      await _channel.invokeMethod<void>(method, <String, Object>{
        ..._options,
        ...?args,
      });
    } on MissingPluginException catch (e) {
      _markUnavailable(e);
      rethrow;
    } on PlatformException catch (e) {
      if (_isUnavailableSignal(e)) _markUnavailable(e);
      rethrow;
    }
  }

  bool _isUnavailableSignal(PlatformException e) => _classify(e) != null;

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
      final value = await _channel.invokeMethod<String>(
        'read',
        <String, Object>{'key': key, ..._options},
      );
      _probed = true;
      if (_unavailableReason == null) _unavailableReason = null;
      return value;
    } on MissingPluginException catch (e) {
      // No plugin at all: treat as unavailable storage (not a corrupt entry).
      // read() returning null means "no entry", which is safe ONLY because
      // isProtected becomes false and the store keeps the key in memory.
      _markUnavailable(e);
      return null;
    } on PlatformException catch (e) {
      if (_isUnavailableSignal(e)) {
        _markUnavailable(e);
        return null;
      }
      rethrow; // genuine keystore I/O error -> loud failure upstream
    }
  }

  @override
  Future<void> write(String key, String value) =>
      _invoke('write', <String, Object>{'key': key, 'value': value});

  @override
  Future<void> delete(String key) =>
      _invoke('delete', <String, Object>{'key': key});

  /// Explicit reset path: wipe the entry from the system store.
  Future<void> clearAll() async {
    try {
      await _channel.invokeMethod<void>('deleteAll', <String, Object>{
        ..._options,
      });
      _probed = true;
    } on MissingPluginException catch (e) {
      _markUnavailable(e);
    } on PlatformException catch (e) {
      if (_isUnavailableSignal(e)) {
        _markUnavailable(e);
        return;
      }
      rethrow;
    }
  }
}
