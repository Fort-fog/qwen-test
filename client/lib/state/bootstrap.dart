/// Single production composition point for device identity.
///
/// This is the ONLY place that decides which IdentityStore a real session
/// uses, so there is exactly one source of identity. The Flutter entry
/// point (when UI lands) must call [createProductionIdentityStore] and pass
/// the result into SessionConfig.identityStore — it must NOT construct an
/// InMemoryIdentityStore or any plain-storage store for private keys.
///
/// Policy (fail-closed, mirrors SecureStorageIdentityStore):
///  * A platform backend that honestly reports `isProtected == true` gets
///    persistent storage through the system secret store. This does NOT
///    claim guaranteed hardware protection — quality depends on the
///    device/keystore configuration; see docs/SECURITY.md.
///  * An unavailable or unprotected backend NEVER falls back to weaker
///    persistence: the seed stays in memory only (fresh identity per
///    launch) and [IdentityBootstrapResult.warning] must be surfaced.
library;

import '../crypto/e2e.dart';

import 'identity_store.dart';
import 'secure_identity_store.dart';

/// Builds the production [IdentityStore] over a platform [SecureBackend].
/// Pure-Dart (no Flutter imports) so it is covered by the standalone test
/// suite; the Flutter adapter (FlutterSecureBackend) is injected by the
/// app entry point.
SecureStorageIdentityStore createProductionIdentityStore(SecureBackend be) {
  return SecureStorageIdentityStore(be);
}

/// Result of identity bootstrap for the session/UI layer.
class IdentityBootstrapResult {
  IdentityBootstrapResult({
    required this.store,
    required this.keyPair,
    this.warning,
  });

  final IdentityStore store;
  final IdentityKeyPair keyPair;

  /// Non-null when the identity will NOT survive a restart (no usable
  /// secure storage). The app must show this instead of pretending the
  /// identity is persistent. Never contains key material.
  final String? warning;

  bool get persistsAcrossRestart => warning == null;
}

/// Load-or-create the device identity with explicit, safe degradation.
///
/// Throws [IdentityLoadException] unchanged when an existing identity is
/// unreadable/corrupt — callers must surface it and MUST NOT retry with a
/// different store or regenerate (peers may have pinned the old key).
Future<IdentityBootstrapResult> bootstrapIdentity(
  SecureBackend backend, {
  IdentityStore? store,
}) async {
  final s = store ?? createProductionIdentityStore(backend);
  // Any load error propagates untouched (fail loud, no silent fallback).
  final kp = await s.loadOrCreate();

  String? warning;
  if (!backend.isProtected) {
    warning = backend.unavailableReason != null
        ? 'Secure storage unavailable (${backend.unavailableReason}); '
            'identity is kept in memory only and changes every launch'
        : 'No protected storage backend configured; identity is kept in '
            'memory only and changes every launch';
  } else if (s is SecureStorageIdentityStore && s.writeFailed) {
    // Backend claims protection but the first persist attempt errored:
    // this process keeps working, however the identity will be lost on
    // restart unless the write succeeds later. Surface explicitly.
    warning = 'Secure storage reported an error while saving the new '
        'identity; it may not survive a restart';
  }
  return IdentityBootstrapResult(store: s, keyPair: kp, warning: warning);
}
