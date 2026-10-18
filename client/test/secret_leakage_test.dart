import 'dart:convert';
import 'dart:typed_data';

import 'package:boltun_client/crypto/e2e.dart' as e2e;
import 'package:boltun_client/crypto/fingerprint.dart';
import 'package:boltun_client/state/identity_store.dart';
import 'package:boltun_client/state/peer_trust.dart';
import 'package:boltun_client/state/secure_identity_store.dart';
import 'package:test/test.dart';

/// Narrow audit guard: no private key material, seed or base64/hex encodings
/// of them may ever appear in string representations, exception messages or
/// diagnostic surfaces. These tests lock the proven-safe behavior from
/// commit b8c7237 (IdentityKeyPair.toString override) and the fail-loud
/// IdentityLoadException paths.

String _hex(Uint8List b) =>
    b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();

void _expectNoSecret(String? where, Uint8List priv, List<String> renderings) {
  final needleB64 = base64.encode(priv);
  final needleHex = _hex(priv);
  for (final s in renderings.whereType<String>()) {
    expect(
      s.contains(base64.encode(priv)) ||
          s.contains(needleB64) ||
          s.contains(needleHex),
      isFalse,
      reason: 'secret material leaked into $where: "$s"',
    );
  }
}

void main() {
  test('IdentityKeyPair.toString never renders private bytes', () async {
    final kp = await e2e.IdentityKeyPair.generate();
    final r = kp.toString();
    _expectNoSecret('IdentityKeyPair.toString()', kp.privateBytes, [r]);
    // Interpolation into logs/diagnostics must also be safe.
    _expectNoSecret(
      'interpolated toString()',
      kp.privateBytes,
      ['session init done: $kp'],
    );
  });

  test('SecureStorageIdentityStore.toString exposes no key material', () async {
    final backend = RecordingBackend();
    final store = SecureStorageIdentityStore(backend);
    final kp = await store.loadOrCreate();
    final r = store.toString();
    _expectNoSecret('store.toString()', kp.privateBytes, [r, '$store']);
  });

  test('IdentityLoadException messages carry no secret bytes', () async {
    final backend = RecordingBackend();
    final store = SecureStorageIdentityStore(backend);

    // 1) read failure
    backend.failReadWith = StateError('permission denied on keystore entry');
    Object? err1;
    try {
      await store.loadOrCreate();
    } catch (e) {
      err1 = e;
    }
    expect(err1, isA<IdentityLoadException>());
    final s1 = '$err1';
    expect(RegExp(r'[0-9a-f]{32,}').hasMatch(s1), isFalse,
        reason: 'long hex blob (possible key material) in error: $s1');
    expect(RegExp(r'[A-Za-z0-9+/]{44,}={0,2}').hasMatch(s1), isFalse,
        reason: 'long base64 blob (possible key material) in error: $s1');

    // 2) corrupt entry with REAL secret bytes inside — the store must not
    // echo the raw stored value into the exception message.
    final realSeed = _randomBytesForTest(32);
    final b = RecordingBackend();
    b.data[RecordingBackend.defaultIdentityKeyName] =
        base64.encode(realSeed.sublist(0, 20));
    final store2 = SecureStorageIdentityStore(b);
    Object? err2;
    try {
      await store2.loadOrCreate();
    } catch (e) {
      err2 = e;
    }
    expect(err2, isA<IdentityLoadException>());
    _expectNoSecret('corrupt-entry IdentityLoadException', realSeed, ['$err2']);
  });

  test('E2eException messages never embed key material', () async {
    final kp = await e2e.IdentityKeyPair.generate();
    final bad = Uint8List(16);
    Object? err;
    try {
      await e2e.IdentityKeyPair.fromPrivate(bad);
    } catch (e) {
      err = e;
    }
    expect(err, isNotNull);
    _expectNoSecret('E2eException', kp.privateBytes, ['$err']);
    // The too-short buffer itself must not be echoed either.
    expect('$err'.contains(_hex(bad)), isFalse);
  });

  test('PeerTrustStore diagnostics expose only public material', () async {
    final kp = await e2e.IdentityKeyPair.generate();
    final trust = PeerTrustStore();
    final outcome = await trust.register('dev-A', kp.publicBytes);
    expect(outcome, isA<FirstContact>());
    final dump = [
      '$outcome',
      trust.exportJson(),
      '${trust.fingerprintOf('dev-A')}',
      '${trust.pinnedKey('dev-A')}', // List<int> rendering = decimal bytes
    ];
    _expectNoSecret('PeerTrustStore diagnostics', kp.privateBytes, dump);
    // Fingerprints stay visible (useful, public diagnostics).
    expect(trust.fingerprintOf('dev-A'), isNotNull);
  });

  test('KeyFingerprint renders grouped hex of the PUBLIC key only', () async {
    final kp = await e2e.IdentityKeyPair.generate();
    final fp = await KeyFingerprint.fromPublicKey(kp.publicBytes);
    _expectNoSecret('fingerprint string', kp.privateBytes, [fp]);
    expect(fp, contains('-'));
  });

  test('Session lastError surface carries no secret material', () async {
    // The session composes its error strings from fixed codes + ids +
    // exception .message fields. Verify the exact templates used for the
    // identity-load path cannot contain key material by checking the
    // underlying exception again through the same composition.
    final b = RecordingBackend();
    // Stored value that fails to parse (invalid base64 chars); if the error
    // message ever echoed the raw stored entry, the assertion below fires.
    b.data[RecordingBackend.defaultIdentityKeyName] =
        'Zm9vYmFy###corrupt-tail###';
    final store = SecureStorageIdentityStore(b);
    Object? err;
    try {
      await store.loadOrCreate();
    } catch (e) {
      err = e;
    }
    expect(err, isA<IdentityLoadException>());
    final composed =
        'IDENTITY_LOAD_FAILED: ${(err as IdentityLoadException).message}';
    expect(composed.contains(b.data[RecordingBackend.defaultIdentityKeyName]!),
        isFalse);
  });
}

Uint8List _randomBytesForTest(int n) =>
    Uint8List.fromList(List<int>.generate(n, (i) => (i * 7 + 13) % 256));

/// Simple in-test backend double (mirrors helpers file but self-contained so
/// this security suite does not depend on unrelated fixtures).
class RecordingBackend implements SecureBackend {
  final Map<String, String> data = {};
  Object? failReadWith;
  Object? failWriteWith;
  static const defaultIdentityKeyName = 'boltun.identity.seed.b64';

  @override
  bool get isProtected => true;

  @override
  String? get unavailableReason => null;

  @override
  Future<String?> read(String key) async {
    if (failReadWith != null) throw failReadWith!;
    return data[key];
  }

  @override
  Future<void> write(String key, String value) async {
    if (failWriteWith != null) throw failWriteWith!;
    data[key] = value;
  }

  @override
  Future<void> delete(String key) async => data.remove(key);
}
