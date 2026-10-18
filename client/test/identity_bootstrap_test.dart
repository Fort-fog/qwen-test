/// Tests for the identity bootstrap composition point (lib/state/bootstrap).
/// Verifies the real lifecycle: first generation -> restart reload, explicit
/// warnings instead of silent unsafe fallbacks, and fail-loud propagation.
import 'package:boltun_client/state/bootstrap.dart';
import 'package:boltun_client/state/identity_store.dart';
import 'package:boltun_client/state/secure_identity_store.dart';
import 'package:test/test.dart';

import 'secure_identity_store_test_helpers.dart';

void main() {
  group('bootstrapIdentity', () {
    test('first launch with protected backend: persists, no warning', () async {
      final be = FakeBackend(isProtected: true);
      final r1 = await bootstrapIdentity(be);
      expect(r1.warning, isNull);
      expect(r1.persistsAcrossRestart, isTrue);
      expect(be.data.containsKey('boltun.identity.seed.b64'), isTrue);

      // Restart over the same storage: SAME identity, still one source.
      final be2 = FakeBackend(isProtected: true, sharedData: be.data);
      final r2 = await bootstrapIdentity(be2);
      expect(r2.keyPair.privateBytes, equals(r1.keyPair.privateBytes));
      expect(r2.keyPair.publicBytes, equals(r1.keyPair.publicBytes));
    });

    test('unprotected backend: in-memory only + explicit warning', () async {
      final be = FakeBackend(isProtected: false);
      final r = await bootstrapIdentity(be);
      expect(be.writes, 0); // nothing persisted anywhere
      expect(be.data, isEmpty);
      expect(r.warning, contains('in memory only'));
      expect(r.persistsAcrossRestart, isFalse);
    });

    test('unavailable backend: reason surfaced, never a silent fallback',
        () async {
      final be =
          FakeBackend(isProtected: false, unavailableReason: 'no keyring');
      final r = await bootstrapIdentity(be);
      expect(r.warning, contains('no keyring'));
      expect(be.data, isEmpty);
    });

    test('write failure on protected backend: flagged warning, no leak',
        () async {
      final be = ThrowingWriteBackend();
      final r = await bootstrapIdentity(
        be,
        store: SecureStorageIdentityStore(be, keyName: 'k'),
      );
      expect(r.keyPair.publicBytes.length, 32);
      expect(r.warning, contains('may not survive a restart'));
      expect(be.data.containsKey('k'), isFalse);
    });

    test('corrupt stored entry: IdentityLoadException propagates untouched',
        () async {
      final be = FakeBackend(isProtected: true);
      await be.write('boltun.identity.seed.b64', 'garbage!!!');
      await expectLater(
        bootstrapIdentity(be),
        throwsA(isA<IdentityLoadException>()),
      );
      // Entry NOT deleted, no replacement generated.
      expect(await be.read('boltun.identity.seed.b64'), 'garbage!!!');
    });

    test('read error: IdentityLoadException propagates, entry untouched',
        () async {
      final be = ThrowingReadBackend({'boltun.identity.seed.b64': 'x'});
      await expectLater(
        bootstrapIdentity(be),
        throwsA(isA<IdentityLoadException>()),
      );
      expect(be.data['boltun.identity.seed.b64'], 'x');
    });

    test('warnings and toString never contain private key material', () async {
      final be = FakeBackend(isProtected: true);
      final r = await bootstrapIdentity(be);
      final seedB64 = be.data['boltun.identity.seed.b64']!;
      final seedHex = r.keyPair.privateBytes
          .map((b) => b.toRadixString(16).padLeft(2, '0'))
          .join();
      final rendered = '${r.warning}${r.store}${r.keyPair}';
      expect(rendered.contains(seedB64), isFalse);
      expect(rendered.contains(seedHex), isFalse);
    });
  });
}
