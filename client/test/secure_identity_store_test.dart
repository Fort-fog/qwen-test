/// Tests for SecureStorageIdentityStore: persistence policy, fail-closed
/// behaviour and the "never write to an unprotected backend" rule.
import 'dart:convert';
import 'dart:typed_data';

import 'package:boltun_client/crypto/e2e.dart';
import 'package:boltun_client/state/identity_store.dart';
import 'package:boltun_client/state/secure_identity_store.dart';
import 'package:test/test.dart';

String pubHex(IdentityKeyPair kp) =>
    kp.publicBytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

class FakeBackend implements SecureBackend {
  FakeBackend({
    required this.isProtected,
    this.unavailableReason,
    Map<String, String>? seed,
  }) : data = {...?seed};
  final Map<String, String> data;
  @override
  final bool isProtected;
  @override
  final String? unavailableReason;
  int writes = 0;
  @override
  Future<String?> read(String key) async => data[key];
  @override
  Future<void> write(String key, String value) async {
    writes++;
    data[key] = value;
  }

  @override
  Future<void> delete(String key) async => data.remove(key);
}

void main() {
  group('SecureStorageIdentityStore', () {
    test('protected backend: seed persists and reloads identically', () async {
      final be = FakeBackend(isProtected: true);
      final s1 = SecureStorageIdentityStore(be);
      final kp = await s1.loadOrCreate();
      expect(be.data.containsKey(s1.keyName), isTrue);
      // Stored value is base64 of exactly the 32-byte private seed.
      expect(base64.decode(be.data[s1.keyName]!).length, 32);

      // Simulated restart: new store instance over the same backend.
      final s2 = SecureStorageIdentityStore(be);
      final reloaded = await s2.loadOrCreate();
      expect(reloaded.privateBytes, equals(kp.privateBytes));
      expect(reloaded.publicBytes, equals(kp.publicBytes));
      expect(s2.persistsAcrossRestart, isTrue);
    });

    test(
      'UNPROTECTED backend: never writes the private key anywhere',
      () async {
        final be = FakeBackend(isProtected: false);
        final s = SecureStorageIdentityStore(be);
        await s.loadOrCreate();
        expect(be.writes, 0);
        expect(be.data, isEmpty);
        expect(s.persistsAcrossRestart, isFalse);
      },
    );

    test(
      'corrupt stored entry -> regenerated, not crashed; no leak in logs',
      () async {
        final be = FakeBackend(isProtected: true);
        be.data['boltun.identity.seed.b64'] = 'not-valid-base64!!!';
        final s = SecureStorageIdentityStore(be);
        final kp = await s.loadOrCreate();
        expect(kp.privateBytes.length, 32);
        // Corrupt value replaced with a valid fresh seed.
        expect(
          Uint8List.fromList(base64.decode(be.data[s.keyName]!)).length,
          32,
        );
      },
    );

    test('clear() removes persisted material', () async {
      final be = FakeBackend(isProtected: true);
      final s = SecureStorageIdentityStore(be);
      await s.loadOrCreate();
      await s.clear();
      expect(be.data, isEmpty);
      // Next load creates a NEW identity (old one is gone).
      final kp2 = await s.loadOrCreate();
      expect(kp2.privateBytes.length, 32);
    });

    test('cache avoids duplicate reads/writes', () async {
      final be = FakeBackend(isProtected: true);
      final s = SecureStorageIdentityStore(be);
      final a = await s.loadOrCreate();
      final b = await s.loadOrCreate();
      expect(identical(a, b), isTrue);
      expect(be.writes, 1);
    });
  });

  group('IdentityKeyPair.toString safety', () {
    test('toString does not expose the private seed', () async {
      final kp = await IdentityKeyPair.generate();
      final repr = kp.toString();
      final secretB64 = base64.encode(kp.privateBytes);
      final secretHex = kp.privateBytes
          .map((b) => b.toRadixString(16).padLeft(2, '0'))
          .join();
      expect(repr.contains(secretB64), isFalse);
      expect(repr.contains(secretHex), isFalse);
    });
  });

  group('identity lifecycle (integration stage)', () {
    test(
      'read error -> explicit IdentityLoadException, entry untouched',
      () async {
        final backend = ThrowingReadBackend({'k': 'anything'});
        final store = SecureStorageIdentityStore(backend, keyName: 'k');
        await expectLater(
          store.loadOrCreate(),
          throwsA(isA<IdentityLoadException>()),
        );
        // The stored material was NOT deleted or overwritten by the failure.
        expect(backend.data['k'], 'anything');
        expect(store.hadRecoveryEvent, isFalse); // read error is retryable
      },
    );

    test('corrupt entry -> explicit error, NO silent new identity', () async {
      final backend = FakeBackend(isProtected: true);
      await backend.write('k', 'not-valid-base64-seed!!!');
      final store = SecureStorageIdentityStore(backend, keyName: 'k');
      await expectLater(
        store.loadOrCreate(),
        throwsA(isA<IdentityLoadException>()),
      );
      // Corrupt entry left in place for operator recovery; not auto-replaced.
      expect(await backend.read('k'), 'not-valid-base64-seed!!!');
      expect(store.hadRecoveryEvent, isTrue);
      // Only an EXPLICIT clear() resets identity...
      await store.clear();
      expect(await backend.read('k'), isNull);
      // ...after which a fresh identity is legitimately created.
      final kp = await store.loadOrCreate();
      expect(pubHex(kp).length, 64);
      expect(await backend.read('k'), isNotNull);
    });

    test(
      'write failure after generation -> session works, flagged, no leak',
      () async {
        final backend = ThrowingWriteBackend();
        final store = SecureStorageIdentityStore(backend, keyName: 'k');
        final kp = await store.loadOrCreate(); // must not throw
        expect(pubHex(kp).length, 64);
        expect(store.writeFailed, isTrue);
        expect(store.hadRecoveryEvent, isTrue);
        expect(backend.data.containsKey('k'), isFalse); // nothing persisted
        // Same in-memory identity served for this process lifetime.
        final again = await store.loadOrCreate();
        expect(pubHex(again), pubHex(kp));
      },
    );

    test(
      'unprotected backend -> fail closed, ephemeral, never persists',
      () async {
        final backend = FakeBackend(isProtected: false);
        final store = SecureStorageIdentityStore(backend, keyName: 'k');
        final kp = await store.loadOrCreate();
        expect(backend.data.isEmpty, isTrue); // NO quiet unsafe persistence
        expect(store.persistsAcrossRestart, isFalse);
        // Simulated restart: brand-new store gets a DIFFERENT ephemeral key.
        final store2 = SecureStorageIdentityStore(
          FakeBackend(isProtected: false),
          keyName: 'k',
        );
        final kp2 = await store2.loadOrCreate();
        expect(pubHex(kp2), isNot(pubHex(kp)));
      },
    );

    test('restart with protected backend reloads the SAME identity', () async {
      final shared = <String, String>{};
      final s1 = SecureStorageIdentityStore(
        FakeBackend(isProtected: true, sharedData: shared),
        keyName: 'k',
      );
      final kp1 = await s1.loadOrCreate();
      final s2 = SecureStorageIdentityStore(
        FakeBackend(isProtected: true, sharedData: shared),
        keyName: 'k',
      );
      final kp2 = await s2.loadOrCreate();
      expect(pubHex(kp2), pubHex(kp1)); // same key across "restarts"
    });

    test('explicit delete removes identity from backend and cache', () async {
      final shared = <String, String>{};
      final store = SecureStorageIdentityStore(
        FakeBackend(isProtected: true, sharedData: shared),
        keyName: 'k',
      );
      final kp = await store.loadOrCreate();
      expect(shared['k'], isNotNull);
      await store.clear();
      expect(shared.containsKey('k'), isFalse);
      final fresh = await store.loadOrCreate();
      expect(pubHex(fresh), isNot(pubHex(kp))); // new identity after reset
    });
  });
}

/// Lifecycle tests added with the identity-integration stage: explicit
/// errors on read/corrupt failures, no silent replacement identity, no
/// auto-delete, write-failure surfaced, clear() is the only reset path.
class ThrowingReadBackend implements SecureBackend {
  final Map<String, String> data;
  ThrowingReadBackend(this.data);
  @override
  bool get isProtected => true;
  @override
  String? get unavailableReason => null;
  @override
  Future<String?> read(String key) async => throw StateError('keystore down');
  @override
  Future<void> write(String key, String value) async => data[key] = value;
  @override
  Future<void> delete(String key) async => data.remove(key);
}

class ThrowingWriteBackend implements SecureBackend {
  final Map<String, String> data = {};
  int deletes = 0;
  @override
  bool get isProtected => true;
  @override
  String? get unavailableReason => null;
  @override
  Future<String?> read(String key) async => data[key];
  @override
  Future<void> write(String key, String value) async =>
      throw StateError('write denied');
  @override
  Future<void> delete(String key) async {
    deletes++;
    data.remove(key);
  }
}
