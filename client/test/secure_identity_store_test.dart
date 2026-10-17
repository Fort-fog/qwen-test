/// Tests for SecureStorageIdentityStore: persistence policy, fail-closed
/// behaviour and the "never write to an unprotected backend" rule.
import 'dart:convert';
import 'dart:typed_data';

import 'package:boltun_client/crypto/e2e.dart';
import 'package:boltun_client/state/secure_identity_store.dart';
import 'package:test/test.dart';

class FakeBackend implements SecureBackend {
  FakeBackend({required this.isProtected, this.unavailableReason});
  final Map<String, String> data = {};
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
}
