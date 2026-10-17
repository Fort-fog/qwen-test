/// Adapter-level tests for FlutterSecureBackend.
///
/// The production path (PluginSecureStorageApi) is exercised against a FAKE
/// SecureStorageApi that throws the exact exceptions flutter_secure_storage's
/// platform interface propagates from its MethodChannel (MissingPluginException
/// when no plugin is registered, PlatformException on native errors). We do
/// NOT emulate Android Keystore / iOS Keychain here — real OS storage behavior
/// must be smoke-tested on devices/emulators via `flutter test`/integration
/// runs; these tests verify the adapter's contract and error policy only.
library;

import 'dart:convert';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:boltun_client/crypto/e2e.dart';
import 'package:boltun_client/state/flutter_secure_backend.dart';
import 'package:boltun_client/state/identity_store.dart';
import 'package:boltun_client/state/secure_identity_store.dart';

String _pubB64(IdentityKeyPair kp) => base64.encode(kp.publicBytes);

class FakeApi implements SecureStorageApi {
  final Map<String, String> store = {};
  Object? failNext; // thrown once by the next call
  bool pluginRegistered = true;
  final List<String> calls = [];

  void _gate() {
    if (!pluginRegistered)
      throw MissingPluginException('no implementation found');
    if (failNext != null) {
      final e = failNext;
      failNext = null;
      throw e!;
    }
  }

  @override
  Future<void> write({required String key, required String value}) async {
    calls.add('write:$key');
    _gate();
    store[key] = value;
  }

  @override
  Future<String?> read({required String key}) async {
    calls.add('read:$key');
    _gate();
    return store[key];
  }

  @override
  Future<void> delete({required String key}) async {
    calls.add('delete:$key');
    _gate();
    store.remove(key);
  }

  @override
  Future<void> deleteAll() async {
    calls.add('deleteAll');
    _gate();
    store.clear();
  }
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  group('FlutterSecureBackend adapter contract', () {
    test('write/read/delete roundtrip through the api seam', () async {
      final api = FakeApi();
      final b = FlutterSecureBackend(api: api);
      await b.write('k1', 'secret-value');
      expect(api.store['k1'], 'secret-value');
      expect(await b.read('k1'), 'secret-value');
      await b.delete('k1');
      expect(await b.read('k1'), isNull);
    });

    test('isProtected only after a successful probe', () async {
      final b = FlutterSecureBackend(api: FakeApi());
      expect(b.isProtected, isFalse); // not probed yet -> refuse to persist
      await b.read('anything');
      expect(b.isProtected, isTrue);
      expect(b.unavailableReason, isNull);
    });

    test(
      'missing plugin -> unavailable reason, read returns null, write throws',
      () async {
        final api = FakeApi()..pluginRegistered = false;
        final b = FlutterSecureBackend(api: api);
        expect(await b.read('k'), isNull);
        expect(b.isProtected, isFalse);
        expect(b.unavailableReason, contains('not registered'));
        await expectLater(
          b.write('k', 'v'),
          throwsA(isA<MissingPluginException>()),
        );
      },
    );

    test(
      'unsupported_platform error marks storage unavailable explicitly',
      () async {
        final api = FakeApi()
          ..failNext = const PlatformException(code: 'unsupported_platform');
        final b = FlutterSecureBackend(api: api);
        expect(await b.read('k'), isNull);
        expect(b.isProtected, isFalse);
        expect(b.unavailableReason, contains('unavailable'));
      },
    );

    test(
      'genuine read I/O error propagates (never looks like empty store)',
      () async {
        final api = FakeApi()
          ..failNext = const PlatformException(code: 'keystore_io_failure');
        final b = FlutterSecureBackend(api: api);
        await expectLater(b.read('k'), throwsA(isA<PlatformException>()));
        expect(b.isProtected, isTrue); // an I/O error is not "no storage"
      },
    );

    test('clearAll wipes entries', () async {
      final api = FakeApi();
      final b = FlutterSecureBackend(api: api);
      await b.write('a', '1');
      await b.write('b', '2');
      await b.clearAll();
      expect(api.store, isEmpty);
    });
  });

  group('adapter + SecureStorageIdentityStore integration', () {
    test('first launch persists seed; reload gets same identity', () async {
      final api = FakeApi();
      final s1 = SecureStorageIdentityStore(FlutterSecureBackend(api: api));
      final kp1 = await s1.loadOrCreate();
      expect(s1.persistsAcrossRestart, isTrue);
      expect(api.store.values.single, isNotEmpty);
      // Regression guard: pair toString never leaks the persisted seed.
      expect(kp1.toString(), isNot(contains(api.store.values.single)));

      final s2 = SecureStorageIdentityStore(FlutterSecureBackend(api: api));
      final kp2 = await s2.loadOrCreate();
      expect(kp2.publicBytes, kp1.publicBytes);
    });

    test(
      'corrupt entry -> IdentityLoadException, entry untouched, no regen',
      () async {
        final api = FakeApi()
          ..store['boltun.identity.seed.b64'] = '!!!not-b64!!!';
        final s = SecureStorageIdentityStore(FlutterSecureBackend(api: api));
        await expectLater(
          s.loadOrCreate(),
          throwsA(isA<IdentityLoadException>()),
        );
        expect(api.store['boltun.identity.seed.b64'], '!!!not-b64!!!');
        expect(api.calls.where((c) => c.startsWith('delete')), isEmpty);
      },
    );

    test(
      'read failure -> IdentityLoadException, stored key preserved',
      () async {
        final api = FakeApi()
          ..store['boltun.identity.seed.b64'] = 'AAAA'
          ..failNext = const PlatformException(code: 'io_error');
        final s = SecureStorageIdentityStore(FlutterSecureBackend(api: api));
        await expectLater(
          s.loadOrCreate(),
          throwsA(isA<IdentityLoadException>()),
        );
        expect(api.store['boltun.identity.seed.b64'], 'AAAA'); // not deleted
      },
    );

    test(
      'unavailable storage keeps identity in memory only (fail-closed)',
      () async {
        final api = FakeApi()..pluginRegistered = false;
        final s = SecureStorageIdentityStore(FlutterSecureBackend(api: api));
        final kp = await s.loadOrCreate(); // works, ephemeral
        expect(_pubB64(kp), isNotEmpty);
        expect(s.persistsAcrossRestart, isFalse);
        expect(api.store, isEmpty); // nothing was written anywhere
      },
    );

    test('explicit clear removes seed from system storage', () async {
      final api = FakeApi();
      final s = SecureStorageIdentityStore(FlutterSecureBackend(api: api));
      await s.loadOrCreate();
      expect(api.store, isNotEmpty);
      await s.clear();
      expect(api.store, isEmpty);
    });
  });
}
