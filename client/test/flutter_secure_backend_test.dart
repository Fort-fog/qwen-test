/// Adapter-level tests for FlutterSecureBackend.
///
/// These mock ONLY the plugin MethodChannel boundary (the platform channel),
/// which is exactly what a real device's keystore/keyring sits behind. They
/// do NOT emulate Android Keystore / iOS Keychain themselves — actual OS
/// storage behavior must still be smoke-tested on real devices/emulators via
/// `flutter test` integration or manual runs.
library;

import 'dart:convert';

import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:boltun_client/crypto/e2e.dart';
import 'package:boltun_client/state/flutter_secure_backend.dart';
import 'package:boltun_client/state/identity_store.dart';
import 'package:boltun_client/state/secure_identity_store.dart';

const _channelName = 'com.itfeather/flutter_secure_storage';

String _pubB64(IdentityKeyPair kp) => base64.encode(kp.publicBytes);

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  late Map<String, String?> store; // fake "OS" side of the channel
  late List<PlatformException?> failNext;
  late bool pluginRegistered;

  setUp(() {
    store = <String, String?>{};
    failNext = <PlatformException?>[];
    pluginRegistered = true;
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(const MethodChannel(_channelName), (
          MethodCall call,
        ) async {
          if (!pluginRegistered) {
            throw MissingPluginException('no implementation found');
          }
          if (failNext.isNotEmpty) {
            final forced = failNext.removeAt(0);
            if (forced != null) throw forced;
          }
          final key = call.arguments['key'] as String?;
          switch (call.method) {
            case 'read':
              return store[key];
            case 'write':
              if (key != null) {
                store[key] = call.arguments['value'] as String;
              }
              return null;
            case 'delete':
              store.remove(key);
              return null;
            case 'deleteAll':
              store.clear();
              return null;
          }
          return null;
        });
  });

  tearDown(() {
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(const MethodChannel(_channelName), null);
  });

  group('FlutterSecureBackend channel contract', () {
    test('write/read/delete roundtrip through the system channel', () async {
      final b = FlutterSecureBackend();
      await b.write('k1', 'secret-value');
      expect(store['k1'], 'secret-value'); // reached the OS-side store
      expect(await b.read('k1'), 'secret-value');
      await b.delete('k1');
      expect(await b.read('k1'), isNull);
    });

    test('isProtected only after a successful probe', () async {
      final b = FlutterSecureBackend();
      expect(b.isProtected, isFalse); // not probed yet -> refuse to persist
      await b.read('anything');
      expect(b.isProtected, isTrue);
      expect(b.unavailableReason, isNull);
    });

    test('iOS options pin ThisDeviceOnly and disable sync', () async {
      final calls = <MethodCall>[];
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
          .setMockMethodCallHandler(const MethodChannel(_channelName), (
            call,
          ) async {
            calls.add(call);
            return null;
          });
      final b = FlutterSecureBackend(biometricUnlock: true);
      await b.write('x', 'y');
      final args = calls.single.arguments as Map;
      expect(
        args['kSecAttrAccessible'],
        'kSecAttrAccessibleWhenUnlockedThisDeviceOnly',
      );
      expect(args['synchronizable'], false);
      expect(args['biometricOnly'], true);
    });

    test(
      'missing plugin -> unavailable reason, read returns null, write throws',
      () async {
        pluginRegistered = false;
        final b = FlutterSecureBackend();
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
        failNext.add(PlatformException(code: 'unsupported_platform'));
        final b = FlutterSecureBackend();
        expect(await b.read('k'), isNull);
        expect(b.isProtected, isFalse);
        expect(b.unavailableReason, contains('unavailable'));
      },
    );

    test(
      'genuine read I/O error propagates (never looks like empty store)',
      () async {
        failNext.add(PlatformException(code: 'keystore_io_failure'));
        final b = FlutterSecureBackend();
        await expectLater(b.read('k'), throwsA(isA<PlatformException>()));
        expect(b.isProtected, isTrue); // an I/O error is not "no storage"
      },
    );

    test('clearAll wipes entries', () async {
      final b = FlutterSecureBackend();
      await b.write('a', '1');
      await b.write('b', '2');
      await b.clearAll();
      expect(store, isEmpty);
    });
  });

  group('adapter + SecureStorageIdentityStore integration', () {
    test(
      'first launch persists seed via channel; reload gets same identity',
      () async {
        final b = FlutterSecureBackend();
        final s1 = SecureStorageIdentityStore(b);
        final kp1 = await s1.loadOrCreate();
        expect(s1.persistsAcrossRestart, isTrue);
        expect(store.values.whereType<String>().single, isNotEmpty);
        // The persisted value IS the private seed base64 — assert it never
        // appears in toString of the pair (regression guard).
        expect(kp1.toString(), isNot(contains(store.values.first!)));

        final s2 = SecureStorageIdentityStore(FlutterSecureBackend());
        final kp2 = await s2.loadOrCreate();
        expect(kp2.publicBytes, kp1.publicBytes);
      },
    );

    test(
      'corrupt entry -> IdentityLoadException, entry untouched, no regen',
      () async {
        store['boltun.identity.seed.b64'] = '!!!not-base64-key!!!';
        final s = SecureStorageIdentityStore(FlutterSecureBackend());
        await expectLater(
          s.loadOrCreate(),
          throwsA(isA<IdentityLoadException>()),
        );
        expect(store.containsKey('boltun.identity.seed.b64'), isTrue);
        expect(store['boltun.identity.seed.b64'], '!!!not-base64-key!!!');
      },
    );

    test(
      'read failure -> IdentityLoadException, stored key preserved',
      () async {
        store['boltun.identity.seed.b64'] = 'AAAA';
        failNext.add(PlatformException(code: 'io_error'));
        final s = SecureStorageIdentityStore(FlutterSecureBackend());
        await expectLater(
          s.loadOrCreate(),
          throwsA(isA<IdentityLoadException>()),
        );
        expect(store['boltun.identity.seed.b64'], 'AAAA'); // not deleted
      },
    );

    test(
      'unavailable storage keeps identity in memory only (fail-closed)',
      () async {
        pluginRegistered = false;
        final s = SecureStorageIdentityStore(FlutterSecureBackend());
        final kp = await s.loadOrCreate(); // works, ephemeral
        expect(_pubB64(kp), isNotEmpty);
        expect(s.persistsAcrossRestart, isFalse);
        expect(store, isEmpty); // nothing was written anywhere
        // second "launch" cannot recover the same key -> fresh one, by design
        final s2 = SecureStorageIdentityStore(FlutterSecureBackend());
        final kp2 = await s2.loadOrCreate();
        expect(_pubB64(kp2), isNot(_pubB64(kp)));
      },
    );

    test('explicit clear removes seed from system storage', () async {
      final s = SecureStorageIdentityStore(FlutterSecureBackend());
      await s.loadOrCreate();
      expect(store, isNotEmpty);
      await s.clear();
      expect(store, isEmpty);
    });
  });
}
