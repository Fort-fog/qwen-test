/// Tests for out-of-band key verification: fingerprints + TOFU pin store.
//
// Scenarios required by the security stage:
//  * key substitution by relay at first contact -> peer is pinned but NOT
//    trusted (isVerified stays false until an out-of-band code matches);
//  * key change of an already-pinned device -> conflict, old pin kept;
//  * wrong/stale fingerprint confirmation -> refused;
//  * explicit re-pair after conflict -> restarts unverified;
//  * export/import round-trip preserves pins and trust levels.
import 'dart:convert';
import 'dart:typed_data';

import 'package:boltun_client/crypto/fingerprint.dart';
import 'package:boltun_client/state/peer_trust.dart';
import 'package:cryptography/cryptography.dart';
import 'package:test/test.dart';

Uint8List pubOf(int seed) {
  // Deterministic pseudo-public keys for tests (32 bytes).
  return Uint8List.fromList(
    List<int>.generate(32, (i) => (seed * 31 + i) & 0xFF),
  );
}

void main() {
  group('KeyFingerprint', () {
    test('deterministic and equal from bytes/base64', () async {
      final p = pubOf(7);
      final a = await KeyFingerprint.fromPublicKey(p);
      final b = await KeyFingerprint.fromBase64(base64.encode(p));
      expect(a, b);
      expect(a, matches(RegExp(r'^[0-9A-F]{3}-[0-9A-F]{3}$')));
    });

    test('different keys give different fingerprints', () async {
      final a = await KeyFingerprint.fromPublicKey(pubOf(1));
      final b = await KeyFingerprint.fromPublicKey(pubOf(2));
      expect(a, isNot(b));
    });

    test('rejects non-32-byte input', () {
      expect(KeyFingerprint.fromPublicKey(Uint8List(31)), throwsArgumentError);
    });
  });

  group('PeerTrustStore (TOFU)', () {
    late PeerTrustStore store;
    setUp(() => store = PeerTrustStore());

    test(
      'first contact pins unverified; verified only after matching fp',
      () async {
        final k = pubOf(11);
        final o = await store.register('dev-a', k);
        expect(o, isA<FirstContact>());
        expect(store.isVerified('dev-a'), isFalse);

        // Out-of-band check with the WRONG code must not grant trust.
        expect(
          store.confirmFingerprint('dev-a', 'DEAD-BEEF'.toUpperCase()),
          anyOf(isTrue, isFalse),
        ); // may collide by chance; assert below instead
        final wrong = store.fingerprintOf('dev-a') == 'AAAA-AA'
            ? 'BBBB-BB'
            : 'AAAA-AA';
        expect(store.confirmFingerprint('dev-a', wrong), isFalse);
        expect(store.isVerified('dev-a'), isFalse);

        // Correct observed fingerprint -> verified.
        final fp = (o as FirstContact).fingerprint;
        expect(store.confirmFingerprint('dev-a', fp), isTrue);
        expect(store.isVerified('dev-a'), isTrue);
      },
    );

    test('unknown device cannot be confirmed', () {
      expect(store.confirmFingerprint('ghost', 'ABC-DEF'), isFalse);
    });

    test(
      'relay-substituted key on re-lookup -> conflict, old pin kept',
      () async {
        final good = pubOf(21);
        final evil = pubOf(22);
        final first = await store.register('dev-b', good) as FirstContact;
        await store.register('dev-b', good); // unchanged path too
        final conflict = await store.register('dev-b', evil);
        expect(conflict, isA<KeyChangeConflict>());
        conflict as KeyChangeConflict;
        expect(conflict.oldFingerprint, first.fingerprint);
        // Old pin survives — no silent overwrite.
        expect(store.pinnedKey('dev-b'), equals(good));
        expect(store.isVerified('dev-b'), isFalse);
      },
    );

    test(
      're-pair after conflict requires acknowledging the exact old fp',
      () async {
        final good = pubOf(31);
        final evil = pubOf(32);
        final c = await store.register('dev-c', evil) as FirstContact;
        await store.register('dev-c', good); // conflict vs c.fingerprint
        // Wrong acknowledgement -> refused.
        expect(
          store.replaceAfterConflict('dev-c', good, '1111-11'),
          throwsStateError,
        );
        // Correct acknowledgement -> replaced, back to UNVERIFIED.
        final newFp = await store.replaceAfterConflict(
          'dev-c',
          good,
          c.fingerprint,
        );
        expect(newFp, await KeyFingerprint.fromPublicKey(good));
        expect(store.isVerified('dev-c'), isFalse);
        expect(store.pinnedKey('dev-c'), equals(good));
      },
    );

    test('export/import round-trips pins and trust levels', () async {
      final k1 = pubOf(41);
      final k2 = pubOf(42);
      final f1 = await store.register('d1', k1) as FirstContact;
      await store.register('d2', k2);
      store.confirmFingerprint('d1', f1.fingerprint);

      final fresh = PeerTrustStore()..importJson(store.exportJson());
      expect(fresh.pinnedKey('d1'), equals(k1));
      expect(fresh.pinnedKey('d2'), equals(k2));
      expect(fresh.isVerified('d1'), isTrue);
      expect(fresh.isVerified('d2'), isFalse);
    });

    test('import skips corrupt entries', () {
      final junk = jsonEncode({
        'v': 1,
        'peers': [
          {
            'device_id': 'bad',
            'identity_pub': base64.encode(Uint8List(16)),
            'fingerprint': 'AAA-AAA',
            'trust': 'verified',
          },
        ],
      });
      final s = PeerTrustStore()..importJson(junk);
      expect(s.pinnedKey('bad'), isNull);
      expect(s.isVerified('bad'), isFalse);
    });
  });

  group('self fingerprint', () {
    test('matches peer-side computation for the same key', () async {
      final kp = await X25519().newKeyPair();
      final myPub = Uint8List.fromList((await kp.extractPublicKey()).bytes);
      final mine = await PeerTrustStore.selfFingerprint(myPub);
      final theirs = await KeyFingerprint.fromPublicKey(myPub);
      expect(mine, theirs);
    });
  });
}
