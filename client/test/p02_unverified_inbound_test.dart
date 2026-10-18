// P0.2 regression tests: E2E messages from unverified peers must never be
// presented as trusted; verified path unchanged; key-change conflict keeps
// the old pin and does not decrypt under the new key; deferred retransmit
// after KEY_RESPONSE still works; no plaintext fallback anywhere.
library;

import 'dart:convert';
import 'dart:io' show File;
import 'dart:typed_data';

import 'package:test/test.dart';

import 'package:boltun_client/crypto/e2e.dart' as e2e;
import 'package:boltun_client/net/relay_client.dart';
import 'package:boltun_client/protocol/packet.dart';
import 'package:boltun_client/state/message_store.dart';
import 'package:boltun_client/state/session.dart';
import 'package:boltun_client/crypto/fingerprint.dart';

Uint8List _unhex(String h) {
  final out = Uint8List(h.length ~/ 2);
  for (var i = 0; i < out.length; i++) {
    out[i] = int.parse(h.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return out;
}

Future<void> main() async {
  final vectors = jsonDecode(
    await File('test/e2e_vectors.json').readAsString(),
  ) as Map<String, dynamic>;
  final recipPriv = _unhex(vectors['recipient_identity_priv_hex'] as String);
  final senderPubV = _unhex(vectors['sender_identity_pub_hex'] as String);
  final msgId = vectors['msg_id'] as String;
  final plaintext = vectors['plaintext_utf8'] as String;
  final envHex = vectors['envelope_hex'] as String;

  final bob = await e2e.IdentityKeyPair.fromPrivate(recipPriv);

  // Session with in-memory store seam and an attached inert relay client
  // (connectedForTest never opens a socket; resolvePeerKey fails fast, so
  // deferred envelopes stay queued until processKeyResponseForTest runs).
  Future<(BoltunSession, MessageStore)> newSession() async {
    final store = await MessageStore.openInMemory();
    final s = BoltunSession(storeFactory: () async => store);
    // Attach the inert client FIRST; then start(): the real socket connect
    // fails in the background and its error handler only overwrites
    // _lastError while _client stays attached to the test instance.
    // ignore: invalid_use_of_visible_for_testing_member
    s.attachClientForTest(BoltunRelayClient.connectedForTest(
      url: 'ws://unused',
      deviceId: 'bob',
    ));
    // ignore: invalid_use_of_visible_for_testing_member
    await s.start(SessionConfig(url: 'ws://unused', deviceId: 'bob'));
    await Future<void>.delayed(const Duration(milliseconds: 150));
    return (s, store);
  }

  Packet e2ePacket(String envB64, String mid, {String from = 'alice'}) =>
      Packet(
        type: PacketType.message,
        msgId: mid,
        from: from,
        to: 'bob',
        ts: 1,
        payload: {'kind': 'e2ee', 'v': 1, 'env': envB64},
      );

  group('P0.2 senderVerified model', () {
    test('stored JSON: default true is omitted; false round-trips', () {
      final a = StoredChat(
          msgId: 'm1', peerId: 'p', outgoing: false, ts: 1, text: 'x');
      expect(a.senderVerified, isTrue);
      expect(a.toJson().containsKey('sender_verified'), isFalse,
          reason: 'legacy-compatible serialization: no new key when true');
      final b = StoredChat(
          msgId: 'm2',
          peerId: 'p',
          outgoing: false,
          ts: 1,
          text: 'x',
          senderVerified: false);
      expect(b.toJson()['sender_verified'], isFalse);
      expect(
          StoredChat.fromJson(
                  {'msg_id': 'm3', 'peer': 'p', 'out': false, 'ts': 1})
              .senderVerified,
          isTrue,
          reason:
              'old records without the field load as trusted (plaintext/legacy)');
      expect(StoredChat.fromJson(b.toJson()).senderVerified, isFalse);
    });

    test('putInbound stores senderVerified=false when passed explicitly',
        () async {
      final store = await MessageStore.openInMemory();
      final p = Packet(
          type: PacketType.message,
          msgId: 'x1',
          from: 'a',
          to: 'b',
          ts: 1,
          payload: TextPayload.build('hello'));
      expect(await store.putInbound(p, senderVerified: false), isTrue);
      expect(store.messagesFor('a').single.senderVerified, isFalse);
    });
  });

  group('P0.2 session inbound pipeline', () {
    test('message from VERIFIED peer is stored trusted (behaves as before)',
        () async {
      final (s, store) = await newSession();
      // inject identity + peer key + trust manually through public seams
      // ignore: invalid_use_of_visible_for_testing_member
      s.injectIdentityForTest(bob);
      // register & confirm the pinned key
      final outcome = await s.trust.register('alice', senderPubV);
      expect(outcome, isNotNull);
      final fp = await KeyFingerprint.fromPublicKey(senderPubV);
      expect(s.trust.confirmFingerprint('alice', fp), isTrue);
      s.peerKeysForTest['alice'] = senderPubV;
      final envB64 = e2e.encodeEnvelope(_unhex(envHex));
      // ignore: invalid_use_of_visible_for_testing_member
      s.handleInboundForTest(e2ePacket(envB64, msgId));
      await Future<void>.delayed(const Duration(milliseconds: 50));
      final msgs = store.messagesFor('alice');
      expect(msgs, hasLength(1));
      expect(msgs.single.text, plaintext);
      expect(msgs.single.senderVerified, isTrue);
    });

    test('message from UNVERIFIED peer is stored but NOT trusted', () async {
      final (s, store) = await newSession();
      // ignore: invalid_use_of_visible_for_testing_member
      s.injectIdentityForTest(bob);
      await s.trust.register('alice', senderPubV); // unverified pin
      s.peerKeysForTest['alice'] = senderPubV;
      final envB64 = e2e.encodeEnvelope(_unhex(envHex));
      // ignore: invalid_use_of_visible_for_testing_member
      s.handleInboundForTest(e2ePacket(envB64, msgId));
      await Future<void>.delayed(const Duration(milliseconds: 50));
      final msgs = store.messagesFor('alice');
      expect(msgs, hasLength(1), reason: 'content must not be lost');
      expect(msgs.single.text, plaintext);
      expect(msgs.single.senderVerified, isFalse,
          reason: 'P0.2: never renderable as a trusted chat bubble');
    });

    test('no plaintext fallback: raw e2ee envelope is never stored readable',
        () async {
      final (s, store) = await newSession();
      // ignore: invalid_use_of_visible_for_testing_member
      s.injectIdentityForTest(bob);
      // unknown sender key -> deferred, nothing stored
      final envB64 = e2e.encodeEnvelope(_unhex(envHex));
      // ignore: invalid_use_of_visible_for_testing_member
      s.handleInboundForTest(e2ePacket(envB64, msgId));
      await Future<void>.delayed(const Duration(milliseconds: 20));
      expect(store.messagesFor('alice'), isEmpty);
      // tampered tag -> open fails -> nothing stored at all
      final bad = _unhex(envHex);
      bad[bad.length - 1] ^= 0x01;
      s.peerKeysForTest['alice'] = senderPubV;
      await s.trust.register('alice', senderPubV);
      // ignore: invalid_use_of_visible_for_testing_member
      s.handleInboundForTest(e2ePacket(e2e.encodeEnvelope(bad), 'tamper1'));
      await Future<void>.delayed(const Duration(milliseconds: 50));
      expect(store.messagesFor('alice'), isEmpty,
          reason: 'failed Open must not persist anything (no fallback)');
      expect(s.lastErrorForTest, contains('E2E_OPEN_FAILED'));
    });

    test(
        'key-change conflict: old pin kept, message not opened under attacker key',
        () async {
      final (s, store) = await newSession();
      // ignore: invalid_use_of_visible_for_testing_member
      s.injectIdentityForTest(bob);
      await s.trust.register('alice', senderPubV);
      final attacker = await e2e.IdentityKeyPair.generate();
      final r = KeyResponse(
          targetDeviceId: 'alice',
          found: true,
          identityPub: base64.encode(attacker.publicBytes));
      // ignore: invalid_use_of_visible_for_testing_member
      await s.processKeyResponseForTest(r);
      expect(s.peerKeysForTest.containsKey('alice'), isFalse,
          reason: 'conflicting key must not enter the working key cache');
      expect(s.lastErrorForTest, contains('E2E_KEY_CHANGE'));
      // A message sealed under the ATTACKER key would fail Open for bob's
      // side anyway because cached sender pub stays old — verify nothing
      // got stored:
      final envAtk = await e2e.seal(attacker, bob.publicBytes, 'atk1',
          Uint8List.fromList(utf8.encode('evil')));
      // ignore: invalid_use_of_visible_for_testing_member
      s.handleInboundForTest(e2ePacket(e2e.encodeEnvelope(envAtk), 'atk1'));
      await Future<void>.delayed(const Duration(milliseconds: 50));
      expect(store.messagesFor('alice'), isEmpty);
    });

    test(
        'deferred retransmit after KEY_RESPONSE still works (and honours trust flag)',
        () async {
      final (s, store) = await newSession();
      // ignore: invalid_use_of_visible_for_testing_member
      s.injectIdentityForTest(bob);
      final envB64 = e2e.encodeEnvelope(_unhex(envHex));
      // arrives before key known -> deferred
      // ignore: invalid_use_of_visible_for_testing_member
      s.handleInboundForTest(e2ePacket(envB64, msgId));
      await Future<void>.delayed(const Duration(milliseconds: 20));
      expect(store.messagesFor('alice'), isEmpty);
      // KEY_RESPONSE resolves the key (TOFU: unverified)
      final r = KeyResponse(
          targetDeviceId: 'alice',
          found: true,
          identityPub: base64.encode(senderPubV));
      // ignore: invalid_use_of_visible_for_testing_member
      await s.processKeyResponseForTest(r);
      final msgs = store.messagesFor('alice');
      expect(msgs, hasLength(1),
          reason: 'deferred retry delivered exactly once');
      expect(msgs.single.text, plaintext);
      expect(msgs.single.senderVerified, isFalse,
          reason: 'retried message inherits unverified state (P0.2)');
      // after OOB confirmation, a NEW message from same peer is trusted
      final fp = await KeyFingerprint.fromPublicKey(senderPubV);
      expect(s.trust.confirmFingerprint('alice', fp), isTrue);
      final env2 = await e2e.seal(
          await e2e.IdentityKeyPair.fromPrivate(
              _unhex(vectors['sender_identity_priv_hex'] as String)),
          bob.publicBytes,
          'mid2',
          Uint8List.fromList(utf8.encode('second')));
      // ignore: invalid_use_of_visible_for_testing_member
      s.handleInboundForTest(e2ePacket(e2e.encodeEnvelope(env2), 'mid2'));
      await Future<void>.delayed(const Duration(milliseconds: 50));
      final m2 =
          store.messagesFor('alice').firstWhere((m) => m.msgId == 'mid2');
      expect(m2.text, 'second');
      expect(m2.senderVerified, isTrue,
          reason: 'post-confirmation exchange continues normally');
    });
  });

  group('P0.3 legacy-path bypass protection', () {
    test('normal plaintext message still stores as before (compat)',
        () async {
      final (s, store) = await newSession();
      // ignore: invalid_use_of_visible_for_testing_member
      s.injectIdentityForTest(bob);
      // ignore: invalid_use_of_visible_for_testing_member
      s.handleInboundForTest(Packet(
        type: PacketType.message,
        msgId: 'plain1',
        from: 'carol',
        to: 'bob',
        ts: 1,
        payload: TextPayload.build('legacy hello'),
      ));
      await Future<void>.delayed(const Duration(milliseconds: 50));
      final msgs = store.messagesFor('carol');
      expect(msgs, hasLength(1),
          reason: 'legacy plaintext protocol must keep working');
      expect(msgs.single.text, 'legacy hello');
    });

    test('envelope-shaped payload WITHOUT kind is NOT trusted plaintext',
        () async {
      final (s, store) = await newSession();
      // ignore: invalid_use_of_visible_for_testing_member
      s.injectIdentityForTest(bob);
      final envB64 = e2e.encodeEnvelope(_unhex(envHex));
      // Attacker/relay strips the "kind":"e2ee" marker hoping the client
      // classifies this as a legacy plaintext message.
      // ignore: invalid_use_of_visible_for_testing_member
      s.handleInboundForTest(Packet(
        type: PacketType.message,
        msgId: 'nostrip1',
        from: 'alice',
        to: 'bob',
        ts: 1,
        payload: {'v': 1, 'env': envB64},
      ));
      await Future<void>.delayed(const Duration(milliseconds: 80));
      // Key unknown -> deferred fail-closed; nothing readable persisted.
      expect(store.messagesFor('alice'), isEmpty,
          reason: 'P0.3: env-bearing payload never falls into plaintext path');
      expect(s.lastErrorForTest, contains('E2E_NO_SENDER_KEY'));
    });

    test('kind-stripped envelope resolves via KEY_RESPONSE and opens as E2E',
        () async {
      final (s, store) = await newSession();
      // ignore: invalid_use_of_visible_for_testing_member
      s.injectIdentityForTest(bob);
      final envB64 = e2e.encodeEnvelope(_unhex(envHex));
      // kind marker stripped -> must be classified E2E and deferred, NOT
      // stored as trusted plaintext
      // ignore: invalid_use_of_visible_for_testing_member
      s.handleInboundForTest(Packet(
        type: PacketType.message,
        msgId: 'nostrip2',
        from: 'alice',
        to: 'bob',
        ts: 1,
        payload: {'v': 1, 'env': envB64},
      ));
      await Future<void>.delayed(const Duration(milliseconds: 20));
      expect(store.messagesFor('alice'), isEmpty);
      // KEY_RESPONSE resolves the sender key -> full E2E pipeline runs
      final r = KeyResponse(
          targetDeviceId: 'alice',
          found: true,
          identityPub: base64.encode(senderPubV));
      // ignore: invalid_use_of_visible_for_testing_member
      await s.processKeyResponseForTest(r);
      final msgs = store.messagesFor('alice');
      expect(msgs, hasLength(1));
      expect(msgs.single.text, plaintext);
      expect(msgs.single.senderVerified, isFalse,
          reason: 'went through the E2E pipeline with its trust check');
    });

    test("kind:'e2ee' without env is rejected, never stored", () async {
      final (s, store) = await newSession();
      // ignore: invalid_use_of_visible_for_testing_member
      s.injectIdentityForTest(bob);
      // ignore: invalid_use_of_visible_for_testing_member
      s.handleInboundForTest(Packet(
        type: PacketType.message,
        msgId: 'noenv1',
        from: 'alice',
        to: 'bob',
        ts: 1,
        payload: {'kind': 'e2ee', 'v': 1},
      ));
      await Future<void>.delayed(const Duration(milliseconds: 30));
      expect(store.messagesFor('alice'), isEmpty,
          reason: 'P0.3: malformed envelope never persists anything');
      expect(s.lastErrorForTest, contains('E2E_MALFORMED_ENVELOPE'));
    });

    test('tampered/garbage env (invalid base64) rejected without storage',
        () async {
      final (s, store) = await newSession();
      // ignore: invalid_use_of_visible_for_testing_member
      s.injectIdentityForTest(bob);
      s.peerKeysForTest['alice'] = senderPubV;
      // ignore: invalid_use_of_visible_for_testing_member
      s.handleInboundForTest(Packet(
        type: PacketType.message,
        msgId: 'badb64',
        from: 'alice',
        to: 'bob',
        ts: 1,
        payload: {'kind': 'e2ee', 'v': 1, 'env': '!!!not-base64!!!'},
      ));
      await Future<void>.delayed(const Duration(milliseconds: 30));
      expect(store.messagesFor('alice'), isEmpty,
          reason: 'garbage env must not persist');
      expect(s.lastErrorForTest, contains('E2E_MALFORMED_ENVELOPE'));
      // same smuggle attempt with the kind marker stripped:
      // ignore: invalid_use_of_visible_for_testing_member
      s.handleInboundForTest(Packet(
        type: PacketType.message,
        msgId: 'badb64b',
        from: 'alice',
        to: 'bob',
        ts: 1,
        payload: {'v': 1, 'env': '!!!not-base64!!!'},
      ));
      await Future<void>.delayed(const Duration(milliseconds: 30));
      expect(store.messagesFor('alice'), isEmpty,
          reason: 'P0.3: suspicious non-decodable env never reaches plaintext');
      expect(s.lastErrorForTest, contains('E2E_MALFORMED_ENVELOPE'));
    });

    test('deferred retransmit after KEY_RESPONSE bypasses no check', () async {
      final (s, store) = await newSession();
      // ignore: invalid_use_of_visible_for_testing_member
      s.injectIdentityForTest(bob);
      final envB64 = e2e.encodeEnvelope(_unhex(envHex));
      // kind-stripped envelope arrives before the key is known -> deferred
      // ignore: invalid_use_of_visible_for_testing_member
      s.handleInboundForTest(Packet(
        type: PacketType.message,
        msgId: msgId,
        from: 'alice',
        to: 'bob',
        ts: 1,
        payload: {'v': 1, 'env': envB64},
      ));
      await Future<void>.delayed(const Duration(milliseconds: 20));
      expect(store.messagesFor('alice'), isEmpty);
      final r = KeyResponse(
          targetDeviceId: 'alice',
          found: true,
          identityPub: base64.encode(senderPubV));
      // ignore: invalid_use_of_visible_for_testing_member
      await s.processKeyResponseForTest(r);
      final msgs = store.messagesFor('alice');
      expect(msgs, hasLength(1),
          reason: 'retried exactly once, through the full E2E pipeline');
      expect(msgs.single.text, plaintext);
      expect(msgs.single.senderVerified, isFalse,
          reason: 'trust check applied on the retried path too');
    });
  });
}
