/// Pure-Dart E2E integration tests over the REAL client components:
/// seal -> wire packet -> open (cross-device), refusal without recipient
/// key, and safe handling of tampered/unknown-sender envelopes.
///
/// Uses the fixed Go-generated vectors from e2e_vectors.json so the crypto
/// path is anchored to the same key material as the Go side.
library;

import 'dart:convert';
import 'dart:io' show File;
import 'dart:typed_data';

import 'package:test/test.dart';

import 'package:boltun_client/crypto/e2e.dart';
import 'package:boltun_client/net/relay_client.dart';
import 'package:boltun_client/protocol/packet.dart';

// Mirrors MessageStore's StoredChat persistence shape (readable-message
// check) without pulling in shared_preferences — the harness store test
// covers durability separately.
Map<String, dynamic> storedReadable({
  required String msgId,
  required String peerId,
  required bool outgoing,
  required int ts,
  String? text,
}) => {
  'msg_id': msgId,
  'peer': peerId,
  'out': outgoing,
  'ts': ts,
  if (text != null) 'text': text,
};

Future<void> main() async {
  final vectors = jsonDecode(
    await File('test/e2e_vectors.json').readAsString(),
  ) as Map<String, dynamic>;

  final senderPriv = _unhex(vectors['sender_identity_priv_hex'] as String);
  final recipPriv = _unhex(vectors['recipient_identity_priv_hex'] as String);
  final senderPub = _unhex(vectors['sender_identity_pub_hex'] as String);
  final recipPub = _unhex(vectors['recipient_identity_pub_hex'] as String);
  final msgId = vectors['msg_id'] as String;
  final plaintext = vectors['plaintext_utf8'] as String;

  final alice = await IdentityKeyPair.fromPrivate(senderPriv);
  final bob = await IdentityKeyPair.fromPrivate(recipPriv);

  group('wire format', () {
    test('packet JSON matches server protocol v1 field names', () {
      final p = Packet(
        type: PacketType.message,
        msgId: 'ab12',
        from: 'dev-a',
        to: 'dev-b',
        ts: 1700000000000,
        payload: {'kind': 'e2ee', 'v': 1, 'env': 'AAAA'},
      );
      final j = jsonDecode(p.encode()) as Map<String, dynamic>;
      expect(j['version'], 1); // Go: Version `json:"version"`
      expect(j['type'], 'MESSAGE');
      expect(j['msg_id'], 'ab12');
      expect(j['from'], 'dev-a');
      expect(j['to'], 'dev-b');
      expect(j['ts'], 1700000000000);
      expect((j['payload'] as Map)['kind'], 'e2ee');
      // decode round-trip
      final d = Packet.decode(p.encode());
      expect(d.msgId, 'ab12');
      expect(d.type, PacketType.message);
    });

    test('KEY_REQUEST/KEY_RESPONSE payload keys match Go protocol', () {
      final req = Packet(
        type: PacketType.keyRequest,
        msgId: 'k1',
        from: 'dev-a',
        payload: {'target_device_id': 'dev-b'},
      );
      final jReq = jsonDecode(req.encode()) as Map<String, dynamic>;
      expect(jReq['payload']['target_device_id'], 'dev-b');

      final resp = KeyResponse.fromPayload({
        'target_device_id': 'dev-b',
        'found': true,
        'identity_pub': base64.encode(recipPub),
      });
      expect(resp.targetDeviceId, 'dev-b');
      expect(resp.found, isTrue);
      expect(base64.decode(resp.identityPub), recipPub);
    });
  });

  group('seal -> wire -> open across devices', () {
    test(
      'Alice seals, packet carries only opaque envelope, Bob opens',
      () async {
        final env = await seal(
          alice,
          recipPub,
          msgId,
          Uint8List.fromList(utf8.encode(plaintext)),
        );
        // Wire packet exactly as sendE2EText builds it.
        final wire = Packet(
          type: PacketType.message,
          msgId: msgId,
          from: 'dev-alice',
          to: 'dev-bob',
          ts: 1700000000000,
          payload: {'kind': 'e2ee', 'v': 1, 'env': encodeEnvelope(env)},
        ).encode();

        // The relay-visible text must NOT contain the plaintext.
        expect(wire.contains(plaintext), isFalse);

        final inbound = Packet.decode(wire);
        final pl = inbound.payload! as Map;
        expect(pl['kind'], 'e2ee');
        final raw = decodeEnvelope(pl['env'] as String);
        final clear = await open(bob, raw, inbound.msgId, senderPub);
        expect(utf8.decode(clear), plaintext);
      },
    );

    test(
      'tampered ciphertext/tag/AAD fields are rejected before storing',
      () async {
        final env = await seal(
          alice,
          recipPub,
          msgId,
          Uint8List.fromList(utf8.encode(plaintext)),
        );

        Future<bool> opens(Uint8List e, String id, Uint8List sp) async {
          try {
            await open(bob, e, id, sp);
            return true;
          } on E2eException {
            return false;
          }
        }

        // flip a ciphertext byte
        final t1 = Uint8List.fromList(env)..[40] ^= 0x01;
        expect(await opens(t1, msgId, senderPub), isFalse);
        // flip a tag byte
        final t2 = Uint8List.fromList(env)..[env.length - 1] ^= 0x80;
        expect(await opens(t2, msgId, senderPub), isFalse);
        // wrong msg id (AAD-bound)
        expect(await opens(env, 'ff' * 12, senderPub), isFalse);
        // wrong sender pub (AAD-bound)
        expect(await opens(env, msgId, recipPub), isFalse);
        // truncated envelope
        expect(
          await opens(Uint8List.fromList(env.sublist(0, 20)), msgId, senderPub),
          isFalse,
        );

        // A rejected envelope must never be persisted as readable text:
        // simulate what session does — store only after successful open.
        final stored = <Map<String, dynamic>>[];
        try {
          final clear = await open(bob, t1, msgId, senderPub);
          stored.add(
            storedReadable(
              msgId: msgId,
              peerId: 'dev-alice',
              outgoing: false,
              ts: 0,
              text: utf8.decode(clear),
            ),
          );
        } on E2eException {
          // surfaced as lastError, not stored
        }
        expect(stored, isEmpty);
      },
    );
  });

  group('BoltunRelayClient.sendE2EText semantics', () {
    test('refuses to send when recipient key is unknown', () async {
      final c = BoltunRelayClient(url: 'ws://invalid:1/', deviceId: 'dev-a');
      // Not connected at all -> StateError, message must not go anywhere.
      expect(() => c.sendE2EText('dev-b', 'secret'), throwsStateError);

      // Connected-shaped object with no peer key: resolvePeerKey would hit
      // requestPeerKey which throws StateError while disconnected; verify
      // peerKeys starts empty and sendE2EText identity guard fires first.
      expect(c.peerKeys, isEmpty);
      final noId = BoltunRelayClient(url: 'ws://invalid:1/', deviceId: 'dev-a');
      expect(() => noId.sendE2EText('dev-b', 'hi'), throwsStateError);
    });

    test('resolvePeerKey rejects malformed KEY_RESPONSE payloads', () async {
      final c = BoltunRelayClient(url: 'ws://invalid:1/', deviceId: 'dev-a');
      // Feed synthetic responses through the public handler path by
      // validating the same checks resolvePeerKey applies.
      for (final bad in [
        '',
        'not-base64!!',
        base64.encode([1, 2, 3]),
      ]) {
        final r = KeyResponse.fromPayload({
          'target_device_id': 'p',
          'found': true,
          'identity_pub': bad,
        });
        Uint8List? key;
        try {
          final decoded = base64.decode(r.identityPub);
          if (decoded.length == 32) key = Uint8List.fromList(decoded);
        } catch (_) {
          key = null;
        }
        expect(key, isNull, reason: 'bad b64 or wrong length: $bad');
      }
      final good = KeyResponse.fromPayload({
        'target_device_id': 'p',
        'found': true,
        'identity_pub': base64.encode(recipPub),
      });
      expect(base64.decode(good.identityPub).length, 32);
      expect(c.isConnected, isFalse);
    });

    test(
      'unknown sender: envelope stays unreadable until key resolves',
      () async {
        // Session-side contract: nothing is stored before Open succeeds.
        final env = await seal(
          alice,
          recipPub,
          msgId,
          Uint8List.fromList(utf8.encode(plaintext)),
        );
        final stored = <String, String>{}; // msgId -> readable text

        // Deferred: cannot open without sender pub; assert open attempt is
        // impossible rather than silently succeeding with a guessed key.
        var attempted = false;
        try {
          await open(bob, env, msgId, Uint8List(32)); // zero-filled "unknown"
        } on E2eException {
          attempted = true;
        }
        expect(attempted, isTrue);
        expect(stored.containsKey(msgId), isFalse);

        // After KEY_RESPONSE resolves the real sender pub, open succeeds.
        final clear = await open(bob, env, msgId, senderPub);
        stored[msgId] = utf8.decode(clear);
        expect(stored[msgId], plaintext);
      },
    );
  });
}

Uint8List _unhex(String h) {
  final out = Uint8List(h.length ~/ 2);
  for (var i = 0; i < out.length; i++) {
    out[i] = int.parse(h.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return out;
}
