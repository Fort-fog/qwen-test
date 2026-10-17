// Cross-language E2E driver: two REAL Dart BoltunRelayClient instances
// (Alice, Bob) connect to a real Go relay (server/testfixture) over
// WebSocket, exchange identity keys via HELLO + KEY_REQUEST/KEY_RESPONSE,
// send an E2E-sealed message through the relay, and verify decryption,
// refusal without recipient key, and tamper rejection.
//
// Usage: dart test/relay_e2e_driver.dart <ws-url>
//   e.g. ws://127.0.0.1:34567/ws
// Prints "DRIVER OK" on success; exits non-zero with a reason on failure.
// Test-only script: ephemeral devices, no persisted secrets.
import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:boltun_client/crypto/e2e.dart';
import 'package:boltun_client/net/relay_client.dart';
import 'package:boltun_client/protocol/packet.dart';

void _ok(String msg) => stdout.writeln('[driver] $msg');
Never _fail(String msg) {
  stderr.writeln('DRIVER FAIL: $msg');
  exit(1);
}

Future<void> main(List<String> args) async {
  if (args.isEmpty) _fail('usage: relay_e2e_driver.dart <ws-url>');
  final base = args.first; // .../ws
  final aliceId = 'dart-alice-${DateTime.now().microsecondsSinceEpoch}';
  final bobId = 'dart-bob-${DateTime.now().microsecondsSinceEpoch}';

  final aliceKp = await IdentityKeyPair.generate();
  final bobKp = await IdentityKeyPair.generate();

  final bobInbox = StreamController<Packet>.broadcast();
  late final BoltunRelayClient alice;
  late final BoltunRelayClient bob;

  alice = BoltunRelayClient(url: base, deviceId: aliceId, identity: aliceKp);
  bob = BoltunRelayClient(
    url: base,
    deviceId: bobId,
    identity: bobKp,
    events: RelayEvents(onMessage: (p) => bobInbox.add(p)),
  );

  try {
    await alice.connect();
    await bob.connect();
    _ok('both clients connected + HELLO announced identity_pub');

    // --- 1. Key exchange through the real relay (KEY_REQUEST/RESPONSE) ---
    final ka = await alice.requestPeerKey(bobId);
    if (!ka.found || ka.identityPub.isEmpty) {
      _fail('alice could not resolve bob key via relay');
    }
    if (base64.decode(ka.identityPub).length != 32) {
      _fail('bob key from relay is not 32 bytes');
    }
    final kb = await bob.requestPeerKey(aliceId);
    if (!kb.found || kb.identityPub != base64.encode(aliceKp.publicBytes)) {
      _fail('bob got wrong/malformed alice key from relay');
    }
    _ok('key exchange routed by relay, bound to DeviceIDs');

    // --- 2. E2E send through the relay ---
    final text = 'boltun cross-language e2e ${DateTime.now()}';
    final mid = await alice.sendE2EText(bobId, text);
    if (mid == null) _fail('sendE2EText refused despite resolved key');
    final inbound = await bobInbox.stream
        .firstWhere((p) => p.msgId == mid)
        .timeout(const Duration(seconds: 10));

    // --- 3. Relay must carry ONLY the ciphertext envelope ---
    final pl = inbound.payload;
    if (pl is! Map || pl['kind'] != 'e2ee') {
      _fail('relay delivered non-e2ee payload to bob');
    }
    final envB64 = pl['env'] as String;
    final wire = jsonEncode(inbound.toJson());
    if (wire.contains(text)) _fail('plaintext leaked into relay-visible frame');
    final env = decodeEnvelope(envB64);
    if (utf8.decode(env, allowMalformed: true).contains(text)) {
      _fail('plaintext present in envelope bytes');
    }
    _ok('relay forwarded encrypted envelope only (no plaintext)');

    // --- 4. Open at recipient -> exact original text ---
    final senderPub = Uint8List.fromList(base64.decode(kb.identityPub));
    final clear = utf8.decode(await open(bobKp, env, mid, senderPub));
    if (clear != text) _fail('decrypted text mismatch: "$clear"');
    _ok('exact plaintext recovered after Seal->relay->Open');

    // --- 5. Refusal when recipient key is unknown ---
    final ghost = await alice.sendE2EText(
      'ghost-device-never-connects',
      'must never be sent',
    );
    if (ghost != null) _fail('send succeeded without recipient key');
    _ok('send refused when recipient key unresolved (no plaintext fallback)');

    // --- 6. Tampered envelope rejected at recipient side ---
    var threw = false;
    try {
      await open(bobKp, _flipByte(env), mid, senderPub);
    } on E2eException {
      threw = true;
    }
    if (!threw) _fail('tampered envelope was accepted');
    threw = false;
    try {
      await open(bobKp, env, 'f' * 24, senderPub); // wrong msg_id -> AAD
    } on E2eException {
      threw = true;
    }
    if (!threw) _fail('envelope opened under a different msg_id');
    _ok('tampered ciphertext/tag and foreign msg_id rejected');

    stdout.writeln('DRIVER OK');
  } finally {
    await alice.disconnect();
    await bob.disconnect();
    await bobInbox.close();
  }
  exit(0);
}

Uint8List _flipByte(Uint8List b) {
  final c = Uint8List.fromList(b);
  c[c.length - 1] ^= 0x01; // flip one bit of the auth tag
  return c;
}
