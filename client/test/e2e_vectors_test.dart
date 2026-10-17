/// Cross-language compatibility tests: Go-generated vectors vs Dart E2E.
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:boltun_client/crypto/e2e.dart';
import 'package:test/test.dart';

late Map<String, dynamic> v;
List<int> _un(String h) {
  final out = <int>[];
  for (var i = 0; i < h.length; i += 2) {
    out.add(int.parse(h.substring(i, i + 2), radix: 16));
  }
  return out;
}

void main() {
  setUpAll(() {
    v = jsonDecode(File('test/e2e_vectors.json').readAsStringSync());
  });

  test('1. identity public keys match Go', () async {
    final sender = await IdentityKeyPair.fromPrivateHex(
      v['sender_identity_priv_hex'],
    );
    final recip = await IdentityKeyPair.fromPrivateHex(
      v['recipient_identity_priv_hex'],
    );
    expect(sender.publicBytes, equals(_un(v['sender_identity_pub_hex'])));
    expect(recip.publicBytes, equals(_un(v['recipient_identity_pub_hex'])));
  });

  test('2. derived AES key matches Go', () async {
    final ephPub = Uint8List.fromList(_un(v['ephemeral_pub_hex']));
    final recipPub = Uint8List.fromList(_un(v['recipient_identity_pub_hex']));
    final shared = await deriveSharedForTest(
      Uint8List.fromList(_un(v['ephemeral_priv_hex'])),
      recipPub,
    );
    final key = await deriveKey(
      shared,
      ephPub,
      Uint8List.fromList(_un(v['sender_identity_pub_hex'])),
      recipPub,
      v['msg_id'],
    );
    expect(key, equals(Uint8List.fromList(_un(v['derived_key_hex']))));
  });

  test('3. Open() decrypts the Go envelope exactly', () async {
    final recip = await IdentityKeyPair.fromPrivateHex(
      v['recipient_identity_priv_hex'],
    );
    final env = decodeEnvelope(v['envelope_b64']);
    expect(env, equals(Uint8List.fromList(_un(v['envelope_hex']))));
    final plain = await open(
      recip,
      env,
      v['msg_id'],
      Uint8List.fromList(_un(v['sender_identity_pub_hex'])),
    );
    expect(utf8.decode(plain), equals(v['plaintext_utf8']));
  });

  test(
    '4. deterministic Seal() reproduces the Go envelope byte-for-byte',
    () async {
      final sender = await IdentityKeyPair.fromPrivateHex(
        v['sender_identity_priv_hex'],
      );
      final env = await seal(
        sender,
        Uint8List.fromList(_un(v['recipient_identity_pub_hex'])),
        v['msg_id'],
        Uint8List.fromList(utf8.encode(v['plaintext_utf8'])),
        ephPriv: Uint8List.fromList(_un(v['ephemeral_priv_hex'])),
        nonce: Uint8List.fromList(_un(v['nonce_hex'])),
      );
      expect(env, equals(Uint8List.fromList(_un(v['envelope_hex']))));
    },
  );

  test('5. tampered ciphertext is rejected', () async {
    final recip = await IdentityKeyPair.fromPrivateHex(
      v['recipient_identity_priv_hex'],
    );
    final env = decodeEnvelope(v['envelope_b64']);
    env[50] ^= 0x01; // flip a bit in ciphertext area
    expect(
      () => open(
        recip,
        env,
        v['msg_id'],
        Uint8List.fromList(_un(v['sender_identity_pub_hex'])),
      ),
      throwsA(isA<E2eException>()),
    );
  });

  test('6. tampered tag is rejected', () async {
    final recip = await IdentityKeyPair.fromPrivateHex(
      v['recipient_identity_priv_hex'],
    );
    final env = decodeEnvelope(v['envelope_b64']);
    env[env.length - 1] ^= 0x80;
    expect(
      () => open(
        recip,
        env,
        v['msg_id'],
        Uint8List.fromList(_un(v['sender_identity_pub_hex'])),
      ),
      throwsA(isA<E2eException>()),
    );
  });

  test('7. wrong msg_id is rejected (AAD binding)', () async {
    final recip = await IdentityKeyPair.fromPrivateHex(
      v['recipient_identity_priv_hex'],
    );
    final env = decodeEnvelope(v['envelope_b64']);
    expect(
      () => open(
        recip,
        env,
        'deadbeef',
        Uint8List.fromList(_un(v['sender_identity_pub_hex'])),
      ),
      throwsA(isA<E2eException>()),
    );
  });

  test('8. wrong sender pub is rejected (AAD binding)', () async {
    final recip = await IdentityKeyPair.fromPrivateHex(
      v['recipient_identity_priv_hex'],
    );
    final env = decodeEnvelope(v['envelope_b64']);
    final fake = Uint8List(32)..[0] = 0xFF;
    expect(
      () => open(recip, env, v['msg_id'], fake),
      throwsA(isA<E2eException>()),
    );
  });

  test('9. wrong recipient key is rejected', () async {
    final other = await IdentityKeyPair.generate();
    final env = decodeEnvelope(v['envelope_b64']);
    expect(
      () => open(
        other,
        env,
        v['msg_id'],
        Uint8List.fromList(_un(v['sender_identity_pub_hex'])),
      ),
      throwsA(isA<E2eException>()),
    );
  });

  test('10. malformed envelopes are rejected', () async {
    final recip = await IdentityKeyPair.fromPrivateHex(
      v['recipient_identity_priv_hex'],
    );
    final good = decodeEnvelope(v['envelope_b64']);
    expect(
      () => open(
        recip,
        good.sublist(0, 40),
        v['msg_id'],
        Uint8List.fromList(_un(v['sender_identity_pub_hex'])),
      ),
      throwsA(isA<E2eException>()),
    ); // too short
    final badVer = Uint8List.fromList(good)..[0] = 0x01;
    expect(
      () => open(
        recip,
        badVer,
        v['msg_id'],
        Uint8List.fromList(_un(v['sender_identity_pub_hex'])),
      ),
      throwsA(isA<E2eException>()),
    ); // bad version
  });

  test('11. random roundtrip Dart->Dart', () async {
    final a = await IdentityKeyPair.generate();
    final b = await IdentityKeyPair.generate();
    final msg = Uint8List.fromList(utf8.encode('привет boltun'));
    final env = await seal(a, b.publicBytes, 'cafe01', msg);
    final clear = await open(b, env, 'cafe01', a.publicBytes);
    expect(clear, equals(msg));
  });
}
