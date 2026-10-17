import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'package:boltun_client/protocol/packet.dart';
import 'package:boltun_client/state/message_store.dart';

void main() {
  setUp(() {
    SharedPreferences.setMockInitialValues({});
  });

  group('Packet', () {
    test('encode/decode round-trip keeps fields', () {
      final p = Packet(
        type: PacketType.message,
        msgId: 'aabbcc',
        from: 'dev-1',
        to: 'dev-2',
        ts: 1700000000000,
        payload: TextPayload.build('привет'),
      );
      final raw = p.encode();
      final d = Packet.decode(raw);
      expect(d.type, PacketType.message);
      expect(d.msgId, 'aabbcc');
      expect(d.from, 'dev-1');
      expect(d.to, 'dev-2');
      expect(d.ts, 1700000000000);
      expect(TextPayload.extract(d.payload), 'привет');
    });

    test('decode tolerates payload delivered as JSON string', () {
      const raw = '{"version":1,"type":"MESSAGE","msg_id":"x",'
          '"payload":"{\\"kind\\":\\"text\\",\\"text\\":\\"hi\\"}"}';
      final p = Packet.decode(raw);
      expect(TextPayload.extract(p.payload), 'hi');
    });

    test('omits empty optional fields', () {
      final p = Packet(type: PacketType.ping);
      expect(p.toJson().containsKey('msg_id'), isFalse);
      expect(p.toJson().containsKey('from'), isFalse);
    });
  });

  group('MessageStore', () {
    test('putInbound dedups by msg_id and reports freshness', () async {
      final s = await MessageStore.open();
      final p = Packet(
        type: PacketType.message,
        msgId: 'm1',
        from: 'peer-a',
        ts: 100,
        payload: TextPayload.build('one'),
      );
      expect(await s.putInbound(p), isTrue);
      expect(await s.putInbound(p), isFalse, reason: 'duplicate delivery');
      expect(s.count, 1);
      s.dispose();
    });

    test('messages survive reopen (durability across restarts)', () async {
      final s1 = await MessageStore.open();
      await s1.putOutgoing('peer-b', TextPayload.build('echo'),
          msgId: 'o1', text: 'echo');
      final c1 = s1.count;

      final s2 = await MessageStore.open(); // simulates app restart
      expect(s2.count, c1);
      final m = s2.byMsgId('o1');
      expect(m, isNotNull);
      expect(m!.outgoing, isTrue);
      expect(m.text, 'echo');
      s1.dispose();
      s2.dispose();
    });

    test('markAcked is idempotent and persisted', () async {
      final s = await MessageStore.open();
      final p = Packet(
          type: PacketType.message,
          msgId: 'm9',
          from: 'peer-c',
          ts: 5,
          payload: TextPayload.build('ack me'));
      await s.putInbound(p);
      await s.markAcked('m9');
      await s.markAcked('m9'); // no-op
      expect(s.byMsgId('m9')!.ackedServer, isTrue);

      final reopened = await MessageStore.open();
      expect(reopened.byMsgId('m9')!.ackedServer, isTrue);
      s.dispose();
      reopened.dispose();
    });

    test('conversations lists unique peers sorted', () async {
      final s = await MessageStore.open();
      await s.putInbound(Packet(
          type: PacketType.message, msgId: 'x1', from: 'zzz', ts: 1));
      await s.putInbound(Packet(
          type: PacketType.message, msgId: 'x2', from: 'aaa', ts: 2));
      await s.putInbound(Packet(
          type: PacketType.message, msgId: 'x3', from: 'zzz', ts: 3));
      expect(s.conversations(), ['aaa', 'zzz']);
      expect(s.messagesFor('zzz').map((m) => m.msgId).toList(),
          ['x1', 'x3']);
      s.dispose();
    });

    test('prune drops only stale entries', () async {
      final s = await MessageStore.open();
      final now = DateTime.now().millisecondsSinceEpoch;
      await s.putInbound(Packet(
          type: PacketType.message, msgId: 'old', from: 'p', ts: now - 200 * 86400000));
      await s.putInbound(
          Packet(type: PacketType.message, msgId: 'new', from: 'p', ts: now));
      final dropped = await s.prune(maxAge: const Duration(days: 90));
      expect(dropped, 1);
      expect(s.byMsgId('old'), isNull);
      expect(s.byMsgId('new'), isNotNull);
      s.dispose();
    });
  });
}
