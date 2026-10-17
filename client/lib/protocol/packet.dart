/// BOLTUN relay protocol v1 — packet envelope and types.
///
/// Mirrors `server/internal/protocol`: JSON text frames over WebSocket.
library;

import 'dart:convert';

const int protocolVersion = 1;

/// Maximum inbound packet size in bytes (must match the server).
const int maxPacketBytes = 256 * 1024;

class PacketType {
  static const hello = 'HELLO';
  static const welcome = 'WELCOME';
  static const error = 'ERROR';
  static const ping = 'PING';
  static const pong = 'PONG';
  static const message = 'MESSAGE';
  static const messageAck = 'MESSAGE_ACK';
  static const deliveryStatus = 'DELIVERY_STATUS';
  static const syncRequest = 'SYNC_REQUEST';
  static const syncResponse = 'SYNC_RESPONSE';
  static const storeAck = 'STORE_ACK';
  static const pairRequest = 'PAIR_REQUEST';
  static const pairAccept = 'PAIR_ACCEPT';
  static const pairReject = 'PAIR_REJECT';
}

/// A single protocol envelope. [payload] stays opaque (E2E design):
/// the client never trusts server-supplied identity for its own sends.
class Packet {
  Packet({
    required this.type,
    this.msgId = '',
    this.from = '',
    this.to = '',
    this.ts = 0,
    this.payload,
  });

  final String type;
  final String msgId;
  final String from;
  final String to;
  final int ts;
  final Object? payload; // Map/List/String — serialized as-is

  Map<String, dynamic> toJson() => {
        'version': protocolVersion,
        'type': type,
        if (msgId.isNotEmpty) 'msg_id': msgId,
        if (from.isNotEmpty) 'from': from,
        if (to.isNotEmpty) 'to': to,
        if (ts != 0) 'ts': ts,
        if (payload != null) 'payload': payload,
      };

  String encode() => jsonEncode(toJson());

  static Packet decode(String raw) {
    final j = jsonDecode(raw) as Map<String, dynamic>;
    return Packet(
      type: j['type'] as String? ?? '',
      msgId: j['msg_id'] as String? ?? '',
      from: j['from'] as String? ?? '',
      to: j['to'] as String? ?? '',
      ts: (j['ts'] as num?)?.toInt() ?? 0,
      payload: _normalizePayload(j['payload']),
    );
  }

  /// Server may deliver payload as a JSON string or an object — tolerate both.
  static Object? _normalizePayload(Object? p) {
    if (p is String) {
      try {
        return jsonDecode(p);
      } catch (_) {
        return p;
      }
    }
    return p;
  }
}

/// Text chat message payload helper.
class TextPayload {
  static Map<String, dynamic> build(String text) => {'kind': 'text', 'text': text};

  static String? extract(Object? payload) {
    if (payload is Map && payload['kind'] == 'text') {
      return payload['text'] as String?;
    }
    // tolerate {"text": "..."} without kind
    if (payload is Map && payload['text'] is String) {
      return payload['text'] as String;
    }
    return null;
  }
}
