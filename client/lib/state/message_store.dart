/// Local persistence for incoming/outgoing BOLTUN messages.
///
/// At-least-once delivery contract (docs/PROTOCOL.md): the receiver must
/// durably store a message BEFORE sending STORE_ACK. This layer is that
/// durable store; it keeps raw JSON envelopes keyed by msg_id so dedup and
/// ack decisions survive process restarts.
library;

import 'dart:async';
import 'dart:convert';

import 'package:meta/meta.dart';
import 'package:shared_preferences/shared_preferences.dart';

import '../protocol/packet.dart';

/// One stored chat message, reconstructed from a wire [Packet].
class StoredChat {
  StoredChat({
    required this.msgId,
    required this.peerId,
    required this.outgoing,
    required this.ts,
    this.text,
    this.rawPayload,
    this.ackedServer = false,
  });

  final String msgId;
  final String peerId; // other side of the conversation
  final bool outgoing;
  final int ts; // epoch millis
  final String? text; // decrypted/plain text when available
  final Map<String, dynamic>? rawPayload;
  bool ackedServer; // STORE_ACK sent (inbound) / MESSAGE_ACK received (out)

  Map<String, dynamic> toJson() => {
        'msg_id': msgId,
        'peer': peerId,
        'out': outgoing,
        'ts': ts,
        if (text != null) 'text': text,
        if (rawPayload != null) 'payload': rawPayload,
        'acked': ackedServer,
      };

  static StoredChat fromJson(Map<String, dynamic> j) => StoredChat(
        msgId: j['msg_id'] as String? ?? '',
        peerId: j['peer'] as String? ?? '',
        outgoing: j['out'] as bool? ?? false,
        ts: (j['ts'] as num?)?.toInt() ?? 0,
        text: j['text'] as String?,
        rawPayload: j['payload'] is Map<String, dynamic>
            ? j['payload'] as Map<String, dynamic>
            : null,
        ackedServer: j['acked'] as bool? ?? false,
      );
}

/// SharedPreferences-backed message store with an in-memory mirror for
/// synchronous reads. All mutations are awaited before returning so callers
/// can treat "stored" as "durable" (safe to STORE_ACK afterwards).
class MessageStore {
  MessageStore._(this._prefs);

  static const _indexKey = 'boltun.store.index'; // msg_id -> json blob key
  static final _blobPrefix = 'boltun.store.msg.';

  /// Test seam: inject a fake SharedPreferences backend (same semantics as
  /// SharedPreferences.setMockInitialValues in Flutter tests).
  @visibleForTesting
  static Future<MessageStore> openWith(SharedPreferences prefs) async {
    final s = MessageStore._(prefs);
    s._load();
    return s;
  }

  final SharedPreferences _prefs;
  final Map<String, StoredChat> _cache = {};
  final List<void Function(StoredChat)> _listeners = [];

  /// Load (or create) the store. Call once at app start.
  static Future<MessageStore> open() async {
    final prefs = await SharedPreferences.getInstance();
    final s = MessageStore._(prefs);
    s._load();
    return s;
  }

  void _load() {
    _cache.clear();
    final index = _prefs.getStringList(_indexKey) ?? const [];
    for (final id in index) {
      final raw = _prefs.getString('$_blobPrefix$id');
      if (raw == null) continue;
      try {
        final c = StoredChat.fromJson(jsonDecode(raw) as Map<String, dynamic>);
        _cache[c.msgId] = c;
      } catch (_) {
        // Corrupt entry: drop it rather than crash the whole store.
        _prefs.remove('$_blobPrefix$id');
      }
    }
  }

  StreamController<List<StoredChat>>? _changes;

  /// Emits the full sorted list whenever the store mutates (UI rebinds).
  Stream<List<StoredChat>> watch() {
    final c = _changes ??= StreamController.broadcast();
    return c.stream;
  }

  /// Subscribe to single-message inserts (used to trigger STORE_ACK).
  void onInsert(void Function(StoredChat) cb) => _listeners.add(cb);

  List<StoredChat> messagesFor(String peerId) {
    final list = _cache.values.where((m) => m.peerId == peerId).toList()
      ..sort((a, b) => a.ts.compareTo(b.ts));
    return list;
  }

  List<String> conversations() {
    final peers = <String>{};
    for (final m in _cache.values) {
      peers.add(m.peerId);
    }
    return peers.toList()..sort();
  }

  StoredChat? byMsgId(String msgId) => _cache[msgId];

  bool knows(String msgId) => _cache.containsKey(msgId);

  /// Durably insert an inbound packet (from the relay or a SYNC_RESPONSE).
  /// Returns false if the msg_id was already present (duplicate delivery).
  Future<bool> putInbound(Packet p) async {
    if (p.msgId.isEmpty || knows(p.msgId)) return false;
    final c = StoredChat(
      msgId: p.msgId,
      peerId: p.from,
      outgoing: false,
      ts: p.ts,
      text: TextPayload.extract(p.payload),
      rawPayload: p.payload is Map<String, dynamic>
          ? Map<String, dynamic>.from(p.payload as Map)
          : null,
    );
    await _put(c);
    return true;
  }

  /// Record a message we are sending (before the relay confirms anything).
  Future<String> putOutgoing(String peerId, Map<String, dynamic> payload,
      {required String msgId, String? text}) async {
    final c = StoredChat(
      msgId: msgId,
      peerId: peerId,
      outgoing: true,
      ts: DateTime.now().millisecondsSinceEpoch,
      text: text ?? TextPayload.extract(payload),
      rawPayload: payload,
    );
    await _put(c);
    return msgId;
  }

  Future<void> _put(StoredChat c) async {
    _cache[c.msgId] = c;
    final index = _prefs.getStringList(_indexKey)?.toList() ?? [];
    index.add(c.msgId);
    await Future.wait([
      _prefs.setStringList(_indexKey, index),
      _prefs.setString('$_blobPrefix${c.msgId}', jsonEncode(c.toJson())),
    ]);
    for (final l in _listeners) {
      l(c);
    }
    _emit();
  }

  /// Mark a message as server-acked (inbound STORE_ACK sent / outbound
  /// MESSAGE_ACK received). Idempotent.
  Future<void> markAcked(String msgId) async {
    final c = _cache[msgId];
    if (c == null || c.ackedServer) return;
    c.ackedServer = true;
    await _prefs.setString('$_blobPrefix$msgId', jsonEncode(c.toJson()));
    _emit();
  }

  /// Remove messages older than [maxAge] (housekeeping; not part of the
  /// protocol). Returns how many entries were dropped.
  Future<int> prune({Duration maxAge = const Duration(days: 90)}) async {
    final cutoff =
        DateTime.now().subtract(maxAge).millisecondsSinceEpoch;
    final stale =
        _cache.values.where((m) => m.ts != 0 && m.ts < cutoff).toList();
    for (final m in stale) {
      _cache.remove(m.msgId);
      await _prefs.remove('$_blobPrefix${m.msgId}');
    }
    if (stale.isNotEmpty) {
      final index = _cache.keys.toList();
      await _prefs.setStringList(_indexKey, index);
      _emit();
    }
    return stale.length;
  }

  int get count => _cache.length;

  void _emit() {
    final c = _changes;
    if (c != null && !c.isClosed) {
      final all = _cache.values.toList()
        ..sort((a, b) => a.ts.compareTo(b.ts));
      c.add(all);
    }
  }

  void dispose() {
    _changes?.close();
    _changes = null;
    _listeners.clear();
  }
}
