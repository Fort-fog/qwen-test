/// Reusable BOLTUN relay client for Flutter: WebSocket + protocol v1.
///
/// Handles HELLO/WELCOME handshake, PING keep-alive at the server-announced
/// interval, inbound dedup by msg_id (at-least-once delivery), and the
/// offline SYNC_REQUEST / STORE_ACK flow. Mirrors the Go `internal/client`.
library;

// dart:io SocketException is used in _teardownTransport.
// ignore_for_file: avoid_web_libraries_in_flutter
import 'dart:async';
import 'dart:convert';
import 'dart:io' show SocketException;
import 'dart:math';

import 'package:web_socket_channel/web_socket_channel.dart';

import '../protocol/packet.dart';

enum ConnState { disconnected, connecting, connected }

class WelcomeInfo {
  WelcomeInfo({
    required this.serverTime,
    required this.pingIntervalSec,
    required this.pendingMessages,
    this.e2eeActive,
    this.e2eeWarning,
  });

  final int serverTime;
  final int pingIntervalSec;
  final int pendingMessages;
  final bool? e2eeActive; // null if the server build doesn't report it
  final String? e2eeWarning;

  static WelcomeInfo fromPayload(Object? p) {
    final m = p is Map ? p : const {};
    return WelcomeInfo(
      serverTime: (m['server_time'] as num?)?.toInt() ?? 0,
      pingIntervalSec: (m['ping_interval_sec'] as num?)?.toInt() ?? 25,
      pendingMessages: (m['pending_messages'] as num?)?.toInt() ?? 0,
      e2eeActive: m['e2ee_active'] as bool?,
      e2eeWarning: m['e2ee_warning'] as String?,
    );
  }
}

/// Callbacks run on the isolate's event loop; keep them cheap.
class RelayEvents {
  const RelayEvents({
    this.onWelcome,
    this.onMessage,
    this.onAck,
    this.onError,
    this.onDisconnected,
    this.onStateChanged,
  });

  final void Function(WelcomeInfo w)? onWelcome;
  final void Function(Packet msg)? onMessage; // MESSAGE and routed signalling types
  final void Function(String refMsgId, String stage)? onAck;
  final void Function(String code, String message)? onError;
  final void Function()? onDisconnected;
  final void Function(ConnState state)? onStateChanged;
}

class BoltunRelayClient {
  BoltunRelayClient({
    required this.url,
    required this.deviceId,
    this.events = const RelayEvents(),
    this.maxReconnectDelay = const Duration(seconds: 30),
  });

  final String url;
  final String deviceId;
  final RelayEvents events;
  final Duration maxReconnectDelay;

  WebSocketChannel? _channel;
  StreamSubscription<dynamic>? _sub;
  Timer? _pingTimer;
  Future<WelcomeInfo>? _handshake;
  ConnState _state = ConnState.disconnected;
  bool _wantConnect = false;
  int _retries = 0;
  final Random _rnd = Random.secure();

  /// Inbound msg_id dedup (at-least-once semantics).
  final Set<String> _seen = <String>{};

  ConnState get state => _state;
  bool get isConnected => _state == ConnState.connected;

  /// Connect and complete the HELLO/WELCOME handshake. Idempotent while
  /// already connected. Auto-reconnects with exponential backoff after
  /// unexpected disconnects until [disconnect] is called.
  Future<WelcomeInfo> connect() async {
    _wantConnect = true;
    if (_state == ConnState.connected) {
      return WelcomeInfo(serverTime: 0, pingIntervalSec: 25, pendingMessages: 0);
    }
    final h = _handshake;
    if (h != null) return h;
    final fut = _doConnect();
    _handshake = fut;
    try {
      return await fut;
    } finally {
      if (identical(_handshake, fut)) _handshake = null;
    }
  }

  Future<WelcomeInfo> _doConnect() async {
    _setState(ConnState.connecting);
    late WebSocketChannel ch;
    ch = WebSocketChannel.connect(Uri.parse(url));
    await ch.ready.timeout(const Duration(seconds: 10));
    _channel = ch;
    _sub = ch.stream.listen(
      _onFrame,
      onDone: _onDone,
      onError: (_) => _onDone(),
      cancelOnError: true,
    );

    // HELLO — device identity bound by the server from here on.
    final nonce = base64Url.encode(List<int>.generate(16, (_) => _rnd.nextInt(256)));
    _rawSend(Packet(
      type: PacketType.hello,
      payload: {'device_id': deviceId, 'client_nonce': nonce},
    ));

    final welcome = await _awaitWelcome();
    _retries = 0;
    _setState(ConnState.connected);
    _startPing(welcome.pingIntervalSec);
    events.onWelcome?.call(welcome);
    return welcome;
  }

  Completer<WelcomeInfo>? _welcomeCompleter;

  Future<WelcomeInfo> _awaitWelcome() {
    final c = Completer<WelcomeInfo>();
    _welcomeCompleter = c;
    return c.future.timeout(const Duration(seconds: 10), onTimeout: () {
      throw TimeoutException('no WELCOME from $url within 10s');
    });
  }

  void _onFrame(dynamic frame) {
    final raw = frame is String ? frame : utf8.decode(frame as List<int>);
    if (raw.length > maxPacketBytes) return; // oversized — drop
    Packet p;
    try {
      p = Packet.decode(raw);
    } catch (_) {
      return; // malformed
    }
    switch (p.type) {
      case PacketType.welcome:
        final wc = _welcomeCompleter;
        if (wc != null && !wc.isCompleted) {
          wc.complete(WelcomeInfo.fromPayload(p.payload));
        }
      case PacketType.pong:
        break;
      case PacketType.message:
      case PacketType.pairRequest:
      case PacketType.pairAccept:
      case PacketType.pairReject:
      case PacketType.deliveryStatus:
        if (_dedup(p.msgId)) events.onMessage?.call(p);
      case PacketType.syncResponse:
        _handleSyncResponse(p);
      case PacketType.messageAck:
        final pl = p.payload;
        if (pl is Map) {
          events.onAck?.call(
            pl['ref_msg_id'] as String? ?? '',
            pl['stage'] as String? ?? '',
          );
        }
      case PacketType.error:
        final pl = p.payload;
        if (pl is Map) {
          final msg = pl['message'] as String? ?? 'unknown error';
          final code = pl['code'] as String? ?? 'ERR';
          final wc = _welcomeCompleter;
          if (wc != null && !wc.isCompleted) {
            wc.completeError(StateError('server rejected HELLO: $code $msg'));
          }
          events.onError?.call(code, msg);
        }
      default:
        break;
    }
  }

  void _handleSyncResponse(Packet p) {
    final pl = p.payload;
    final list = pl is Map ? pl['messages'] : null;
    if (list is! List) return;
    for (final e in list) {
      if (e is! Map) continue;
      var payload = e['payload'];
      if (payload is String) {
        try {
          payload = jsonDecode(payload);
        } catch (_) {
          /* keep raw string */
        }
      }
      final msg = Packet(
        type: (e['type'] as String?) ?? PacketType.message,
        msgId: e['msg_id'] as String? ?? '',
        from: e['from'] as String? ?? '',
        to: deviceId,
        ts: (e['ts'] as num?)?.toInt() ?? 0,
        payload: payload,
      );
      if (_dedup(msg.msgId)) {
        events.onMessage?.call(msg);
        // Durable local receipt is assumed done by the store layer before
        // wiring; ack so the server can delete it.
        ackStored(msg.msgId);
      }
    }
  }

  bool _dedup(String msgId) {
    if (msgId.isEmpty) return true;
    if (_seen.contains(msgId)) return false;
    _seen.add(msgId);
    if (_seen.length > 5000) _seen.remove(_seen.first); // bounded window
    return true;
  }

  void _onDone() {
    _teardownTransport();
    _setState(ConnState.disconnected);
    events.onDisconnected?.call();
    if (_wantConnect) _scheduleReconnect();
  }

  void _teardownTransport() {
    _pingTimer?.cancel();
    _pingTimer = null;
    _sub?.cancel();
    _sub = null;
    try {
      _channel?.sink.close();
    } catch (_) {}
    _channel = null;
    final wc = _welcomeCompleter;
    if (wc != null && !wc.isCompleted) wc.completeError(const SocketException('closed'));
    _welcomeCompleter = null;
  }

  void _scheduleReconnect() {
    _retries += 1;
    final base = pow(2, min(_retries, 5)).toInt(); // 2..32s capped
    final delay = Duration(seconds: base.clamp(1, maxReconnectDelay.inSeconds));
    Timer(delay, () {
      if (_wantConnect && _state == ConnState.disconnected) {
        connect().catchError((_) {
          // failure triggers onDone → reschedule via backoff
          return WelcomeInfo(serverTime: 0, pingIntervalSec: 25, pendingMessages: 0);
        });
      }
    });
  }

  void _startPing(int intervalSec) {
    _pingTimer?.cancel();
    final per = Duration(seconds: max(intervalSec - 5, 5));
    _pingTimer = Timer.periodic(per, (_) {
      if (_state == ConnState.connected) {
        _rawSend(Packet(type: PacketType.ping, msgId: newMsgId()));
      }
    });
  }

  /// Send a text MESSAGE to [recipient]; returns the local msg_id used for
  /// ack correlation. Throws [StateError] when not connected.
  String sendMessage(String recipient, Map<String, dynamic> payload) {
    return _sendRouted(PacketType.message, recipient, payload);
  }

  String _sendRouted(String type, String recipient, Object? payload) {
    final ch = _channel;
    if (ch == null || _state != ConnState.connected) {
      throw StateError('not connected');
    }
    final id = newMsgId();
    _rawSend(Packet(
      type: type,
      msgId: id,
      from: deviceId, // server overwrites with bound identity anyway
      to: recipient,
      ts: DateTime.now().millisecondsSinceEpoch,
      payload: payload,
    ));
    return id;
  }

  void requestSync() {
    _rawSend(Packet(type: PacketType.syncRequest, msgId: newMsgId(), from: deviceId));
  }

  void ackStored(String refMsgId) {
    _rawSend(Packet(
      type: PacketType.storeAck,
      msgId: newMsgId(),
      from: deviceId,
      payload: {'ref_msg_id': refMsgId},
    ));
  }

  void _rawSend(Packet p) {
    final ch = _channel;
    if (ch == null) return;
    ch.sink.add(p.encode());
  }

  void _setState(ConnState s) {
    if (_state == s) return;
    _state = s;
    events.onStateChanged?.call(s);
  }

  /// Stop auto-reconnect and close the session.
  Future<void> disconnect() async {
    _wantConnect = false;
    _teardownTransport();
    _setState(ConnState.disconnected);
  }

  String newMsgId() {
    final b = List<int>.generate(12, (_) => _rnd.nextInt(256));
    return hex(b);
  }
}

String hex(List<int> bytes) =>
    bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
