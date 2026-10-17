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
import 'dart:typed_data';

import 'package:web_socket_channel/web_socket_channel.dart';

import '../crypto/e2e.dart';
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
    this.onKeyResponse,
  });

  final void Function(WelcomeInfo w)? onWelcome;
  final void Function(Packet msg)?
  onMessage; // MESSAGE and routed signalling types
  final void Function(String refMsgId, String stage)? onAck;
  final void Function(String code, String message)? onError;
  final void Function()? onDisconnected;
  final void Function(ConnState state)? onStateChanged;
  final void Function(KeyResponse r)? onKeyResponse;
}

/// Payload of a KEY_RESPONSE packet (mirrors Go client.KeyRes).
class KeyResponse {
  const KeyResponse({
    required this.targetDeviceId,
    required this.found,
    this.identityPub = '',
  });

  final String targetDeviceId;
  final bool found;

  /// base64-std 32-byte X25519 public key, empty when [found] is false.
  final String identityPub;

  static KeyResponse fromPayload(Object? p) {
    final m = p is Map ? p : const {};
    return KeyResponse(
      targetDeviceId: m['target_device_id'] as String? ?? '',
      found: m['found'] as bool? ?? false,
      identityPub: m['identity_pub'] as String? ?? '',
    );
  }
}

class BoltunRelayClient {
  BoltunRelayClient({
    required this.url,
    required this.deviceId,
    this.events = const RelayEvents(),
    this.maxReconnectDelay = const Duration(seconds: 30),
    this.identity,
  });

  final String url;
  final String deviceId;
  final RelayEvents events;
  final Duration maxReconnectDelay;

  /// This device's E2E identity key pair. When provided, HELLO announces
  /// its public key (server validates base64/32B and registers it for
  /// KEY_REQUEST lookups). Private material never leaves the device.
  final IdentityKeyPair? identity;

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

  /// Pending KEY_REQUEST waiters keyed by target device id. The relay
  /// echoes the request msg_id in the response for correlation.
  final Map<String, Completer<KeyResponse>> _keyWaiters = {};
  final Map<String, String> _keyReqIdByTarget = {};
  final Map<String, String> _keyTargetsByReqId = {};

  ConnState get state => _state;
  bool get isConnected => _state == ConnState.connected;

  /// Connect and complete the HELLO/WELCOME handshake. Idempotent while
  /// already connected. Auto-reconnects with exponential backoff after
  /// unexpected disconnects until [disconnect] is called.
  Future<WelcomeInfo> connect() async {
    _wantConnect = true;
    if (_state == ConnState.connected) {
      return WelcomeInfo(
        serverTime: 0,
        pingIntervalSec: 25,
        pendingMessages: 0,
      );
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
    // identity_pub (when E2E is configured) is announced so peers can look
    // it up via KEY_REQUEST; the server validates base64/32B and never sees
    // private material. Mirrors Go client.go HELLO payload.
    final nonce = hex(List<int>.generate(16, (_) => _rnd.nextInt(256)));
    _rawSend(
      Packet(
        type: PacketType.hello,
        payload: {
          'device_id': deviceId,
          'client_nonce': nonce,
          if (identity != null)
            // Server expects standard base64 of the raw 32-byte key
            // (protocol.Hello.identity_pub).
            'identity_pub': base64.encode(identity!.publicBytes),
        },
      ),
    );

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
    return c.future.timeout(
      const Duration(seconds: 10),
      onTimeout: () {
        throw TimeoutException('no WELCOME from $url within 10s');
      },
    );
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
      case PacketType.keyResponse:
        _handleKeyResponse(p);
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

  /// Correlate a KEY_RESPONSE with the in-flight KEY_REQUEST. The relay
  /// echoes the request's msg_id; fall back to target_device_id matching.
  void _handleKeyResponse(Packet p) {
    final r = KeyResponse.fromPayload(p.payload);
    events.onKeyResponse?.call(r);
    String? target = _keyTargetsByReqId.remove(p.msgId);
    target ??= r.targetDeviceId;
    final c = _keyWaiters.remove(target);
    _keyReqIdByTarget.remove(target);
    if (c != null && !c.isCompleted) c.complete(r);
  }

  /// Ask the relay for [target]'s announced identity public key and await
  /// the KEY_RESPONSE (bounded by [timeout]). Throws [TimeoutException] on
  /// no answer, [StateError] when not connected. found=false means the peer
  /// is offline or never announced a key.
  Future<KeyResponse> requestPeerKey(
    String target, {
    Duration timeout = const Duration(seconds: 10),
  }) async {
    if (_channel == null || _state != ConnState.connected) {
      throw StateError('not connected');
    }
    final existing = _keyWaiters[target];
    if (existing != null) return existing.future.timeout(timeout);
    final c = Completer<KeyResponse>();
    final id = newMsgId();
    _keyWaiters[target] = c;
    _keyReqIdByTarget[target] = id;
    _keyTargetsByReqId[id] = target;
    _rawSend(
      Packet(
        type: PacketType.keyRequest,
        msgId: id,
        from: deviceId,
        payload: {'target_device_id': target},
      ),
    );
    try {
      return await c.future.timeout(timeout);
    } on TimeoutException {
      // Drop the waiter so a later request can retry cleanly.
      if (identical(_keyWaiters[target], c)) {
        _keyWaiters.remove(target);
        _keyReqIdByTarget.remove(target);
        _keyTargetsByReqId.remove(id);
      }
      rethrow;
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
    // Fail all in-flight KEY_REQUEST waiters — they can never be answered
    // on the dead connection (callers treat this as "key unknown").
    for (final c in _keyWaiters.values) {
      if (!c.isCompleted) {
        c.completeError(const SocketException('connection closed'));
      }
    }
    _keyWaiters.clear();
    _keyReqIdByTarget.clear();
    _keyTargetsByReqId.clear();
    try {
      _channel?.sink.close();
    } catch (_) {}
    _channel = null;
    final wc = _welcomeCompleter;
    if (wc != null && !wc.isCompleted)
      wc.completeError(const SocketException('closed'));
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
          return WelcomeInfo(
            serverTime: 0,
            pingIntervalSec: 25,
            pendingMessages: 0,
          );
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

  /// Peer identity keys resolved via KEY_RESPONSE (deviceID -> 32B pub).
  final Map<String, Uint8List> peerKeys = {};

  /// Resolve and cache [peer]'s identity public key (KEY_REQUEST round-trip).
  /// Returns null when the peer is offline or announced no key.
  Future<Uint8List?> resolvePeerKey(String peer) async {
    final known = peerKeys[peer];
    if (known != null) return known;
    try {
      final r = await requestPeerKey(peer);
      if (!r.found || r.identityPub.isEmpty) return null;
      final Uint8List key;
      try {
        key = Uint8List.fromList(base64.decode(r.identityPub));
      } catch (_) {
        return null; // not valid base64 — treat as unusable
      }
      if (key.length != 32) return null; // server validates too, belt & braces
      peerKeys[peer] = key;
      return key;
    } on TimeoutException {
      return null;
    }
  }

  /// Seal [text] for [recipient] with E2E and send it as a MESSAGE.
  ///
  /// Delivery semantics (mirrors Go SendE2EMessage):
  ///  - the recipient's identity key must be resolved first; otherwise the
  ///    message is NOT sent (never in plaintext, never "delivered");
  ///  - msg_id is generated BEFORE sealing so the envelope AAD binds it —
  ///    the relay cannot re-route or replay the envelope under another id.
  /// Returns the msg_id used for ack correlation.
  Future<String?> sendE2EText(String recipient, String text) async {
    final self = identity;
    if (self == null) throw StateError('e2e identity not configured');
    if (_channel == null || _state != ConnState.connected) {
      throw StateError('not connected');
    }
    final recipPub = await resolvePeerKey(recipient);
    if (recipPub == null) return null; // key unknown -> refuse to send
    final id = newMsgId();
    final env = await seal(
      self,
      recipPub,
      id,
      Uint8List.fromList(utf8.encode(text)),
    );
    _sendRouted(PacketType.message, recipient, {
      'kind': 'e2ee',
      'v': 1,
      'env': encodeEnvelope(env),
    }, msgId: id);
    return id;
  }

  String _sendRouted(
    String type,
    String recipient,
    Object? payload, {
    String? msgId,
  }) {
    final ch = _channel;
    if (ch == null || _state != ConnState.connected) {
      throw StateError('not connected');
    }
    final id = msgId ?? newMsgId();
    _rawSend(
      Packet(
        type: type,
        msgId: id,
        from: deviceId, // server overwrites with bound identity anyway
        to: recipient,
        ts: DateTime.now().millisecondsSinceEpoch,
        payload: payload,
      ),
    );
    return id;
  }

  void requestSync() {
    _rawSend(
      Packet(type: PacketType.syncRequest, msgId: newMsgId(), from: deviceId),
    );
  }

  void ackStored(String refMsgId) {
    _rawSend(
      Packet(
        type: PacketType.storeAck,
        msgId: newMsgId(),
        from: deviceId,
        payload: {'ref_msg_id': refMsgId},
      ),
    );
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
