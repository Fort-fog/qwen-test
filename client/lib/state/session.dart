/// Session model: glues BoltunRelayClient + MessageStore into one observable
/// object for the UI layer.
///
/// Responsibilities:
///  - durable-first inbound handling (store → then STORE_ACK), per the
///    at-least-once contract in docs/PROTOCOL.md;
///  - outgoing send with local echo before the relay accepts it;
///  - ack correlation (MESSAGE_ACK stages update the stored copy);
///  - connection state exposure for status banners.
library;

import 'dart:async';

import '../net/relay_client.dart';
import '../protocol/packet.dart';
import 'message_store.dart';

class SessionConfig {
  const SessionConfig({
    required this.url,
    required this.deviceId,
    this.displayName = '',
  });

  final String url; // ws://host:port/ws
  final String deviceId;
  final String displayName;
}

/// Everything the UI needs, in one stream.
class SessionSnapshot {
  SessionSnapshot({
    required this.state,
    required this.conversations,
    this.lastError,
    this.e2eeWarning,
  });

  final ConnState state;
  final List<String> conversations;
  final String? lastError;
  final String? e2eeWarning; // server's "E2EE not active" notice, if any
}

class BoltunSession {
  BoltunRelayClient? _client;
  MessageStore? _store;
  SessionConfig? _config;

  final StreamController<SessionSnapshot> _snap =
      StreamController.broadcast();
  ConnState _state = ConnState.disconnected;
  String? _lastError;
  String? _e2eeWarning;

  Stream<SessionSnapshot> get snapshots => _snap.stream;
  ConnState get state => _state;
  bool get isConnected => _state == ConnState.connected;
  MessageStore? get store => _store;
  SessionConfig? get config => _config;

  /// Open the local store and connect to the relay. Safe to call once;
  /// reconnection is handled internally by the relay client.
  Future<void> start(SessionConfig cfg) async {
    _config = cfg;
    _store = await MessageStore.open();
    final client = BoltunRelayClient(
      url: cfg.url,
      deviceId: cfg.deviceId,
      events: RelayEvents(
        onWelcome: (w) {
          // The server always announces whether E2EE is active; surface the
          // warning banner whenever it says encryption is not enabled.
          _e2eeWarning = w.e2eeActive == false ? w.e2eeWarning : null;
          _emit();
        },
        onMessage: _handleInbound,
        onAck: _handleAck,
        onError: (code, msg) {
          _lastError = '$code: $msg';
          _emit();
        },
        onStateChanged: (s) {
          _state = s;
          _emit();
        },
        onDisconnected: () {},
      ),
    );
    _client = client;
    unawaited(client.connect().catchError((Object e) {
      _lastError = e.toString();
      _emit();
      return WelcomeInfo(serverTime: 0, pingIntervalSec: 25, pendingMessages: 0);
    }));
    _emit();
  }

  void _handleInbound(Packet p) {
    final store = _store;
    if (store == null) return;
    // Durable first, ack after — never ack a message we haven't persisted.
    unawaited(store.putInbound(p).then((fresh) {
      if (fresh) {
        _client?.ackStored(p.msgId);
      }
      _emit();
    }));
  }

  void _handleAck(String refMsgId, String stage) {
    final store = _store;
    if (store == null || refMsgId.isEmpty) return;
    // RELAYED_TO_PEER / STORED_FOR_LATER_DELIVERY both mean the server has
    // accepted our message; mark it so the UI can show a single checkmark.
    unawaited(store.markAcked(refMsgId).then((_) => _emit()));
  }

  /// Send a text message to [peerId]. Returns the local msg_id immediately;
  /// the message is already visible in the store as an outgoing echo.
  Future<String?> sendText(String peerId, String text) async {
    final client = _client;
    final store = _store;
    if (client == null || store == null) return null;
    if (!client.isConnected) return null;
    final id = client.sendMessage(peerId, TextPayload.build(text));
    await store.putOutgoing(peerId, TextPayload.build(text),
        msgId: id, text: text);
    _emit();
    return id;
  }

  /// Force a manual sync pull (e.g. after returning from background).
  void requestSync() => _client?.requestSync();

  void _emit() {
    if (_snap.isClosed) return;
    _snap.add(SessionSnapshot(
      state: _state,
      conversations: _store?.conversations() ?? const [],
      lastError: _lastError,
      e2eeWarning: _e2eeWarning,
    ));
  }

  Future<void> stop() async {
    await _client?.disconnect();
    _client = null;
    _store?.dispose();
    _store = null;
    await _snap.close();
  }
}
