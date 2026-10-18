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
import 'dart:convert';
import 'dart:typed_data';

import '../crypto/e2e.dart' as e2e;
import '../net/relay_client.dart';
import '../protocol/packet.dart';
import 'identity_store.dart';
import 'message_store.dart';
import 'peer_trust.dart';

// `open` is also the name of MessageStore.open's verb; alias the crypto
// entry point so both read unambiguously.
Future<Uint8List> e2eOpen(
  e2e.IdentityKeyPair recipient,
  Uint8List envelope,
  String msgId,
  Uint8List senderPub,
) => e2e.open(recipient, envelope, msgId, senderPub);

class SessionConfig {
  const SessionConfig({
    required this.url,
    required this.deviceId,
    this.displayName = '',
    this.identityStore,
  });

  final String url; // ws://host:port/ws
  final String deviceId;
  final String displayName;

  /// E2E identity persistence. When null, the session runs in legacy
  /// plaintext mode (no identity_pub announced). NOTE: production must use
  /// a keystore-backed IdentityStore — see identity_store.dart limitations.
  final IdentityStore? identityStore;
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
  // Non-nullable so `_identity!` is unnecessary and the
  // analyzer's null checks are sound. Null-equivalent = not configured.
  late e2e.IdentityKeyPair? _identity;
  bool _started = false;

  /// Envelopes received before the sender's identity key was resolved;
  /// retried automatically when KEY_RESPONSE arrives (mirrors the Go
  /// E2EHandler deferred queue, bounded per peer).
  final Map<String, List<Packet>> _deferred = {};
  static const int _maxDeferredPerPeer = 100;

  /// TOFU pin registry for peer identity keys (public material only).
  /// A relay-supplied key is never trusted merely because it parses.
  final PeerTrustStore trust = PeerTrustStore();

  final StreamController<SessionSnapshot> _snap = StreamController.broadcast();
  ConnState _state = ConnState.disconnected;
  String? _lastError;
  String? _e2eeWarning;

  Stream<SessionSnapshot> get snapshots => _snap.stream;
  ConnState get state => _state;
  bool get isConnected => _state == ConnState.connected;
  MessageStore? get store => _store;
  SessionConfig? get config => _config;
  e2e.IdentityKeyPair? get identity => _identity;

  /// Open the local store and connect to the relay. Safe to call once;
  /// reconnection is handled internally by the relay client.
  Future<void> start(SessionConfig cfg) async {
    if (_started) return;
    _started = true;
    _config = cfg;
    _identity = null;
    _store = await MessageStore.open();
    final store = cfg.identityStore;
    if (store != null) {
      try {
        _identity = await store.loadOrCreate();
      } on IdentityLoadException catch (e) {
        // The device HAS an identity we could not safely load. Do NOT fall
        // back to legacy plaintext mode and do NOT generate a replacement:
        // fail the start explicitly so the operator notices before any
        // message is sent/received with the wrong key.
        _started = false;
        _lastError = 'IDENTITY_LOAD_FAILED: ${e.message}';
        rethrow;
      }
    }
    final client = BoltunRelayClient(
      url: cfg.url,
      deviceId: cfg.deviceId,
      identity: _identity,
      events: RelayEvents(
        onWelcome: (w) {
          // The server always announces whether E2EE is active; surface the
          // warning banner whenever it says encryption is not enabled.
          _e2eeWarning = w.e2eeActive == false ? w.e2eeWarning : null;
          _emit();
        },
        onMessage: _handleInbound,
        onAck: _handleAck,
        onKeyResponse: _handleKeyResponse,
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
    unawaited(
      client.connect().catchError((Object e) {
        _lastError = e.toString();
        _emit();
        return WelcomeInfo(
          serverTime: 0,
          pingIntervalSec: 25,
          pendingMessages: 0,
        );
      }),
    );
    _emit();
  }

  void _handleInbound(Packet p) {
    if (p.type == PacketType.message && _isE2eEnvelope(p.payload)) {
      _handleE2eInbound(p);
      return;
    }
    final store = _store;
    if (store == null) return;
    // Durable first, ack after — never ack a message we haven't persisted.
    unawaited(
      store.putInbound(p).then((fresh) {
        if (fresh) {
          _client?.ackStored(p.msgId);
        }
        _emit();
      }),
    );
  }

  static bool _isE2eEnvelope(Object? payload) =>
      payload is Map && payload['kind'] == 'e2ee';

  /// Opens an incoming "e2ee" envelope before persisting/acking it.
  /// Failure modes are terminal-safe: malformed envelopes and open errors
  /// are surfaced via lastError and NOT stored as readable messages; an
  /// unknown sender key defers the envelope until KEY_RESPONSE resolves it.
  void _handleE2eInbound(Packet p) {
    final self = _identity;
    final client = _client;
    if (self == null || client == null) {
      _lastError = 'E2E_OPEN_FAILED: encrypted message but no identity key';
      _emit();
      return;
    }
    final envB64 = p.payload is Map ? (p.payload as Map)['env'] : null;
    if (envB64 is! String) {
      _lastError = 'E2E_MALFORMED_ENVELOPE (${p.msgId})';
      _emit();
      return;
    }
    final Uint8List raw;
    try {
      raw = e2e.decodeEnvelope(envB64);
    } catch (_) {
      _lastError = 'E2E_MALFORMED_ENVELOPE (${p.msgId})';
      _emit();
      return;
    }
    final senderPub = client.peerKeys[p.from];
    if (senderPub == null) {
      // Queue for retry once the sender's key resolves; ask for it now.
      final dq = _deferred.putIfAbsent(p.from, () => <Packet>[]);
      if (dq.length < _maxDeferredPerPeer) dq.add(p);
      unawaited(client.resolvePeerKey(p.from));
      _lastError = 'E2E_NO_SENDER_KEY: ${p.from} (${p.msgId})';
      _emit();
      return;
    }
    _openAndStore(p, raw, senderPub);
  }

  Future<void> _openAndStore(
    Packet p,
    Uint8List raw,
    Uint8List senderPub,
  ) async {
    final store = _store;
    if (store == null) return;
    final self = _identity;
    if (self == null) return; // no key -> nothing to open with; caller guarded
    try {
      final plain = await e2eOpen(self, raw, p.msgId, senderPub);
      final text = utf8.decode(plain);
      final opened = Packet(
        type: p.type,
        msgId: p.msgId,
        from: p.from,
        to: p.to,
        ts: p.ts,
        payload: TextPayload.build(text),
      );
      // Durable first, ack after — same contract as plaintext inbound.
      final fresh = await store.putInbound(opened);
      if (fresh) _client?.ackStored(p.msgId);
    } on e2e.E2eException catch (e) {
      // Auth failure / tampering: never store, never silently drop.
      _lastError = 'E2E_OPEN_FAILED: ${e.message} (${p.msgId})';
    } on FormatException {
      _lastError = 'E2E_OPEN_FAILED: invalid utf-8 plaintext (${p.msgId})';
    }
    _emit();
  }

  void _handleKeyResponse(KeyResponse r) {
    unawaited(_processKeyResponse(r));
  }

  Future<void> _processKeyResponse(KeyResponse r) async {
    if (!r.found || r.identityPub.isEmpty) return;
    final client = _client;
    if (client == null) return;
    Uint8List key;
    try {
      key = Uint8List.fromList(base64.decode(r.identityPub));
    } catch (_) {
      return;
    }
    if (key.length != 32) return;
    // TOFU pinning: a relay-supplied key is NEVER trusted just because it
    // is well-formed. It is pinned as unverified; a later change of the
    // same DeviceID surfaces as KeyChangeConflict (kept old pin wins).
    final outcome = await trust.register(r.targetDeviceId, key);
    if (outcome is KeyChangeConflict) {
      _lastError =
          'E2E_KEY_CHANGE:${r.targetDeviceId}:'
          '${outcome.oldFingerprint}->${outcome.newFingerprint}';
      // Do NOT overwrite the cached/pinned key — keep talking to the old
      // identity until the user re-verifies out of band.
      return;
    }
    client.peerKeys[r.targetDeviceId] = key;
    // Retry envelopes that arrived before this sender's key was known.
    final retry = _deferred.remove(r.targetDeviceId);
    if (retry != null) {
      for (final p in retry) {
        final env = p.payload is Map ? (p.payload as Map)['env'] : null;
        if (env is! String) continue;
        Uint8List raw;
        try {
          raw = e2e.decodeEnvelope(env);
        } catch (_) {
          continue; // malformed while waiting — surface, don't crash the loop
        }
        unawaited(_openAndStore(p, raw, key));
      }
    }
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
  ///
  /// When E2E is configured (identity present) the text is sealed with
  /// e2e.Seal before leaving the device — the relay only ever sees the
  /// opaque envelope. If the recipient's identity key cannot be resolved,
  /// the message is NOT sent and nothing is echoed as delivered.
  Future<String?> sendText(String peerId, String text) async {
    final client = _client;
    final store = _store;
    if (client == null || store == null) return null;
    if (!client.isConnected) return null;
    if (_identity != null) {
      // Seal + wire send FIRST; only a message that actually left the
      // device is echoed as sent (refusal -> nothing stored, see below).
      final id = await client.sendE2EText(peerId, text);
      if (id == null) {
        _lastError = 'E2E_NO_RECIPIENT_KEY: $peerId (message not sent)';
        _emit();
        return null;
      }
      // Store the plaintext locally (device-side only); the wire carried
      // only the sealed envelope.
      await store.putOutgoing(
        peerId,
        {'kind': 'e2ee', 'sent': true},
        msgId: id,
        text: text,
      );
      _emit();
      return id;
    }
    final id = client.sendMessage(peerId, TextPayload.build(text));
    await store.putOutgoing(
      peerId,
      TextPayload.build(text),
      msgId: id,
      text: text,
    );
    _emit();
    return id;
  }

  /// Force a manual sync pull (e.g. after returning from background).
  void requestSync() => _client?.requestSync();

  void _emit() {
    if (_snap.isClosed) return;
    _snap.add(
      SessionSnapshot(
        state: _state,
        conversations: _store?.conversations() ?? const [],
        lastError: _lastError,
        e2eeWarning: _e2eeWarning,
      ),
    );
  }

  Future<void> stop() async {
    await _client?.disconnect();
    _client = null;
    _store?.dispose();
    _store = null;
    await _snap.close();
  }
}
