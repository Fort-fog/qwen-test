# BOLTUN relay protocol (v1)

Wire format: JSON text frames over WebSocket. Single envelope:

```json
{
  "version": 1,
  "type": "MESSAGE",
  "msg_id": "hex(24)",
  "from": "device-id",
  "to": "device-id",
  "ts": 1700000000000,
  "payload": { "...opaque, E2E-encrypted in the final design..." }
}
```

## Packet types

| Type                | Direction        | Purpose |
|---------------------|------------------|---------|
| HELLO               | client → server  | Handshake, binds session to `device_id` (8..64 chars `[A-Za-z0-9_-]`) |
| WELCOME             | server → client  | Session accepted; carries `server_time`, `ping_interval_sec`, `pending_messages` |
| PING / PONG         | both             | Keep-alive at the interval announced in WELCOME |
| MESSAGE             | client → peer    | Routed by `to`; if peer offline, durably stored (at-least-once) |
| MESSAGE_ACK         | server → sender  | Stages: `RELAYED_TO_PEER` or `STORED_FOR_LATER_DELIVERY`, correlated via `ref_msg_id` |
| SYNC_REQUEST        | client → server  | Ask for the offline queue after reconnect |
| SYNC_RESPONSE       | server → client  | Batched stored messages |
| STORE_ACK           | client → server  | Confirms durable local receipt; server deletes that message |
| ERROR               | server → client  | Rejection with `code` + human message |
| PAIR_REQUEST/ACCEPT/REJECT, FILE_*, CALL_* | routed | Opaque signalling, forwarded like MESSAGE |

## Guarantees & rules

- Identity is bound at HELLO; the server **overwrites** `from` on every
  inbound packet — clients can never spoof another device.
- Max packet size 256 KiB (`protocol.MaxPacketSize`).
- Offline store: JSON file (`BOLTUN_STORE_FILE`, default `./data/boltun-store.json`).
- Delivery semantics: **at-least-once**. Receivers must deduplicate by `msg_id`
  and only `STORE_ACK` after local persistence. The Go client package
  (`internal/client`) does the dedup automatically unless `KeepDuplicates` is set.
- Payloads are opaque to the server. Real E2E encryption is a client-side
  responsibility (not yet implemented — smoke tools mark packets explicitly).

## Reference implementations

- Server: `server/cmd/boltun-server`
- Go client library: `server/internal/client` (used by `cmd/boltun-smoke`)
- Python dev clients: `scripts/smoke_ws_test.sh`
