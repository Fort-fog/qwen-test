#!/usr/bin/env bash
# BOLTUN dev smoke test: two REAL websocket clients (Python) exchange
# packets through a running boltun-server. Verifies the end-to-end relay
# path outside of Go unit tests.
#
# Usage: scripts/smoke_ws_test.sh [ws_url]
#   default ws_url = ws://localhost:8443/ws (server must already run in dev mode)
set -euo pipefail

WS_URL="${1:-ws://localhost:8443/ws}"
DEV_A="smoke-device-alpha"
DEV_B="smoke-device-bravo"

python3 - "$WS_URL" "$DEV_A" "$DEV_B" <<'PYEOF'
import asyncio, json, sys, time, uuid

try:
    import websockets
except ImportError:
    print("MISSING DEPENDENCY: pip install websockets (or run inside venv)")
    sys.exit(2)

WS_URL, DEV_A, DEV_B = sys.argv[1], sys.argv[2], sys.argv[3]
V = 1

def pkt(t, **kw):
    p = {"version": V, "type": t}
    p.update(kw)
    return json.dumps(p)

async def hello(ws, dev):
    await ws.send(pkt("HELLO", payload={"device_id": dev, "client_nonce": uuid.uuid4().hex}))
    while True:
        m = json.loads(await asyncio.wait_for(ws.recv(), 5))
        if m["type"] == "WELCOME":
            warn = json.loads(m["payload"]).get("e2ee_warning", "")
            print(f"[{dev}] WELCOME ok; e2e warning present: {bool(warn)}")
            return m
        if m["type"] == "ERROR":
            print(f"[{dev}] HELLO rejected: {m}")
            sys.exit(1)

async def recv_type(ws, dev, want, timeout=5):
    while True:
        m = json.loads(await asyncio.wait_for(ws.recv(), timeout))
        if m["type"] == "PING":
            continue
        if m["type"] == want:
            return m
        if m["type"] == "ERROR":
            print(f"[{dev}] ERROR: {m}")
            sys.exit(1)
        # tolerate other types by looping

async def main():
    async with websockets.connect(WS_URL) as a, websockets.connect(WS_URL) as b:
        await hello(a, DEV_A); await hello(b, DEV_B)

        msg_id = "smoke-" + uuid.uuid4().hex[:8]
        await a.send(pkt("MESSAGE", msg_id=msg_id, from_=None, to=DEV_B,
                         ts=int(time.time()*1000),
                         payload={"text": "hello bravo (TEST PACKET, NO E2E YET)"})
                     .replace('"from_": null,', '"from": "%s",' % DEV_A))
        got = await recv_type(b, DEV_B, "MESSAGE")
        assert got["msg_id"] == msg_id, got
        assert got["from"] == DEV_A, got
        body = json.loads(got["payload"]) if isinstance(got.get("payload"), str) else got.get("payload", {})
        print(f"[{DEV_B}] received MESSAGE msg_id={got['msg_id']} from={got['from']} text={body.get('text')!r}")

        ack = await recv_type(a, DEV_A, "MESSAGE_ACK")
        print(f"[{DEV_A}] transport ack: {ack['payload']}")

        rid = "smoke-" + uuid.uuid4().hex[:8]
        await b.send(json.dumps({"version": V, "type": "MESSAGE", "msg_id": rid,
                                 "from": DEV_B, "to": DEV_A, "ts": int(time.time()*1000),
                                 "payload": {"text": "hi alpha (REPLY TEST PACKET)"}}))
        rep = await recv_type(a, DEV_A, "MESSAGE")
        assert rep["msg_id"] == rid and rep["from"] == DEV_B, rep
        print(f"[{DEV_A}] received reply msg_id={rep['msg_id']} from={rep['from']}")

        # offline status check
        await a.send(json.dumps({"version": V, "type": "MESSAGE",
                                 "msg_id": "ghost-1", "from": DEV_A,
                                 "to": "nobody-online-here", "payload": {}}))
        err = await recv_type(a, DEV_A, "ERROR")
        code = err["payload"]["code"] if isinstance(err.get("payload"), dict) else json.loads(err["payload"])["code"]
        assert code == "PEER_OFFLINE", err
        print(f"[{DEV_A}] offline status verified: {code}")

    print("SMOKE TEST PASSED: real bidirectional exchange through the server.")

asyncio.run(main())
PYEOF
