package protocol

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDecodeValidMessage(t *testing.T) {
	raw := `{"version":1,"type":"MESSAGE","msg_id":"m1","from":"dev_a","to":"dev_b","ts":1,"payload":{"k":"v"}}`
	p, err := Decode([]byte(raw))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if p.Type != PacketMessage || p.MsgID != "m1" || p.To != "dev_b" {
		t.Fatalf("unexpected packet: %+v", p)
	}
}

func TestRejectUnknownType(t *testing.T) {
	raw := `{"version":1,"type":"BOGUS","msg_id":"x"}`
	if _, err := Decode([]byte(raw)); err == nil {
		t.Fatal("expected error for unknown type")
	} else if !strings.Contains(err.Error(), "unknown packet type") {
		t.Fatalf("wrong error: %v", err)
	}
}

func TestRejectMissingType(t *testing.T) {
	raw := `{"version":1}`
	if _, err := Decode([]byte(raw)); err == nil {
		t.Fatal("expected error for missing type")
	}
}

func TestRejectBadVersion(t *testing.T) {
	raw := `{"version":99,"type":"PING"}`
	if _, err := Decode([]byte(raw)); err != ErrBadVersion {
		t.Fatalf("want ErrBadVersion, got %v", err)
	}
}

func TestRejectMissingMsgID(t *testing.T) {
	raw := `{"version":1,"type":"MESSAGE","to":"dev_b"}`
	if _, err := Decode([]byte(raw)); err != ErrMissingMsgID {
		t.Fatalf("want ErrMissingMsgID, got %v", err)
	}
}

func TestRejectMissingTo(t *testing.T) {
	raw := `{"version":1,"type":"MESSAGE","msg_id":"m1"}`
	if _, err := Decode([]byte(raw)); err != ErrMissingTo {
		t.Fatalf("want ErrMissingTo, got %v", err)
	}
}

func TestRejectInvalidJSON(t *testing.T) {
	if _, err := Decode([]byte(`{not json`)); err != ErrInvalidJSON {
		t.Fatalf("want ErrInvalidJSON, got %v", err)
	}
}

func TestRejectOversizedPacket(t *testing.T) {
	big := make([]byte, MaxPacketSize+1)
	for i := range big {
		big[i] = 'a'
	}
	if _, err := Decode(big); err != ErrPayloadTooBig {
		t.Fatalf("want ErrPayloadTooBig, got %v", err)
	}
}

func TestControlPacketsNoMsgID(t *testing.T) {
	for _, typ := range []PacketType{PacketHello, PacketPing} {
		raw, _ := json.Marshal(Packet{Version: ProtocolVersion, Type: typ})
		if _, err := Decode(raw); err != nil {
			t.Fatalf("%s should not require msg_id: %v", typ, err)
		}
	}
}

func TestNeedsAuth(t *testing.T) {
	if PacketHello.NeedsAuth() {
		t.Fatal("HELLO must not require auth")
	}
	if !PacketMessage.NeedsAuth() {
		t.Fatal("MESSAGE must require auth")
	}
}

func TestEncodeRoundTrip(t *testing.T) {
	p := &Packet{
		Version: ProtocolVersion,
		Type:    PacketMessage,
		MsgID:   "abc",
		To:      "peer1",
		Payload: json.RawMessage(`{"opaque":"blob"}`),
	}
	raw, err := Encode(p)
	if err != nil {
		t.Fatal(err)
	}
	back, err := Decode(raw)
	if err != nil {
		t.Fatalf("roundtrip decode: %v", err)
	}
	if string(back.Payload) != `{"opaque":"blob"}` {
		t.Fatalf("payload lost: %s", back.Payload)
	}
}
