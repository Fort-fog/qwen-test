package store

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
)

func msg(id string) StoredMessage {
	return StoredMessage{
		MsgID:   id,
		From:    "device-alpha",
		TS:      1234567890,
		Type:    "MESSAGE",
		Payload: json.RawMessage(fmt.Sprintf(`{"ct":"blob-%s"}`, id)),
	}
}

func TestAppendPendingCountAck(t *testing.T) {
	s, err := Open("") // in-memory
	if err != nil {
		t.Fatal(err)
	}
	if got := s.Count("bob"); got != 0 {
		t.Fatalf("count=%d want 0", got)
	}
	for _, id := range []string{"m1", "m2", "m3"} {
		if err := s.Append("bob", msg(id)); err != nil {
			t.Fatal(err)
		}
	}
	if got := s.Count("bob"); got != 3 {
		t.Fatalf("count=%d want 3", got)
	}
	pend, err := s.Pending("bob")
	if err != nil {
		t.Fatal(err)
	}
	if len(pend) != 3 || pend[0].MsgID != "m1" || pend[2].MsgID != "m3" {
		t.Fatalf("pending wrong order/content: %+v", pend)
	}
	// Pending must not delete.
	if got := s.Count("bob"); got != 3 {
		t.Fatalf("Pending deleted messages: count=%d", got)
	}
	if err := s.Ack("bob", "m2"); err != nil {
		t.Fatal(err)
	}
	pend, _ = s.Pending("bob")
	if len(pend) != 2 || pend[0].MsgID != "m1" || pend[1].MsgID != "m3" {
		t.Fatalf("after ack: %+v", pend)
	}
	// Duplicate ack is ErrNotFound (caller treats as idempotent noop).
	if err := s.Ack("bob", "m2"); err != ErrNotFound {
		t.Fatalf("dup ack err=%v want ErrNotFound", err)
	}
	if err := s.Ack("carol", "nope"); err != ErrNotFound {
		t.Fatalf("unknown box ack err=%v want ErrNotFound", err)
	}
}

func TestAppendValidation(t *testing.T) {
	s, _ := Open("")
	if err := s.Append("", msg("x")); err == nil {
		t.Fatal("empty recipient must fail")
	}
	if err := s.Append("bob", StoredMessage{From: "a"}); err == nil {
		t.Fatal("empty msg_id must fail")
	}
}

func TestFIFORingCap(t *testing.T) {
	s, _ := Open("")
	for i := 0; i < MaxStoredMessages+10; i++ {
		if err := s.Append("bob", msg(strconv.Itoa(i))); err != nil {
			t.Fatal(err)
		}
	}
	pend, _ := s.Pending("bob")
	if len(pend) != MaxStoredMessages {
		t.Fatalf("len=%d want %d", len(pend), MaxStoredMessages)
	}
	// Oldest 10 dropped -> first retained is "10", last is the newest.
	if pend[0].MsgID != "10" {
		t.Fatalf("ring head=%q want \"10\"", pend[0].MsgID)
	}
	if last := pend[len(pend)-1].MsgID; last != strconv.Itoa(MaxStoredMessages+9) {
		t.Fatalf("ring tail=%q want %q", last, strconv.Itoa(MaxStoredMessages+9))
	}
}

func TestPersistenceRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.json")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Append("bob", msg("m1")); err != nil {
		t.Fatal(err)
	}
	if err := s.Append("alice", msg("m2")); err != nil {
		t.Fatal(err)
	}
	// Reopen from disk.
	s2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if s2.Count("bob") != 1 || s2.Count("alice") != 1 {
		t.Fatalf("reload counts bob=%d alice=%d", s2.Count("bob"), s2.Count("alice"))
	}
	if s2.TotalCount() != 2 {
		t.Fatalf("total=%d want 2", s2.TotalCount())
	}
	if s2.Path() != path {
		t.Fatalf("path=%s", s2.Path())
	}
	// Ack persists too.
	if err := s2.Ack("bob", "m1"); err != nil {
		t.Fatal(err)
	}
	s3, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if s3.Count("bob") != 0 {
		t.Fatalf("ack not persisted: %d", s3.Count("bob"))
	}
}

func TestCorruptStoreRejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path); err == nil {
		t.Fatal("corrupt store must not open silently")
	}
	if err := os.WriteFile(path, []byte(`{"version":99,"boxes":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path); err == nil {
		t.Fatal("unsupported version must be rejected")
	}
}

func TestConcurrentAccess(t *testing.T) {
	s, _ := Open("")
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			dev := "dev-" + strconv.Itoa(g)
			for i := 0; i < 50; i++ {
				_ = s.Append(dev, msg(strconv.Itoa(i)))
			}
			_, _ = s.Pending(dev)
			_ = s.Count(dev)
		}(g)
	}
	wg.Wait()
	if s.TotalCount() != 8*50 {
		t.Fatalf("total=%d want %d", s.TotalCount(), 8*50)
	}
}
