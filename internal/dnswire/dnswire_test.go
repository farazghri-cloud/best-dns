package dnswire

import (
	"encoding/binary"
	"testing"
)

func TestQueryRoundTrip(t *testing.T) {
	q, err := NewQuery(0x1234, "a.b.example.com", TypeA)
	if err != nil {
		t.Fatal(err)
	}
	m, err := Parse(q)
	if err != nil {
		t.Fatal(err)
	}
	if m.Header.ID != 0x1234 {
		t.Fatalf("id = %x", m.Header.ID)
	}
	if len(m.Questions) != 1 || m.Questions[0].Name != "a.b.example.com" || m.Questions[0].Type != TypeA {
		t.Fatalf("question = %+v", m.Questions)
	}
	if m.Header.Flags&0x0100 == 0 {
		t.Fatal("RD bit not set")
	}
}

func TestBuildReply(t *testing.T) {
	q, _ := NewQuery(0x4321, "example.com", TypeA)
	req, err := Parse(q)
	if err != nil {
		t.Fatal(err)
	}
	raw := BuildReply(req, RcodeNoError, []Answer{AAnswer([4]byte{1, 2, 3, 4}, 60)}, true)
	m, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if m.Header.Rcode() != RcodeNoError {
		t.Fatalf("rcode = %d", m.Header.Rcode())
	}
	if m.Header.Flags&0x8000 == 0 {
		t.Fatal("QR bit missing")
	}
	if len(m.Answers) != 1 {
		t.Fatalf("answers = %d", len(m.Answers))
	}
	if got := m.Answers[0].IP(); got != "1.2.3.4" {
		t.Fatalf("ip = %s", got)
	}
	if m.Answers[0].TTL != 60 {
		t.Fatalf("ttl = %d", m.Answers[0].TTL)
	}
	if m.Answers[0].Name != "example.com" {
		t.Fatalf("compressed name not resolved: %s", m.Answers[0].Name)
	}
	if len(m.Additional) != 1 || m.Additional[0].Type != TypeOPT {
		t.Fatal("OPT record missing")
	}
}

func TestDecayTTLs(t *testing.T) {
	q, _ := NewQuery(1, "x.test", TypeA)
	req, _ := Parse(q)
	raw := BuildReply(req, 0, []Answer{AAnswer([4]byte{9, 9, 9, 9}, 300)}, false)
	out := DecayTTLs(raw, 40)
	m, err := Parse(out)
	if err != nil {
		t.Fatal(err)
	}
	if m.Answers[0].TTL != 260 {
		t.Fatalf("ttl after decay = %d", m.Answers[0].TTL)
	}
	// decay beyond the ttl floors at zero
	m2, _ := Parse(DecayTTLs(raw, 10_000))
	if m2.Answers[0].TTL != 0 {
		t.Fatalf("ttl should floor at 0, got %d", m2.Answers[0].TTL)
	}
	// the original must not be mutated
	if binary.BigEndian.Uint32(raw) == 0 {
		t.Fatal("unexpected")
	}
}

func TestCompressionPointerLoop(t *testing.T) {
	// name at offset 12 is a pointer to itself → must not hang
	buf := make([]byte, 20)
	binary.BigEndian.PutUint16(buf[0:2], 1)
	binary.BigEndian.PutUint16(buf[4:6], 1)
	buf[12] = 0xC0
	buf[13] = 0x0C
	if _, _, err := ReadName(buf, 12); err == nil {
		t.Fatal("expected loop detection error")
	}
}

func TestSetTruncated(t *testing.T) {
	q, _ := NewQuery(7, "y.test", TypeA)
	req, _ := Parse(q)
	raw := SetTruncated(BuildReply(req, 0, nil, false))
	if binary.BigEndian.Uint16(raw[2:4])&0x0200 == 0 {
		t.Fatal("TC bit not set")
	}
}
