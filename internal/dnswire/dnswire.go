// Package dnswire implements the subset of the DNS wire format (RFC 1035)
// that best-dns needs: parsing questions and resource records, building
// replies, decaying cached TTLs and decoding names with compression.
//
// It is deliberately dependency-free and allocation-light so the daemon can
// stay a single static binary.
package dnswire

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

// RR types used by the router.
const (
	TypeA     uint16 = 1
	TypeNS    uint16 = 2
	TypeCNAME uint16 = 5
	TypeSOA   uint16 = 6
	TypePTR   uint16 = 12
	TypeMX    uint16 = 15
	TypeAAAA  uint16 = 28
	TypeOPT   uint16 = 41
	TypeHTTPS uint16 = 65

	ClassINET uint16 = 1
)

// RCODEs.
const (
	RcodeNoError  = 0
	RcodeFormErr  = 1
	RcodeServFail = 2
	RcodeNXDomain = 3
	RcodeNotImpl  = 4
	RcodeRefused  = 5
)

// Header is the fixed 12-byte DNS header.
type Header struct {
	ID      uint16
	Flags   uint16
	QDCount uint16
	ANCount uint16
	NSCount uint16
	ARCount uint16
}

// ParseHeader decodes the fixed header.
func ParseHeader(b []byte) (Header, error) {
	if len(b) < 12 {
		return Header{}, errors.New("dns: short header")
	}
	return Header{
		ID:      binary.BigEndian.Uint16(b[0:2]),
		Flags:   binary.BigEndian.Uint16(b[2:4]),
		QDCount: binary.BigEndian.Uint16(b[4:6]),
		ANCount: binary.BigEndian.Uint16(b[6:8]),
		NSCount: binary.BigEndian.Uint16(b[8:10]),
		ARCount: binary.BigEndian.Uint16(b[10:12]),
	}, nil
}

// Bytes encodes the header.
func (h Header) Bytes() []byte {
	b := make([]byte, 12)
	binary.BigEndian.PutUint16(b[0:2], h.ID)
	binary.BigEndian.PutUint16(b[2:4], h.Flags)
	binary.BigEndian.PutUint16(b[4:6], h.QDCount)
	binary.BigEndian.PutUint16(b[6:8], h.ANCount)
	binary.BigEndian.PutUint16(b[8:10], h.NSCount)
	binary.BigEndian.PutUint16(b[10:12], h.ARCount)
	return b
}

// Rcode returns the response code.
func (h Header) Rcode() int { return int(h.Flags & 0x000F) }

// Question is a single DNS question.
type Question struct {
	Name  string
	Type  uint16
	Class uint16
}

// RR is a decoded resource record. Data holds raw RDATA (compression pointers
// inside RDATA are not expanded; only the record's own NAME is decoded).
type RR struct {
	Name    string
	Type    uint16
	Class   uint16
	TTL     uint32
	Data    []byte
	TTLPos  int // absolute offset of the TTL field in the source buffer
	DataPos int // absolute offset of the RDATA in the source buffer
}

// IP decodes A/AAAA RDATA.
func (r RR) IP() string {
	switch {
	case r.Type == TypeA && len(r.Data) == 4:
		return fmt.Sprintf("%d.%d.%d.%d", r.Data[0], r.Data[1], r.Data[2], r.Data[3])
	case r.Type == TypeAAAA && len(r.Data) == 16:
		var sb strings.Builder
		for i := 0; i < 16; i += 2 {
			if i > 0 {
				sb.WriteByte(':')
			}
			fmt.Fprintf(&sb, "%x", binary.BigEndian.Uint16(r.Data[i:i+2]))
		}
		return sb.String()
	}
	return ""
}

// Msg is a parsed message.
type Msg struct {
	Header     Header
	Questions  []Question
	Answers    []RR
	Authority  []RR
	Additional []RR
}

var errNameLoop = errors.New("dns: compression loop")

// ReadName decodes a (possibly compressed) name at off and returns the offset
// just past the name in the original stream.
func ReadName(buf []byte, off int) (string, int, error) {
	var sb strings.Builder
	next := -1
	visited := 0
	for {
		if off < 0 || off >= len(buf) {
			return "", 0, errors.New("dns: name out of range")
		}
		l := int(buf[off])
		if l == 0 {
			off++
			break
		}
		if l&0xC0 == 0xC0 {
			if off+1 >= len(buf) {
				return "", 0, errors.New("dns: bad pointer")
			}
			ptr := int(binary.BigEndian.Uint16(buf[off:off+2]) & 0x3FFF)
			if next < 0 {
				next = off + 2
			}
			off = ptr
			visited++
			if visited > 64 {
				return "", 0, errNameLoop
			}
			continue
		}
		if l > 63 || off+1+l > len(buf) {
			return "", 0, errors.New("dns: bad label")
		}
		if sb.Len() > 0 {
			sb.WriteByte('.')
		}
		sb.Write(buf[off+1 : off+1+l])
		off += 1 + l
		if sb.Len() > 255 {
			return "", 0, errors.New("dns: name too long")
		}
	}
	if next < 0 {
		next = off
	}
	return sb.String(), next, nil
}

// SkipName advances past a name without decoding it.
func SkipName(buf []byte, off int) (int, error) {
	for {
		if off < 0 || off >= len(buf) {
			return 0, errors.New("dns: name out of range")
		}
		l := int(buf[off])
		switch {
		case l == 0:
			return off + 1, nil
		case l&0xC0 == 0xC0:
			if off+2 > len(buf) {
				return 0, errors.New("dns: bad pointer")
			}
			return off + 2, nil
		case l > 63:
			return 0, errors.New("dns: bad label")
		default:
			if off+1+l > len(buf) {
				return 0, errors.New("dns: truncated label")
			}
			off += 1 + l
		}
	}
}

func parseRR(buf []byte, off int) (RR, int, error) {
	name, n, err := ReadName(buf, off)
	if err != nil {
		return RR{}, 0, err
	}
	if n+10 > len(buf) {
		return RR{}, 0, errors.New("dns: truncated rr")
	}
	rr := RR{
		Name:    name,
		Type:    binary.BigEndian.Uint16(buf[n : n+2]),
		Class:   binary.BigEndian.Uint16(buf[n+2 : n+4]),
		TTLPos:  n + 4,
		DataPos: n + 10,
	}
	rr.TTL = binary.BigEndian.Uint32(buf[n+4 : n+8])
	rdlen := int(binary.BigEndian.Uint16(buf[n+8 : n+10]))
	start := n + 10
	if start+rdlen > len(buf) {
		return RR{}, 0, errors.New("dns: truncated rdata")
	}
	rr.Data = buf[start : start+rdlen]
	return rr, start + rdlen, nil
}

// Parse decodes a full DNS message.
func Parse(buf []byte) (*Msg, error) {
	h, err := ParseHeader(buf)
	if err != nil {
		return nil, err
	}
	m := &Msg{Header: h}
	off := 12
	for i := 0; i < int(h.QDCount); i++ {
		name, n, err := ReadName(buf, off)
		if err != nil {
			return nil, err
		}
		if n+4 > len(buf) {
			return nil, errors.New("dns: truncated question")
		}
		m.Questions = append(m.Questions, Question{
			Name:  name,
			Type:  binary.BigEndian.Uint16(buf[n : n+2]),
			Class: binary.BigEndian.Uint16(buf[n+2 : n+4]),
		})
		off = n + 4
	}
	sections := []struct {
		count int
		dst   *[]RR
	}{
		{int(h.ANCount), &m.Answers},
		{int(h.NSCount), &m.Authority},
		{int(h.ARCount), &m.Additional},
	}
	for _, sec := range sections {
		for i := 0; i < sec.count; i++ {
			rr, next, err := parseRR(buf, off)
			if err != nil {
				return nil, err
			}
			*sec.dst = append(*sec.dst, rr)
			off = next
		}
	}
	return m, nil
}

// DecayTTLs returns a copy of raw with every record's TTL reduced by elapsed
// seconds (floored at 0). Used for cached answers. If the message cannot be
// parsed the input is returned unchanged.
func DecayTTLs(raw []byte, elapsed uint32) []byte {
	h, err := ParseHeader(raw)
	if err != nil || elapsed == 0 {
		return raw
	}
	out := make([]byte, len(raw))
	copy(out, raw)
	off := 12
	for i := 0; i < int(h.QDCount); i++ {
		n, err := SkipName(out, off)
		if err != nil || n+4 > len(out) {
			return raw
		}
		off = n + 4
	}
	for _, count := range []int{int(h.ANCount), int(h.NSCount), int(h.ARCount)} {
		for i := 0; i < count; i++ {
			rr, next, err := parseRR(out, off)
			if err != nil {
				return raw
			}
			ttl := rr.TTL
			if ttl > elapsed {
				ttl -= elapsed
			} else {
				ttl = 0
			}
			binary.BigEndian.PutUint32(out[rr.TTLPos:rr.TTLPos+4], ttl)
			off = next
		}
	}
	return out
}

// MinTTL returns the smallest TTL in the answer section (used as cache
// lifetime). It defaults to fallback when there are no answers.
func MinTTL(m *Msg, fallback uint32) uint32 {
	if len(m.Answers) == 0 {
		return fallback
	}
	min := uint32(1<<32 - 1)
	for _, rr := range m.Answers {
		if rr.Type == TypeOPT {
			continue
		}
		if rr.TTL < min {
			min = rr.TTL
		}
	}
	if min == 0 || min == 1<<32-1 {
		return fallback
	}
	return min
}

// EncodeName writes a name in uncompressed label form.
func EncodeName(name string) ([]byte, error) {
	name = strings.TrimSuffix(strings.TrimSpace(name), ".")
	if name == "" {
		return []byte{0}, nil
	}
	if len(name) > 253 {
		return nil, errors.New("dns: name too long")
	}
	out := make([]byte, 0, len(name)+2)
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 {
			return nil, fmt.Errorf("dns: bad label %q", label)
		}
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	return append(out, 0), nil
}

// NewQuery builds a simple recursive query with EDNS0 (1232 byte payload).
func NewQuery(id uint16, name string, qtype uint16) ([]byte, error) {
	q, err := EncodeName(name)
	if err != nil {
		return nil, err
	}
	b := make([]byte, 0, 12+len(q)+4+11)
	h := Header{ID: id, Flags: 0x0100, QDCount: 1, ARCount: 1}
	b = append(b, h.Bytes()...)
	b = append(b, q...)
	b = binary.BigEndian.AppendUint16(b, qtype)
	b = binary.BigEndian.AppendUint16(b, ClassINET)
	// OPT pseudo-record: root name, type 41, class = UDP size, ttl 0, rdlen 0
	b = append(b, 0)
	b = binary.BigEndian.AppendUint16(b, TypeOPT)
	b = binary.BigEndian.AppendUint16(b, 1232)
	b = binary.BigEndian.AppendUint32(b, 0)
	b = binary.BigEndian.AppendUint16(b, 0)
	return b, nil
}

// Answer is an RR to be written into a reply.
type Answer struct {
	Type uint16
	TTL  uint32
	Data []byte
}

// AAnswer builds an A record answer payload.
func AAnswer(ip [4]byte, ttl uint32) Answer {
	return Answer{Type: TypeA, TTL: ttl, Data: ip[:]}
}

// BuildReply constructs a reply to req carrying answers. It echoes the
// question with a compression pointer and appends an OPT record when the
// client sent one (or when includeOPT is true).
func BuildReply(req *Msg, rcode int, answers []Answer, includeOPT bool) []byte {
	flags := uint16(0x8000) | (req.Header.Flags & 0x0100) // QR + copy RD
	flags |= uint16(rcode) & 0x000F
	h := Header{
		ID:      req.Header.ID,
		Flags:   flags,
		QDCount: uint16(len(req.Questions)),
		ANCount: uint16(len(answers)),
	}
	if includeOPT {
		h.ARCount = 1
	}
	b := h.Bytes()
	for _, q := range req.Questions {
		name, err := EncodeName(q.Name)
		if err != nil {
			name = []byte{0}
		}
		b = append(b, name...)
		b = binary.BigEndian.AppendUint16(b, q.Type)
		b = binary.BigEndian.AppendUint16(b, q.Class)
	}
	// Compression pointer to the question name at offset 12 (only valid when
	// there is exactly one question and it starts at 12).
	ptr := func() []byte { return []byte{0xC0, 0x0C} }
	for _, a := range answers {
		if len(req.Questions) == 1 {
			b = append(b, ptr()...)
		} else {
			name, _ := EncodeName(req.Questions[0].Name)
			b = append(b, name...)
		}
		b = binary.BigEndian.AppendUint16(b, a.Type)
		b = binary.BigEndian.AppendUint16(b, ClassINET)
		b = binary.BigEndian.AppendUint32(b, a.TTL)
		b = binary.BigEndian.AppendUint16(b, uint16(len(a.Data)))
		b = append(b, a.Data...)
	}
	if includeOPT {
		b = append(b, 0)
		b = binary.BigEndian.AppendUint16(b, TypeOPT)
		b = binary.BigEndian.AppendUint16(b, 1232)
		b = binary.BigEndian.AppendUint32(b, 0)
		b = binary.BigEndian.AppendUint16(b, 0)
	}
	return b
}

// SetTruncated flips the TC bit on a raw response.
func SetTruncated(raw []byte) []byte {
	if len(raw) < 4 {
		return raw
	}
	out := make([]byte, len(raw))
	copy(out, raw)
	flags := binary.BigEndian.Uint16(out[2:4]) | 0x0200
	binary.BigEndian.PutUint16(out[2:4], flags)
	return out
}
