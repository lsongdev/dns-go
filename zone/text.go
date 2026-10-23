package zone

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/lsongdev/dns-go/packet"
)

// RecordText is one record in presentation form with its owner relative to
// a zone origin ("@" for the apex). It is the storage-neutral shape of
// editable zone data: config files keep String() lines, databases keep the
// fields as columns.
type RecordText struct {
	Name string
	TTL  uint32
	Type string
	Data string
}

// String renders the record as a zone-file line.
func (r RecordText) String() string {
	return fmt.Sprintf("%s %d IN %s %s", r.Name, r.TTL, r.Type, r.Data)
}

// ID is a stable identifier derived from the record's content, so the same
// record has the same ID whichever backend stores it.
func (r RecordText) ID() string {
	sum := sha256.Sum256([]byte(r.String()))
	return hex.EncodeToString(sum[:6])
}

// ParseRecordText parses one zone-file line under origin and returns it in
// canonical form: relative owner, upper-case type, normalized RDATA with
// absolute names.
func ParseRecordText(origin, line string) (RecordText, error) {
	z, err := ParseString(origin, line)
	if err != nil {
		msg := err.Error()
		if _, rest, ok := strings.Cut(msg, ": "); ok && strings.HasPrefix(msg, "line ") {
			msg = rest
		}
		return RecordText{}, fmt.Errorf("%s", msg)
	}
	if len(z.Records) != 1 {
		return RecordText{}, fmt.Errorf("expected exactly one record, got %d", len(z.Records))
	}
	return TextOf(z.Records[0], origin), nil
}

// TextOf converts a parsed record to RecordText relative to origin.
func TextOf(r packet.DNSResource, origin string) RecordText {
	h := r.Header()
	return RecordText{Name: RelativeName(h.Name, origin), TTL: h.TTL, Type: TypeString(h.Type), Data: FormatRData(r)}
}

// RelativeName returns name relative to origin: "@" for the origin itself,
// the leading labels for names inside it, and an absolute name (trailing
// dot) for anything else.
func RelativeName(name, origin string) string {
	name, origin = CanonicalName(name), CanonicalName(origin)
	switch {
	case name == origin:
		return "@"
	case origin == "":
		return name + "."
	case strings.HasSuffix(name, "."+origin):
		return strings.TrimSuffix(name, "."+origin)
	default:
		return name + "."
	}
}
