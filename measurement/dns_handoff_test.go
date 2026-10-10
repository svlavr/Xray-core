package measurement

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/miekg/dns"
)

func TestDNSResponseHandoffPreservesCancellationAndWireFacts(t *testing.T) {
	query := new(dns.Msg)
	query.SetQuestion("fixture.invalid.", dns.TypeA)
	response := new(dns.Msg)
	response.SetReply(query)
	wire, err := response.Pack()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		wire  []byte
		valid bool
	}{
		{"valid", wire, true},
		{"partial", wire[:len(wire)-1], false},
		{"invalid", wire[:8], false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// The worker's bytes are already queued before caller cancellation.
			// Exercise the actual parser/handoff boundary deterministically.
			queued := append([]byte(nil), tc.wire...)
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			message, err := parseDNSResponse(ctx, queued, query, DNSUDP)
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("queued DNS result hid cancellation: %v", err)
			}
			if tc.valid {
				if message == nil || message.Id != query.Id || errors.Is(err, ErrDNSResponse) {
					t.Fatalf("valid response fact lost at cancelled handoff: %+v %v", message, err)
				}
			} else if message != nil || !errors.Is(err, ErrDNSResponse) {
				t.Fatalf("real parsing error lost at cancelled handoff: %+v %v", message, err)
			}
			if !bytes.Equal(queued, tc.wire) {
				t.Fatal("raw wire changed during handoff")
			}
		})
	}
}
