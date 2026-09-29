package dnscheck

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/wookja-0/whyisitdown/internal/check"
	"github.com/wookja-0/whyisitdown/internal/target"
)

func TestRunSkipsIPLiterals(t *testing.T) {
	for _, tc := range []struct {
		in       string
		wantA    []string
		wantAAAA []string
	}{
		{"10.0.3.18", []string{"10.0.3.18"}, nil},
		{"https://[2606:4700::1]/", nil, []string{"2606:4700::1"}},
	} {
		t.Run(tc.in, func(t *testing.T) {
			tg, err := target.Parse(tc.in)
			if err != nil {
				t.Fatal(err)
			}
			res := Checker{}.Run(context.Background(), tg)
			if res.Status != check.StatusSkip {
				t.Errorf("status = %q, want skip", res.Status)
			}
			if !res.Literal {
				t.Error("Literal = false")
			}
			if len(res.Addresses()) != 1 {
				t.Fatalf("Addresses() = %v, want the literal itself", res.Addresses())
			}
			if tc.wantA != nil && res.A[0] != tc.wantA[0] {
				t.Errorf("A = %v, want %v", res.A, tc.wantA)
			}
			if tc.wantAAAA != nil && res.AAAA[0] != tc.wantAAAA[0] {
				t.Errorf("AAAA = %v, want %v", res.AAAA, tc.wantAAAA)
			}
		})
	}
}

func TestClassify(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want check.ErrorKind
	}{
		{"nxdomain", &net.DNSError{Err: "no such host", IsNotFound: true}, check.KindDNSNotFound},
		{"timeout", &net.DNSError{Err: "i/o timeout", IsTimeout: true}, check.KindDNSTimeout},
		{"context deadline", context.DeadlineExceeded, check.KindDNSTimeout},
		{"servfail", &net.DNSError{Err: "server misbehaving", IsTemporary: true}, check.KindDNSServerError},
		{"unrecognised", errors.New("boom"), check.KindDNSServerError},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := classify("api.example.com", tc.err)
			if got.Kind != tc.want {
				t.Errorf("kind = %q, want %q", got.Kind, tc.want)
			}
			if got.Message == "" || len(got.Causes) == 0 || len(got.Commands) == 0 {
				t.Errorf("incomplete guidance: %+v", got)
			}
		})
	}
}

// A lookup that fails must still be reported with its own timing rather than
// an empty result.
func TestRunFailureIsReported(t *testing.T) {
	tg, err := target.Parse("this-name-does-not-exist.invalid")
	if err != nil {
		t.Fatal(err)
	}
	// A resolver pointed at a closed port fails without needing the network.
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return nil, &net.OpError{Op: "dial", Err: errors.New("refused")}
		},
	}
	res := Checker{Resolver: r}.Run(context.Background(), tg)
	if res.Status != check.StatusFail {
		t.Fatalf("status = %q, want fail", res.Status)
	}
	if res.Error == nil {
		t.Fatal("Error is nil on a failed lookup")
	}
	if res.Host != "this-name-does-not-exist.invalid" {
		t.Errorf("Host = %q", res.Host)
	}
}
