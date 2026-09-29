package diagnosis

import (
	"strings"
	"testing"

	"github.com/wookja-0/whyisitdown/internal/check"
)

// failed builds a Base in the failed state with the given kind.
func failed(kind check.ErrorKind) check.Base {
	return check.Base{Status: check.StatusFail, Error: &check.Error{Kind: kind}}
}

func passed() check.Base { return check.Base{Status: check.StatusPass} }

func TestEvaluateArea(t *testing.T) {
	tests := []struct {
		name     string
		checks   check.Checks
		wantArea string
		contains string
	}{
		{
			name:     "dns failure",
			checks:   check.Checks{DNS: check.DNS{Base: failed(check.KindDNSNotFound), Host: "api.example.com"}},
			wantArea: AreaDNS,
			contains: "api.example.com",
		},
		{
			name: "tcp timeout after dns pass",
			checks: check.Checks{
				DNS: check.DNS{Base: passed()},
				TCP: check.TCP{Base: failed(check.KindTCPTimeout), Port: 443},
			},
			wantArea: AreaNetwork,
			contains: "port 443",
		},
		{
			name: "tcp refused",
			checks: check.Checks{
				DNS: check.DNS{Base: passed()},
				TCP: check.TCP{Base: failed(check.KindTCPRefused), Port: 8080},
			},
			wantArea: AreaNetwork,
			contains: "refused",
		},
		{
			name: "expired certificate",
			checks: check.Checks{
				DNS:         check.DNS{Base: passed()},
				TCP:         check.TCP{Base: passed()},
				TLS:         check.TLS{Base: passed()},
				Certificate: check.Certificate{Base: failed(check.KindCertExpired)},
			},
			wantArea: AreaTLS,
			contains: "expired",
		},
		{
			name: "untrusted chain",
			checks: check.Checks{
				DNS:         check.DNS{Base: passed()},
				TCP:         check.TCP{Base: passed()},
				TLS:         check.TLS{Base: passed()},
				Certificate: check.Certificate{Base: failed(check.KindTLSUnknownAuthority)},
			},
			wantArea: AreaTLS,
			contains: "not trusted",
		},
		{
			name: "hostname mismatch",
			checks: check.Checks{
				DNS:         check.DNS{Base: passed()},
				TCP:         check.TCP{Base: passed()},
				TLS:         check.TLS{Base: passed()},
				Certificate: check.Certificate{Base: failed(check.KindTLSHostnameMismatch)},
			},
			wantArea: AreaTLS,
			contains: "hostname",
		},
		{
			name: "plaintext port",
			checks: check.Checks{
				DNS: check.DNS{Base: passed()},
				TCP: check.TCP{Base: passed()},
				TLS: check.TLS{Base: failed(check.KindTLSNotTLS)},
			},
			wantArea: AreaTLS,
			contains: "http://",
		},
		{
			name: "redirect loop",
			checks: check.Checks{
				DNS:      check.DNS{Base: passed()},
				TCP:      check.TCP{Base: passed()},
				Redirect: check.Redirect{Base: failed(check.KindRedirectLoop)},
			},
			wantArea: AreaRouting,
			contains: "loop",
		},
		{
			name: "server error",
			checks: check.Checks{
				DNS:  check.DNS{Base: passed()},
				TCP:  check.TCP{Base: passed()},
				HTTP: check.HTTP{Base: failed(check.KindHTTPServerError), StatusCode: 502, StatusText: "Bad Gateway"},
			},
			wantArea: AreaUpstream,
			contains: "502",
		},
		{
			name: "not found",
			checks: check.Checks{
				DNS:  check.DNS{Base: passed()},
				HTTP: check.HTTP{Base: failed(check.KindHTTPNotFound), StatusCode: 404, StatusText: "Not Found"},
			},
			wantArea: AreaRouting,
			contains: "404",
		},
		{
			name: "unauthorized",
			checks: check.Checks{
				DNS:  check.DNS{Base: passed()},
				HTTP: check.HTTP{Base: failed(check.KindHTTPUnauthorized), StatusCode: 401, StatusText: "Unauthorized"},
			},
			wantArea: AreaAuth,
			contains: "401",
		},
		{
			name: "rate limited",
			checks: check.Checks{
				DNS:  check.DNS{Base: passed()},
				HTTP: check.HTTP{Base: failed(check.KindHTTPClientError), StatusCode: 429, StatusText: "Too Many Requests"},
			},
			wantArea: AreaApp,
			contains: "429",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Evaluate(tc.checks)
			if got.LikelyArea == nil {
				t.Fatalf("LikelyArea is nil, want %q", tc.wantArea)
			}
			if *got.LikelyArea != tc.wantArea {
				t.Errorf("LikelyArea = %q, want %q", *got.LikelyArea, tc.wantArea)
			}
			if !strings.Contains(got.Message, tc.contains) {
				t.Errorf("Message = %q, want it to mention %q", got.Message, tc.contains)
			}
		})
	}
}

// The first failing step wins: everything after it is a consequence, not a
// second opinion.
func TestEvaluateReportsEarliestFailure(t *testing.T) {
	got := Evaluate(check.Checks{
		DNS:  check.DNS{Base: failed(check.KindDNSNotFound), Host: "x.example.com"},
		TCP:  check.TCP{Base: failed(check.KindTCPTimeout)},
		HTTP: check.HTTP{Base: failed(check.KindHTTPServerError)},
	})
	if *got.LikelyArea != AreaDNS {
		t.Errorf("LikelyArea = %q, want %q", *got.LikelyArea, AreaDNS)
	}
}

func TestEvaluateHealthy(t *testing.T) {
	got := Evaluate(check.Checks{
		DNS:  check.DNS{Base: passed()},
		TCP:  check.TCP{Base: passed()},
		HTTP: check.HTTP{Base: passed()},
	})
	if got.LikelyArea != nil {
		t.Errorf("LikelyArea = %q, want nil", *got.LikelyArea)
	}
	if got.Message != "Service is reachable." {
		t.Errorf("Message = %q", got.Message)
	}
}

func TestEvaluateExpiringCertificate(t *testing.T) {
	days := 18
	got := Evaluate(check.Checks{
		DNS:         check.DNS{Base: passed()},
		TCP:         check.TCP{Base: passed()},
		Certificate: check.Certificate{Base: check.Base{Status: check.StatusWarn}, DaysRemaining: &days},
		HTTP:        check.HTTP{Base: passed()},
	})
	if got.LikelyArea != nil {
		t.Errorf("LikelyArea = %q, want nil: nothing is broken yet", *got.LikelyArea)
	}
	if !strings.Contains(got.Message, "18 days") {
		t.Errorf("Message = %q, want the remaining days", got.Message)
	}
}
