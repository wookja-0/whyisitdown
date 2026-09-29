package target

import (
	"errors"
	"testing"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name     string
		in       string
		wantURL  string
		wantHost string
		wantPort int
		wantTLS  bool
	}{
		{"bare host defaults to https", "example.com", "https://example.com/", "example.com", 443, true},
		{"explicit https", "https://example.com", "https://example.com/", "example.com", 443, true},
		{"explicit http", "http://example.com", "http://example.com/", "example.com", 80, false},
		{"host with port", "example.com:8443", "https://example.com:8443/", "example.com", 8443, true},
		{"full url", "https://example.com:8443/api/health", "https://example.com:8443/api/health", "example.com", 8443, true},
		{"http with port", "http://example.com:8080/x", "http://example.com:8080/x", "example.com", 8080, false},
		{"ipv4 literal", "127.0.0.1:8080", "https://127.0.0.1:8080/", "127.0.0.1", 8080, true},
		{"ipv6 literal", "https://[::1]:8443/", "https://[::1]:8443/", "::1", 8443, true},
		{"trailing dot", "example.com.", "https://example.com./", "example.com.", 443, true},
		{"query preserved", "https://example.com/a?b=c", "https://example.com/a?b=c", "example.com", 443, true},
		{"internal hyphens", "api--v2.example.com", "https://api--v2.example.com/", "api--v2.example.com", 443, true},
		{"underscore host", "my_host.internal", "https://my_host.internal/", "my_host.internal", 443, true},
		{"surrounding space", "  example.com  ", "https://example.com/", "example.com", 443, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Parse(tc.in)
			if err != nil {
				t.Fatalf("Parse(%q) returned %v", tc.in, err)
			}
			if got.URL.String() != tc.wantURL {
				t.Errorf("URL = %q, want %q", got.URL, tc.wantURL)
			}
			if got.Host != tc.wantHost {
				t.Errorf("Host = %q, want %q", got.Host, tc.wantHost)
			}
			if got.Port != tc.wantPort {
				t.Errorf("Port = %d, want %d", got.Port, tc.wantPort)
			}
			if got.TLS() != tc.wantTLS {
				t.Errorf("TLS() = %v, want %v", got.TLS(), tc.wantTLS)
			}
		})
	}
}

func TestParseIPLiteral(t *testing.T) {
	got, err := Parse("10.0.3.18")
	if err != nil {
		t.Fatal(err)
	}
	if got.IP == nil {
		t.Fatal("IP is nil, want the parsed literal")
	}
	if got.HostPort() != "10.0.3.18:443" {
		t.Errorf("HostPort() = %q", got.HostPort())
	}

	v6, err := Parse("https://[2606:4700::1]/")
	if err != nil {
		t.Fatal(err)
	}
	if v6.HostPort() != "[2606:4700::1]:443" {
		t.Errorf("HostPort() = %q, want brackets around the literal", v6.HostPort())
	}
}

func TestParseInvalid(t *testing.T) {
	for _, in := range []string{
		"",
		"   ",
		"ftp://example.com",
		"ssh://example.com:22",
		"https://",
		"example.com:0",
		"example.com:99999",
		"example.com:http",
		"exa mple.com",
		"example..com",
		"-example.com",
		"example-.com",
		"api.-internal.example.com",
		"https://한글.example.com",
	} {
		t.Run(in, func(t *testing.T) {
			if _, err := Parse(in); !errors.Is(err, ErrInvalid) {
				t.Errorf("Parse(%q) error = %v, want ErrInvalid", in, err)
			}
		})
	}
}
