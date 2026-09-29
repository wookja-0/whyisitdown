package target

import "testing"

func TestSanitize(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"nothing to redact", "https://example.com/health?page=2", "https://example.com/health?page=2"},
		{"basic auth", "https://user:hunter2@example.com/", "https://REDACTED:REDACTED@example.com/"},
		{"username only", "https://user@example.com/", "https://REDACTED@example.com/"},
		{"token query", "https://example.com/?token=abc123", "https://example.com/?token=REDACTED"},
		{"api key query", "https://example.com/?X-Api-Key=abc&page=2", "https://example.com/?X-Api-Key=REDACTED&page=2"},
		{"signature query", "https://example.com/o?Signature=xyz&Expires=1", "https://example.com/o?Signature=REDACTED&Expires=1"},
		{"order preserved", "https://example.com/?z=1&password=p&a=2", "https://example.com/?z=1&password=REDACTED&a=2"},
		{"valueless param", "https://example.com/?debug", "https://example.com/?debug"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Parse(tc.in)
			if err != nil {
				t.Fatal(err)
			}
			if display := got.Display(); display != tc.want {
				t.Errorf("Display() = %q, want %q", display, tc.want)
			}
		})
	}
}

func TestSanitizeRawURL(t *testing.T) {
	if got := SanitizeRawURL("https://example.com/cb?code=1&access_token=secret"); got != "https://example.com/cb?code=1&access_token=REDACTED" {
		t.Errorf("SanitizeRawURL() = %q", got)
	}
	if got := SanitizeRawURL("/relative?session=abc"); got != "/relative?session=REDACTED" {
		t.Errorf("SanitizeRawURL() = %q", got)
	}
}
