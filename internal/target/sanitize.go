package target

import (
	"net/url"
	"strings"
)

// redacted replaces any value we refuse to print.
const redacted = "REDACTED"

// sensitiveKeys are query-parameter name fragments whose values are hidden.
// Matching is a case-insensitive substring test, so "X-Api-Key" and
// "access_token" are both covered. Over-redacting is the safe direction here.
var sensitiveKeys = []string{
	"apikey", "api_key", "auth", "credential", "key", "passwd",
	"password", "pwd", "secret", "session", "sig", "signature", "token",
}

// SanitizeURL renders a URL with credentials removed: userinfo is stripped and
// the values of sensitive query parameters are replaced.
//
// The original URL is never modified, and requests are always made with the
// real values; only what we print or serialise goes through here.
func SanitizeURL(u *url.URL) string {
	if u == nil {
		return ""
	}
	c := *u
	if c.User != nil {
		if _, hasPassword := c.User.Password(); hasPassword {
			c.User = url.UserPassword(redacted, redacted)
		} else {
			c.User = url.User(redacted)
		}
	}
	if c.RawQuery != "" {
		c.RawQuery = sanitizeQuery(c.RawQuery)
	}
	return c.String()
}

// SanitizeRawURL is SanitizeURL for a string that may not parse, such as a
// Location header echoed back by a server.
func SanitizeRawURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		// Unparseable: show the part before any query rather than guess.
		if i := strings.IndexByte(raw, '?'); i >= 0 {
			return raw[:i] + "?" + redacted
		}
		return raw
	}
	return SanitizeURL(u)
}

// sanitizeQuery rewrites sensitive values while preserving parameter order,
// which url.Values.Encode would sort away.
func sanitizeQuery(rawQuery string) string {
	var b strings.Builder
	for i, pair := range strings.Split(rawQuery, "&") {
		if i > 0 {
			b.WriteByte('&')
		}
		key, _, hasValue := strings.Cut(pair, "=")
		if !hasValue {
			b.WriteString(pair)
			continue
		}
		b.WriteString(key)
		b.WriteByte('=')
		if decoded, err := url.QueryUnescape(key); err == nil && isSensitive(decoded) {
			b.WriteString(redacted)
		} else if isSensitive(key) {
			b.WriteString(redacted)
		} else {
			_, value, _ := strings.Cut(pair, "=")
			b.WriteString(value)
		}
	}
	return b.String()
}

func isSensitive(key string) bool {
	k := strings.ToLower(key)
	for _, s := range sensitiveKeys {
		if strings.Contains(k, s) {
			return true
		}
	}
	return false
}
