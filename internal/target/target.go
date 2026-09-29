// Package target parses the user's input into a concrete endpoint to probe,
// and redacts credentials from anything that gets printed back out.
package target

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// ErrInvalid is returned for any input that cannot be probed. Callers map it
// to the usage exit code.
var ErrInvalid = errors.New("invalid target")

// Default ports used when the input does not specify one.
const (
	DefaultHTTPPort  = 80
	DefaultHTTPSPort = 443
)

// schemeRe matches a leading URL scheme, so "example.com:8443" is not mistaken
// for the scheme "example.com".
var schemeRe = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9+.\-]*://`)

// Target is a parsed, probe-ready endpoint.
type Target struct {
	// Raw is the string the user typed.
	Raw string
	// URL is the normalised URL, with scheme, host and path filled in.
	URL *url.URL
	// Host is the hostname or IP literal, without port or brackets.
	Host string
	// Port is the resolved port number.
	Port int
	// IP is non-nil when Host is an IP literal, in which case DNS is skipped.
	IP net.IP
}

// TLS reports whether the target speaks TLS.
func (t *Target) TLS() bool { return t.URL.Scheme == "https" }

// HostPort returns host:port, bracketing IPv6 literals.
func (t *Target) HostPort() string {
	return net.JoinHostPort(t.Host, strconv.Itoa(t.Port))
}

// Display returns the target URL with credentials redacted, safe to print.
func (t *Target) Display() string { return SanitizeURL(t.URL) }

// Parse turns user input into a Target.
//
// Accepted forms include "example.com", "https://example.com",
// "example.com:8443" and "https://example.com:8443/api/health". A missing
// scheme defaults to https; a missing port defaults to the scheme's port.
func Parse(raw string) (*Target, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return nil, fmt.Errorf("%w: empty target", ErrInvalid)
	}
	if !schemeRe.MatchString(s) {
		if strings.Contains(s, "://") {
			return nil, fmt.Errorf("%w: %q", ErrInvalid, raw)
		}
		s = "https://" + s
	}

	u, err := url.Parse(s)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrInvalid, err)
	}
	switch u.Scheme {
	case "http", "https":
	default:
		return nil, fmt.Errorf("%w: unsupported scheme %q (only http and https)", ErrInvalid, u.Scheme)
	}

	host := u.Hostname()
	if host == "" {
		return nil, fmt.Errorf("%w: %q has no host", ErrInvalid, raw)
	}

	port := DefaultHTTPSPort
	if u.Scheme == "http" {
		port = DefaultHTTPPort
	}
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("%w: bad port %q", ErrInvalid, p)
		}
		port = n
	}

	if u.Path == "" {
		u.Path = "/"
	}

	t := &Target{Raw: raw, URL: u, Host: host, Port: port}
	if ip := net.ParseIP(host); ip != nil {
		t.IP = ip
	} else if err := validateHostname(host); err != nil {
		return nil, err
	}
	return t, nil
}

// validateHostname rejects names that could never resolve, so the user gets a
// usage error instead of a confusing DNS failure.
func validateHostname(h string) error {
	if len(h) > 253 {
		return fmt.Errorf("%w: hostname too long", ErrInvalid)
	}
	for _, label := range strings.Split(strings.TrimSuffix(h, "."), ".") {
		if label == "" {
			return fmt.Errorf("%w: hostname %q has an empty label", ErrInvalid, h)
		}
		if len(label) > 63 {
			return fmt.Errorf("%w: hostname label %q is too long", ErrInvalid, label)
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("%w: hostname label %q starts or ends with a hyphen", ErrInvalid, label)
		}
		for _, r := range label {
			switch {
			// Underscores are not legal in hostnames, but they exist in the
			// wild and Go's HTTP client requests them without complaint.
			// Refusing to diagnose a host that actually resolves would be the
			// worse failure for a tool whose job is to explain outages.
			case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			default:
				return fmt.Errorf("%w: hostname %q contains an invalid character %q", ErrInvalid, h, r)
			}
		}
	}
	return nil
}
