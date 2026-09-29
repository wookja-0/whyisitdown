// Package check defines the data model shared by every diagnostic step.
//
// Checkers produce these types, the diagnosis engine reads them, and the
// renderers format them. Keeping the model in its own package is what lets the
// checkers stay unaware of each other and of how results are displayed.
package check

import (
	"encoding/json"
	"time"
)

// SchemaVersion is the version of the --json document. It is incremented only
// when an existing field changes meaning or disappears; adding new fields does
// not bump it, so consumers can pin on a major-style check.
const SchemaVersion = 1

// Status is the outcome of a single diagnostic step.
type Status string

const (
	// StatusPass means the step completed and found nothing wrong.
	StatusPass Status = "pass"
	// StatusWarn means the step succeeded but something deserves attention
	// (an expiring certificate, for example). WARN never fails the run.
	StatusWarn Status = "warn"
	// StatusFail means the step could not complete or found a hard problem.
	StatusFail Status = "fail"
	// StatusSkip means the step did not run, usually because an earlier one
	// failed or because it does not apply (TLS on a plain HTTP target).
	StatusSkip Status = "skip"
)

// Millis is a duration that serialises to whole milliseconds, so JSON
// consumers never have to parse Go's duration strings or nanosecond integers.
type Millis time.Duration

// Duration returns the underlying duration.
func (m Millis) Duration() time.Duration { return time.Duration(m) }

// MarshalJSON implements json.Marshaler.
func (m Millis) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(m).Milliseconds())
}

// UnmarshalJSON implements json.Unmarshaler so reports can be round-tripped.
func (m *Millis) UnmarshalJSON(b []byte) error {
	var ms int64
	if err := json.Unmarshal(b, &ms); err != nil {
		return err
	}
	*m = Millis(time.Duration(ms) * time.Millisecond)
	return nil
}

// ErrorKind is a stable identifier for a failure mode.
//
// Checkers classify errors once, at the point where the real error value is
// still available (via errors.Is / errors.As). Everything downstream switches
// on the kind instead of matching error strings, and the values are part of
// the JSON contract.
type ErrorKind string

const (
	KindUnknown ErrorKind = "unknown"

	KindDNSNotFound    ErrorKind = "dns_not_found"    // NXDOMAIN / no such host
	KindDNSNoAddress   ErrorKind = "dns_no_address"   // name exists, no A/AAAA
	KindDNSTimeout     ErrorKind = "dns_timeout"      // resolver did not answer
	KindDNSServerError ErrorKind = "dns_server_error" // SERVFAIL, resolver down

	KindTCPRefused     ErrorKind = "tcp_refused"
	KindTCPTimeout     ErrorKind = "tcp_timeout"
	KindTCPUnreachable ErrorKind = "tcp_unreachable"
	KindTCPReset       ErrorKind = "tcp_reset"

	KindTLSTimeout          ErrorKind = "tls_timeout"
	KindTLSHandshake        ErrorKind = "tls_handshake_failure"
	KindTLSUnknownAuthority ErrorKind = "tls_unknown_authority"
	KindTLSHostnameMismatch ErrorKind = "tls_hostname_mismatch"
	KindTLSNotTLS           ErrorKind = "tls_not_tls" // plaintext answer on a TLS port

	KindCertExpired     ErrorKind = "cert_expired"
	KindCertNotYetValid ErrorKind = "cert_not_yet_valid"

	KindHTTPTimeout      ErrorKind = "http_timeout"
	KindHTTPClientError  ErrorKind = "http_client_error" // 4xx
	KindHTTPServerError  ErrorKind = "http_server_error" // 5xx
	KindHTTPUnauthorized ErrorKind = "http_unauthorized" // 401 / 403
	KindHTTPNotFound     ErrorKind = "http_not_found"    // 404
	KindHTTPProtocol     ErrorKind = "http_protocol"     // malformed response
	KindRedirectLoop     ErrorKind = "redirect_loop"
	KindRedirectTooMany  ErrorKind = "redirect_too_many"
)

// Error is a classified failure, carrying the operator-facing context that the
// checker is in the best position to know.
type Error struct {
	Kind ErrorKind `json:"kind"`
	// Message is a single human-readable sentence.
	Message string `json:"message"`
	// Detail is the underlying error text, kept for --verbose and JSON.
	Detail string `json:"detail,omitempty"`
	// Causes lists the plausible explanations, most likely first.
	Causes []string `json:"causes,omitempty"`
	// Commands suggests what to run next to narrow it down further.
	Commands []string `json:"commands,omitempty"`
}

// Base holds the fields every check result has in common.
type Base struct {
	Status   Status `json:"status"`
	Duration Millis `json:"duration_ms"`
	Error    *Error `json:"error,omitempty"`
}

// Failed reports whether the step ended in a hard failure.
func (b Base) Failed() bool { return b.Status == StatusFail }

// Ran reports whether the step actually executed.
func (b Base) Ran() bool { return b.Status != StatusSkip }

// DNS is the result of name resolution.
type DNS struct {
	Base
	// Host is the name that was looked up. Empty when the target was a
	// literal IP address, in which case the step is skipped.
	Host string `json:"host,omitempty"`
	// Literal is true when the target was already an IP address.
	Literal bool `json:"literal_ip"`
	// A and AAAA are the resolved addresses, split by family.
	A    []string `json:"a,omitempty"`
	AAAA []string `json:"aaaa,omitempty"`
	// CNAME is the canonical name, when the resolver exposes one.
	CNAME string `json:"cname,omitempty"`
}

// Addresses returns every resolved address, IPv4 first.
func (d DNS) Addresses() []string {
	out := make([]string, 0, len(d.A)+len(d.AAAA))
	out = append(out, d.A...)
	out = append(out, d.AAAA...)
	return out
}

// TCPAttempt is one connection attempt against one address.
type TCPAttempt struct {
	Address  string `json:"address"`
	Status   Status `json:"status"`
	Duration Millis `json:"duration_ms"`
	Error    *Error `json:"error,omitempty"`
}

// TCP is the result of establishing a connection.
type TCP struct {
	Base
	Port int `json:"port"`
	// Address is the endpoint that accepted the connection, if any.
	Address string `json:"address,omitempty"`
	// Attempts records every address tried, in order.
	Attempts []TCPAttempt `json:"attempts,omitempty"`
}

// TLS is the result of the TLS handshake.
type TLS struct {
	Base
	Version     string `json:"version,omitempty"`
	CipherSuite string `json:"cipher_suite,omitempty"`
	ALPN        string `json:"alpn,omitempty"`
	ServerName  string `json:"server_name,omitempty"`
}

// Certificate describes the leaf certificate presented by the server.
//
// It is populated even when verification fails: knowing which certificate was
// rejected is usually the whole point of looking.
type Certificate struct {
	Base
	Subject       string   `json:"subject,omitempty"`
	Issuer        string   `json:"issuer,omitempty"`
	SANs          []string `json:"sans,omitempty"`
	NotBefore     string   `json:"not_before,omitempty"`
	NotAfter      string   `json:"not_after,omitempty"`
	DaysRemaining *int     `json:"days_remaining,omitempty"`
	// ExpiryLevel is one of ok, warn, critical, expired. It is derived from
	// DaysRemaining using the thresholds in package tlscheck.
	ExpiryLevel string `json:"expiry_level,omitempty"`
	ChainLength int    `json:"chain_length,omitempty"`
	SelfSigned  bool   `json:"self_signed,omitempty"`
}

// HTTP is the result of the final HTTP response, after redirects.
type HTTP struct {
	Base
	// URL is the sanitised URL the final response came from.
	URL           string `json:"url,omitempty"`
	StatusCode    int    `json:"status_code,omitempty"`
	StatusText    string `json:"status_text,omitempty"`
	Proto         string `json:"proto,omitempty"`
	Server        string `json:"server,omitempty"`
	ContentType   string `json:"content_type,omitempty"`
	ContentLength *int64 `json:"content_length,omitempty"`
}

// Hop is one step of a redirect chain.
type Hop struct {
	// URL is the sanitised URL that was requested.
	URL string `json:"url"`
	// StatusCode is the response that URL returned.
	StatusCode int `json:"status_code"`
	// Location is the sanitised target of the redirect, empty on the last hop.
	Location string `json:"location,omitempty"`
}

// Redirect is the result of following the redirect chain.
type Redirect struct {
	Base
	// Followed is false when redirect following was disabled.
	Followed bool `json:"followed"`
	// Hops includes the initial request and every redirect that followed it.
	Hops []Hop `json:"hops,omitempty"`
	// Count is the number of redirects, i.e. len(Hops)-1 for a complete chain.
	Count int `json:"count"`
}

// Checks groups the per-step results. Every field is always present, including
// skipped steps, so consumers can rely on the keys existing.
type Checks struct {
	DNS         DNS         `json:"dns"`
	TCP         TCP         `json:"tcp"`
	TLS         TLS         `json:"tls"`
	Certificate Certificate `json:"certificate"`
	HTTP        HTTP        `json:"http"`
	Redirect    Redirect    `json:"redirect"`
}

// Diagnosis is the rule-based conclusion drawn from the checks.
type Diagnosis struct {
	// Message states what happened, in one or two sentences.
	Message string `json:"message"`
	// LikelyArea names the layer worth investigating first. It is null when
	// nothing failed.
	LikelyArea *string `json:"likely_area"`
}

// Report is the complete result of one run and the root of the JSON document.
type Report struct {
	SchemaVersion int       `json:"schema_version"`
	Tool          string    `json:"tool"`
	Version       string    `json:"version"`
	Target        string    `json:"target"`
	Status        Status    `json:"status"`
	TotalDuration Millis    `json:"total_duration_ms"`
	Checks        Checks    `json:"checks"`
	Diagnosis     Diagnosis `json:"diagnosis"`
}

// Worst returns the more severe of two statuses, ordered fail > warn > pass > skip.
func Worst(a, b Status) Status {
	if severity(a) >= severity(b) {
		return a
	}
	return b
}

func severity(s Status) int {
	switch s {
	case StatusFail:
		return 3
	case StatusWarn:
		return 2
	case StatusPass:
		return 1
	default:
		return 0
	}
}
