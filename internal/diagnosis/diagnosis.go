// Package diagnosis turns a set of check results into one sentence about what
// is wrong and one label for where to look first.
//
// Every rule is a plain switch over the classified error kinds produced by the
// checkers. There is no scoring, no heuristics on error strings and no model
// call: the same input always yields the same conclusion.
package diagnosis

import (
	"fmt"

	"github.com/wookja-0/whyisitdown/internal/check"
)

// Areas reported as the place to start investigating.
const (
	AreaDNS      = "DNS"
	AreaNetwork  = "Network / Firewall / Load Balancer"
	AreaTLS      = "TLS / Certificate"
	AreaRouting  = "Application / Routing"
	AreaUpstream = "Application / Upstream"
	AreaAuth     = "Authentication / Authorization"
	AreaApp      = "Application"
)

// Evaluate walks the checks in protocol order and reports on the first one
// that failed, because everything after it is a consequence.
func Evaluate(c check.Checks) check.Diagnosis {
	switch {
	case c.DNS.Failed():
		return area(dnsMessage(c.DNS), AreaDNS)
	case c.TCP.Failed():
		return area(tcpMessage(c.TCP), AreaNetwork)
	case c.TLS.Failed():
		return area(tlsMessage(c.TLS), AreaTLS)
	case c.Certificate.Failed():
		return area(certificateMessage(c.Certificate), AreaTLS)
	case c.Redirect.Failed():
		return area(redirectMessage(c.Redirect), AreaRouting)
	case c.HTTP.Failed():
		msg, a := httpMessage(c.HTTP)
		return area(msg, a)
	}

	// Nothing failed. Certificate expiry is the only warning worth a sentence
	// of its own; it does not name an area because nothing is broken yet.
	if c.Certificate.Status == check.StatusWarn && c.Certificate.DaysRemaining != nil {
		return check.Diagnosis{Message: fmt.Sprintf(
			"Service is reachable, but the TLS certificate expires in %d days.", *c.Certificate.DaysRemaining)}
	}
	return check.Diagnosis{Message: "Service is reachable."}
}

func area(message, likely string) check.Diagnosis {
	return check.Diagnosis{Message: message, LikelyArea: &likely}
}

func dnsMessage(d check.DNS) string {
	switch kindOf(d.Base) {
	case check.KindDNSNotFound:
		return fmt.Sprintf("%s does not resolve: the DNS record does not exist.", d.Host)
	case check.KindDNSNoAddress:
		return fmt.Sprintf("%s exists in DNS but has no A or AAAA record.", d.Host)
	case check.KindDNSTimeout:
		return fmt.Sprintf("DNS resolution for %s timed out, so nothing else could be tested.", d.Host)
	default:
		return fmt.Sprintf("DNS resolution for %s failed, so nothing else could be tested.", d.Host)
	}
}

func tcpMessage(t check.TCP) string {
	const prefix = "DNS resolution succeeded, but "
	switch kindOf(t.Base) {
	case check.KindTCPRefused:
		return prefix + fmt.Sprintf("port %d refused the connection: nothing is listening there.", t.Port)
	case check.KindTCPTimeout:
		return prefix + fmt.Sprintf("the TCP connection to port %d timed out.", t.Port)
	case check.KindTCPUnreachable:
		return prefix + "the resolved address is not routable from here."
	default:
		return prefix + fmt.Sprintf("the TCP connection to port %d failed.", t.Port)
	}
}

func tlsMessage(t check.TLS) string {
	const prefix = "The TCP connection succeeded, but "
	switch kindOf(t.Base) {
	case check.KindTLSNotTLS:
		return prefix + "the port does not speak TLS. Try the same target with http://."
	case check.KindTLSTimeout:
		return prefix + "the TLS handshake timed out."
	default:
		return prefix + "the TLS handshake failed."
	}
}

func certificateMessage(c check.Certificate) string {
	switch kindOf(c.Base) {
	case check.KindCertExpired:
		return "The connection works, but the TLS certificate has expired."
	case check.KindCertNotYetValid:
		return "The connection works, but the TLS certificate is not valid yet."
	case check.KindTLSHostnameMismatch:
		return "The connection works, but the certificate does not cover this hostname."
	case check.KindTLSUnknownAuthority:
		return "The connection works, but the certificate chain is not trusted."
	default:
		return "The connection works, but the certificate could not be verified."
	}
}

func redirectMessage(r check.Redirect) string {
	switch kindOf(r.Base) {
	case check.KindRedirectLoop:
		return "The service answers, but its redirects loop indefinitely."
	case check.KindRedirectTooMany:
		return "The service answers, but the redirect chain never terminates."
	default:
		return "The service answers, but a redirect could not be followed."
	}
}

func httpMessage(h check.HTTP) (string, string) {
	const prefix = "The connection succeeded, but "
	switch kindOf(h.Base) {
	case check.KindHTTPServerError:
		return prefix + fmt.Sprintf("the application answered %d %s.", h.StatusCode, h.StatusText), AreaUpstream
	case check.KindHTTPNotFound:
		return prefix + fmt.Sprintf("the requested path returned %d %s.", h.StatusCode, h.StatusText), AreaRouting
	case check.KindHTTPUnauthorized:
		return prefix + fmt.Sprintf("the request was rejected with %d %s.", h.StatusCode, h.StatusText), AreaAuth
	case check.KindHTTPClientError:
		return prefix + fmt.Sprintf("the request was rejected with %d %s.", h.StatusCode, h.StatusText), AreaApp
	case check.KindHTTPTimeout:
		return prefix + "the application never sent a response.", AreaUpstream
	default:
		return prefix + "the HTTP exchange failed.", AreaUpstream
	}
}

func kindOf(b check.Base) check.ErrorKind {
	if b.Error == nil {
		return check.KindUnknown
	}
	return b.Error.Kind
}
