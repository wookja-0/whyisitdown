// Package tlscheck performs the TLS handshake and inspects the certificate the
// server presents.
//
// Verification is done explicitly rather than by the handshake itself, so that
// a rejected certificate can still be reported in full. Being told only
// "certificate verify failed" is what sends people to openssl s_client.
package tlscheck

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/wookja-0/whyisitdown/internal/check"
	"github.com/wookja-0/whyisitdown/internal/target"
)

// Certificate expiry thresholds, in days.
const (
	// WarnDays is when an expiry starts being reported as WARN.
	WarnDays = 30
	// CriticalDays is when it is reported as WARN with a critical level.
	CriticalDays = 7
)

// Expiry levels reported in ExpiryLevel.
const (
	LevelOK       = "ok"
	LevelWarn     = "warn"
	LevelCritical = "critical"
	LevelExpired  = "expired"
)

// Checker runs the handshake.
type Checker struct {
	// RootCAs overrides the system trust store, mainly for tests.
	RootCAs *x509.CertPool
	// Now overrides the clock used for expiry maths, mainly for tests.
	Now func() time.Time
}

// Result holds both reports produced by the single handshake.
type Result struct {
	TLS         check.TLS
	Certificate check.Certificate
	// HandshakeOK reports whether the transport came up, regardless of whether
	// the certificate passed verification. The HTTP step still runs when it is
	// true, so an expired certificate does not hide the application's answer.
	HandshakeOK bool
}

func (c Checker) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// Skipped returns the pair of results for a target that does not use TLS.
func Skipped() Result {
	var r Result
	r.TLS.Status = check.StatusSkip
	r.Certificate.Status = check.StatusSkip
	return r
}

// Run performs the handshake over conn, which it takes ownership of and
// closes. conn must be a freshly established connection to the target.
func (c Checker) Run(ctx context.Context, t *target.Target, conn net.Conn) Result {
	res := Result{}
	res.TLS.ServerName = t.Host

	cfg := &tls.Config{
		ServerName: t.Host,
		// The handshake must not fail on an untrusted or expired certificate:
		// verification happens below, where the certificate is still readable.
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2", "http/1.1"},
	}
	tlsConn := tls.Client(conn, cfg)
	defer tlsConn.Close()

	// Handshake latency is measured with the real clock; c.now() exists only
	// so tests can move the certificate validity window.
	start := time.Now()
	err := tlsConn.HandshakeContext(ctx)
	res.TLS.Duration = check.Millis(time.Since(start))
	if err != nil {
		res.TLS.Status = check.StatusFail
		res.TLS.Error = classifyHandshake(t.Host, t.Port, err)
		res.Certificate.Status = check.StatusSkip
		return res
	}

	state := tlsConn.ConnectionState()
	res.HandshakeOK = true
	res.TLS.Status = check.StatusPass
	res.TLS.Version = tls.VersionName(state.Version)
	res.TLS.CipherSuite = tls.CipherSuiteName(state.CipherSuite)
	res.TLS.ALPN = state.NegotiatedProtocol

	// The certificate is reported separately: the TLS line describes the
	// transport, which came up, and the Certificate line describes trust,
	// which is a different question with a different fix.
	res.Certificate = c.inspect(t.Host, t.Port, state)
	return res
}

// inspect fills in the certificate report and verifies the chain.
func (c Checker) inspect(host string, port int, state tls.ConnectionState) check.Certificate {
	res := check.Certificate{}
	if len(state.PeerCertificates) == 0 {
		res.Status = check.StatusFail
		res.Error = &check.Error{
			Kind:    check.KindTLSHandshake,
			Message: "The server did not present a certificate.",
			Causes:  []string{"an anonymous or PSK cipher suite was negotiated"},
		}
		return res
	}

	leaf := state.PeerCertificates[0]
	now := c.now()
	res.Subject = nameOf(leaf.Subject.CommonName, leaf.Subject.Organization, "(no subject)")
	res.Issuer = nameOf(leaf.Issuer.CommonName, leaf.Issuer.Organization, "(unknown issuer)")
	res.SANs = sans(leaf)
	res.NotBefore = leaf.NotBefore.UTC().Format(time.RFC3339)
	res.NotAfter = leaf.NotAfter.UTC().Format(time.RFC3339)
	res.ChainLength = len(state.PeerCertificates)
	res.SelfSigned = len(state.PeerCertificates) == 1 && leaf.Subject.String() == leaf.Issuer.String()

	days := int(leaf.NotAfter.Sub(now).Hours() / 24)
	res.DaysRemaining = &days

	verifyErr := c.verify(host, state, now)
	if verifyErr != nil {
		res.Status = check.StatusFail
		res.Error = classifyVerify(host, port, res, verifyErr)
		if res.Error.Kind == check.KindCertExpired {
			res.ExpiryLevel = LevelExpired
		}
		return res
	}

	res.Status, res.ExpiryLevel = expiryStatus(days)
	if res.Status == check.StatusWarn {
		res.Error = &check.Error{
			Kind:    check.KindUnknown,
			Message: fmt.Sprintf("The certificate expires in %d days (%s).", days, res.NotAfter),
			Causes:  []string{"automatic renewal may have stopped working"},
		}
	}
	return res
}

// verify runs the chain and hostname checks the handshake skipped.
func (c Checker) verify(host string, state tls.ConnectionState, now time.Time) error {
	intermediates := x509.NewCertPool()
	for _, cert := range state.PeerCertificates[1:] {
		intermediates.AddCert(cert)
	}
	_, err := state.PeerCertificates[0].Verify(x509.VerifyOptions{
		DNSName:       host,
		Roots:         c.RootCAs,
		Intermediates: intermediates,
		CurrentTime:   now,
	})
	return err
}

// expiryStatus applies the expiry thresholds.
//
// Only an already-expired certificate fails: one that expires next week still
// serves traffic today, and failing the run would make --json unusable as a
// health gate. The level field carries the urgency instead.
func expiryStatus(days int) (check.Status, string) {
	switch {
	case days < 0:
		return check.StatusFail, LevelExpired
	case days < CriticalDays:
		return check.StatusWarn, LevelCritical
	case days < WarnDays:
		return check.StatusWarn, LevelWarn
	default:
		return check.StatusPass, LevelOK
	}
}

func classifyHandshake(host string, port int, err error) *check.Error {
	e := &check.Error{Kind: check.KindTLSHandshake, Detail: err.Error()}
	e.Commands = []string{sClient(host, port)}

	var recordErr tls.RecordHeaderError
	var netErr net.Error
	switch {
	case errors.Is(err, context.DeadlineExceeded),
		errors.As(err, &netErr) && netErr.Timeout():
		e.Kind = check.KindTLSTimeout
		e.Message = "The TLS handshake timed out."
		e.Causes = []string{
			"the port accepts connections but never completes the handshake",
			"a middlebox is intercepting or dropping the handshake",
			"the server is overloaded",
		}
	case errors.As(err, &recordErr):
		e.Kind = check.KindTLSNotTLS
		e.Message = "The server answered, but not with TLS."
		e.Causes = []string{
			"the port serves plain HTTP and the target should use http://",
			"another protocol is listening on this port",
		}
	default:
		e.Message = "The TLS handshake failed."
		e.Causes = []string{
			"no TLS version or cipher suite in common with the server",
			"the server requires a client certificate (mTLS)",
			"the server rejected the SNI name " + host,
		}
	}
	return e
}

func classifyVerify(host string, port int, cert check.Certificate, err error) *check.Error {
	e := &check.Error{Kind: check.KindTLSHandshake, Detail: err.Error()}
	e.Commands = []string{sClient(host, port)}

	var invalid x509.CertificateInvalidError
	var unknownAuthority x509.UnknownAuthorityError
	var hostnameErr x509.HostnameError
	switch {
	case errors.As(err, &invalid) && invalid.Reason == x509.Expired:
		e.Kind = check.KindCertExpired
		if cert.DaysRemaining != nil && *cert.DaysRemaining < 0 {
			e.Message = fmt.Sprintf("The certificate expired %d days ago (%s).", -*cert.DaysRemaining, cert.NotAfter)
		} else {
			e.Message = fmt.Sprintf("The certificate is not valid at this time (valid %s to %s).", cert.NotBefore, cert.NotAfter)
			e.Kind = check.KindCertNotYetValid
		}
		e.Causes = []string{
			"certificate renewal failed or was never automated",
			"the renewed certificate was issued but not deployed to this server",
			"the local clock is wrong",
		}
	case errors.As(err, &hostnameErr):
		e.Kind = check.KindTLSHostnameMismatch
		e.Message = fmt.Sprintf("The certificate is not valid for %s.", host)
		e.Causes = []string{
			"the request reached the wrong virtual host or load balancer",
			"the hostname is missing from the certificate's SAN list",
			"a default or placeholder certificate is being served",
		}
	case errors.As(err, &unknownAuthority):
		e.Kind = check.KindTLSUnknownAuthority
		if cert.SelfSigned {
			e.Message = "The certificate is self-signed and not trusted."
			e.Causes = []string{
				"the server is serving its own certificate instead of one issued by a CA",
				"a placeholder certificate was left in place after provisioning",
			}
			break
		}
		e.Message = "The certificate was issued by an authority this machine does not trust."
		e.Causes = []string{
			"the server is not sending its intermediate certificates",
			"the certificate is signed by an internal CA that is not installed here",
		}
	default:
		e.Message = "The certificate could not be verified."
		e.Causes = []string{"the certificate chain is incomplete or malformed"}
	}
	return e
}

// sClient builds the openssl command for this exact endpoint. Suggesting :443
// for a target on another port sends the reader somewhere they did not ask
// about, which is worse than suggesting nothing.
func sClient(host string, port int) string {
	return fmt.Sprintf("openssl s_client -connect %s -servername %s",
		net.JoinHostPort(host, strconv.Itoa(port)), host)
}

func nameOf(commonName string, organization []string, fallback string) string {
	if commonName != "" {
		return commonName
	}
	if len(organization) > 0 {
		return strings.Join(organization, ", ")
	}
	return fallback
}

func sans(cert *x509.Certificate) []string {
	out := make([]string, 0, len(cert.DNSNames)+len(cert.IPAddresses))
	out = append(out, cert.DNSNames...)
	for _, ip := range cert.IPAddresses {
		out = append(out, ip.String())
	}
	return out
}
