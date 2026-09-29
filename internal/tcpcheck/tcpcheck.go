// Package tcpcheck establishes a TCP connection to the target and classifies
// the ways that can fail.
package tcpcheck

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"syscall"
	"time"

	"github.com/wookja-0/whyisitdown/internal/check"
	"github.com/wookja-0/whyisitdown/internal/target"
)

// Checker dials TCP endpoints.
type Checker struct {
	// Dialer overrides the dialer, mainly for tests.
	Dialer *net.Dialer
}

// Result carries the connection alongside its report, so later steps can reuse
// the socket instead of dialing again. Conn is nil unless Report passed.
type Result struct {
	Report check.TCP
	Conn   net.Conn
}

// Run tries each resolved address in order and stops at the first one that
// accepts a connection. Every attempt is recorded: "one of three addresses
// refuses" is exactly the kind of detail that explains flaky behaviour.
func (c Checker) Run(ctx context.Context, t *target.Target, addresses []string) Result {
	res := check.TCP{Port: t.Port}

	if len(addresses) == 0 {
		res.Status = check.StatusSkip
		return Result{Report: res}
	}

	dialer := c.Dialer
	if dialer == nil {
		dialer = &net.Dialer{}
	}

	total := time.Duration(0)
	for _, addr := range addresses {
		hostPort := net.JoinHostPort(addr, strconv.Itoa(t.Port))
		start := time.Now()
		conn, err := dialer.DialContext(ctx, "tcp", hostPort)
		elapsed := time.Since(start)
		total += elapsed

		attempt := check.TCPAttempt{Address: hostPort, Duration: check.Millis(elapsed)}
		if err != nil {
			attempt.Status = check.StatusFail
			attempt.Error = classify(hostPort, t.URL.Scheme, t.Port, err)
			res.Attempts = append(res.Attempts, attempt)
			continue
		}

		attempt.Status = check.StatusPass
		res.Attempts = append(res.Attempts, attempt)
		res.Status = check.StatusPass
		res.Address = hostPort
		res.Duration = check.Millis(elapsed)
		return Result{Report: res, Conn: conn}
	}

	res.Status = check.StatusFail
	res.Duration = check.Millis(total)
	// Report the first failure: addresses are tried in resolver order, so the
	// first one is what a normal client would have hit.
	res.Error = res.Attempts[0].Error
	return Result{Report: res}
}

// Windows reports socket errors with WSA codes that do not compare equal to
// the syscall.E* constants, so the numeric values are matched as a fallback.
const (
	wsaeTimedOut    = syscall.Errno(10060)
	wsaeConnRefused = syscall.Errno(10061)
	wsaeNetUnreach  = syscall.Errno(10051)
	wsaeHostUnreach = syscall.Errno(10065)
	wsaeConnReset   = syscall.Errno(10054)
	wsaeNetDown     = syscall.Errno(10050)
)

// classify maps a dial error to a stable kind plus operator guidance. The
// scheme is carried through so the suggested command reproduces what was
// actually attempted rather than assuming https.
func classify(hostPort, scheme string, port int, err error) *check.Error {
	e := &check.Error{Kind: check.KindUnknown, Detail: err.Error()}
	portStr := strconv.Itoa(port)

	var netErr net.Error
	switch {
	case is(err, syscall.ECONNREFUSED, wsaeConnRefused):
		e.Kind = check.KindTCPRefused
		e.Message = fmt.Sprintf("Connection to %s was refused.", hostPort)
		e.Causes = []string{
			"nothing is listening on port " + portStr + " at that address",
			"the process crashed or was never started",
			"the load balancer has no healthy target and resets immediately",
		}
	case errors.Is(err, context.DeadlineExceeded),
		is(err, syscall.ETIMEDOUT, wsaeTimedOut),
		errors.As(err, &netErr) && netErr.Timeout():
		e.Kind = check.KindTCPTimeout
		e.Message = fmt.Sprintf("Connection to %s timed out.", hostPort)
		e.Causes = []string{
			"a security group, NACL or firewall is dropping the packets",
			"the service is not listening on port " + portStr,
			"the load balancer has no healthy target",
			"asymmetric routing or a missing return route",
		}
	case is(err, syscall.EHOSTUNREACH, wsaeHostUnreach),
		is(err, syscall.ENETUNREACH, wsaeNetUnreach),
		is(err, syscall.ENETDOWN, wsaeNetDown):
		e.Kind = check.KindTCPUnreachable
		e.Message = fmt.Sprintf("No route to %s.", hostPort)
		e.Causes = []string{
			"the address is in a network this host cannot reach",
			"a VPN or peering link is down",
			"IPv6 is advertised but not actually routable from here",
		}
	case is(err, syscall.ECONNRESET, wsaeConnReset), errors.Is(err, syscall.EPIPE):
		e.Kind = check.KindTCPReset
		e.Message = fmt.Sprintf("Connection to %s was reset.", hostPort)
		e.Causes = []string{
			"the peer closed the connection during the handshake",
			"a proxy or firewall is terminating the connection",
		}
	default:
		e.Message = fmt.Sprintf("Could not connect to %s.", hostPort)
		e.Causes = []string{"the network path or the listener is unavailable"}
	}

	host, _, splitErr := net.SplitHostPort(hostPort)
	if splitErr != nil {
		host = hostPort
	}
	e.Commands = []string{
		fmt.Sprintf("nc -vz %s %s", host, portStr),
		fmt.Sprintf("curl -v --connect-timeout 5 %s://%s/", scheme, hostPort),
	}
	return e
}

// is reports whether err matches any of the given syscall errnos.
func is(err error, errnos ...syscall.Errno) bool {
	for _, e := range errnos {
		if errors.Is(err, e) {
			return true
		}
	}
	return false
}
