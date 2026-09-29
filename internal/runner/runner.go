// Package runner drives the checks in protocol order and assembles the report.
package runner

import (
	"context"
	"crypto/x509"
	"net"
	"time"

	"github.com/wookja-0/whyisitdown/internal/check"
	"github.com/wookja-0/whyisitdown/internal/diagnosis"
	"github.com/wookja-0/whyisitdown/internal/dnscheck"
	"github.com/wookja-0/whyisitdown/internal/httpcheck"
	"github.com/wookja-0/whyisitdown/internal/target"
	"github.com/wookja-0/whyisitdown/internal/tcpcheck"
	"github.com/wookja-0/whyisitdown/internal/tlscheck"
)

// DefaultTimeout bounds each individual step.
const DefaultTimeout = 5 * time.Second

// Options configures a run. The zero value is usable except for Version.
type Options struct {
	// Timeout bounds each step separately, not the run as a whole.
	Timeout time.Duration
	// FollowRedirects controls whether 3xx responses are followed.
	FollowRedirects bool
	// UserAgent is sent with the HTTP request.
	UserAgent string
	// Version is recorded in the report.
	Version string

	// Resolver, RootCAs and Now exist so tests can run the whole pipeline
	// against a local server without touching the network or the clock.
	Resolver *net.Resolver
	RootCAs  *x509.CertPool
	Now      func() time.Time
}

func (o Options) timeout() time.Duration {
	if o.Timeout <= 0 {
		return DefaultTimeout
	}
	return o.Timeout
}

// Run executes the pipeline. Steps that cannot run because an earlier one
// failed are reported as skipped rather than omitted, so the output always
// shows how far the request got.
func Run(ctx context.Context, t *target.Target, opts Options) check.Report {
	report := check.Report{
		SchemaVersion: check.SchemaVersion,
		Tool:          "whyisitdown",
		Version:       opts.Version,
		Target:        t.Display(),
	}
	// Steps that never run still need a status, and skip is the zero-value
	// meaning here.
	report.Checks = skippedChecks()

	start := time.Now()

	report.Checks.DNS = step(ctx, opts, func(ctx context.Context) check.DNS {
		return dnscheck.Checker{Resolver: opts.Resolver}.Run(ctx, t)
	})
	if report.Checks.DNS.Failed() {
		return finish(&report, start)
	}

	tcpRes := step(ctx, opts, func(ctx context.Context) tcpcheck.Result {
		return tcpcheck.Checker{}.Run(ctx, t, report.Checks.DNS.Addresses())
	})
	report.Checks.TCP = tcpRes.Report
	if tcpRes.Conn == nil {
		return finish(&report, start)
	}

	if !t.TLS() {
		tcpRes.Conn.Close()
	} else {
		tlsRes := step(ctx, opts, func(ctx context.Context) tlscheck.Result {
			return tlscheck.Checker{RootCAs: opts.RootCAs, Now: opts.Now}.Run(ctx, t, tcpRes.Conn)
		})
		report.Checks.TLS = tlsRes.TLS
		report.Checks.Certificate = tlsRes.Certificate
		if !tlsRes.HandshakeOK {
			return finish(&report, start)
		}
	}

	httpRes := step(ctx, opts, func(ctx context.Context) httpcheck.Result {
		return httpcheck.Checker{
			UserAgent:       opts.UserAgent,
			FollowRedirects: opts.FollowRedirects,
			PinnedAddress:   report.Checks.TCP.Address,
		}.Run(ctx, t)
	})
	report.Checks.HTTP = httpRes.HTTP
	report.Checks.Redirect = httpRes.Redirect

	return finish(&report, start)
}

// step runs one check under its own deadline. The context is cancelled as soon
// as the check returns, so no timer or dial goroutine outlives it.
func step[T any](ctx context.Context, opts Options, fn func(context.Context) T) T {
	stepCtx, cancel := context.WithTimeout(ctx, opts.timeout())
	defer cancel()
	return fn(stepCtx)
}

func skippedChecks() check.Checks {
	var c check.Checks
	c.DNS.Status = check.StatusSkip
	c.TCP.Status = check.StatusSkip
	tls := tlscheck.Skipped()
	c.TLS, c.Certificate = tls.TLS, tls.Certificate
	web := httpcheck.Skipped()
	c.HTTP, c.Redirect = web.HTTP, web.Redirect
	return c
}

func finish(r *check.Report, start time.Time) check.Report {
	r.TotalDuration = check.Millis(time.Since(start))
	r.Status = overall(r.Checks)
	r.Diagnosis = diagnosis.Evaluate(r.Checks)
	return *r
}

// overall is the worst status across the steps that actually ran. A run where
// everything was skipped after a failure still reports fail, because the
// failing step is one of them.
func overall(c check.Checks) check.Status {
	status := check.StatusPass
	for _, b := range []check.Base{
		c.DNS.Base, c.TCP.Base, c.TLS.Base, c.Certificate.Base, c.HTTP.Base, c.Redirect.Base,
	} {
		if b.Ran() {
			status = check.Worst(status, b.Status)
		}
	}
	return status
}
