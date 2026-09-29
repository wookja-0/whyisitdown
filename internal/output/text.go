// Package output renders a report for humans or for machines.
package output

import (
	"fmt"
	"io"
	"net/url"
	"strings"

	"github.com/wookja-0/whyisitdown/internal/check"
)

const divider = "────────────────────────────────────"

// TextOptions configures the terminal renderer.
type TextOptions struct {
	// Color turns ANSI escapes on.
	Color bool
	// Verbose adds the details that are usually noise: every resolved
	// address, SAN list, cipher suite and connection attempt.
	Verbose bool
}

// Text writes the human-readable report.
func Text(w io.Writer, r check.Report, opts TextOptions) error {
	t := &textWriter{w: w, p: newPalette(opts.Color), verbose: opts.Verbose}
	t.render(r)
	return t.err
}

type textWriter struct {
	w       io.Writer
	p       palette
	verbose bool
	// plaintext records whether the target itself is http, which is the only
	// reason the TLS steps are genuinely "not applicable" rather than merely
	// unreached.
	plaintext bool
	err       error
}

func (t *textWriter) printf(format string, args ...any) {
	if t.err != nil {
		return
	}
	_, t.err = fmt.Fprintf(t.w, format, args...)
}

func (t *textWriter) render(r check.Report) {
	t.plaintext = strings.HasPrefix(r.Target, "http://")
	t.printf("%s %s\n\n", t.p.wrap(t.p.cyan, "●"), t.p.wrap(t.p.bold, "WhyIsItDown"))
	t.printf("%s\n%s\n", t.p.wrap(t.p.bold, "Target"), r.Target)

	t.dns(r.Checks.DNS)
	t.tcp(r.Checks.TCP)
	t.tls(r.Checks.TLS)
	t.certificate(r.Checks.Certificate)
	t.http(r.Checks.HTTP)
	t.redirect(r.Checks.Redirect)

	t.printf("\n%s\n\n", t.p.wrap(t.p.dim, divider))
	if r.Status == check.StatusPass {
		t.printf("%s\n", t.p.wrap(t.p.green, "Everything looks good."))
	} else {
		t.summary(r.Checks)
		t.printf("\n%s\n%s\n", t.p.wrap(t.p.bold, "Diagnosis"), r.Diagnosis.Message)
		if r.Diagnosis.LikelyArea != nil {
			t.printf("\n%s\n%s\n", t.p.wrap(t.p.bold, "Likely area"),
				t.p.wrap(t.p.yellow, *r.Diagnosis.LikelyArea))
		}
	}
	t.printf("\n%s\n", t.p.wrap(t.p.dim, fmt.Sprintf("Total: %s", ms(r.TotalDuration))))
}

// section prints a step heading and returns whether the body should follow.
// Skipped steps collapse to a single dim line: they are context, not results.
func (t *textWriter) section(name string, b check.Base, skipNote string) bool {
	t.printf("\n%s\n", t.p.wrap(t.p.bold, name))
	if b.Status == check.StatusSkip {
		t.printf("%s %s\n", t.symbol(b.Status), t.p.wrap(t.p.dim, skipNote))
		return false
	}
	return true
}

func (t *textWriter) dns(d check.DNS) {
	note := "skipped"
	if d.Literal {
		note = "skipped, the target is an IP address"
	}
	if !t.section("DNS", d.Base, note) {
		return
	}
	if d.Failed() {
		t.failure(d.Error)
		return
	}
	addresses := d.Addresses()
	shown := addresses
	if !t.verbose && len(shown) > 3 {
		shown = shown[:3]
	}
	for _, a := range shown {
		t.printf("%s %s\n", t.symbol(check.StatusPass), a)
	}
	if extra := len(addresses) - len(shown); extra > 0 {
		t.printf("  %s\n", t.p.wrap(t.p.dim, fmt.Sprintf("+%d more", extra)))
	}
	if d.CNAME != "" {
		t.printf("  %s\n", t.p.wrap(t.p.dim, "CNAME "+d.CNAME))
	}
	t.printf("  %s\n", t.p.wrap(t.p.dim, ms(d.Duration)))
}

func (t *textWriter) tcp(c check.TCP) {
	if !t.section("TCP", c.Base, "not attempted") {
		return
	}
	if c.Failed() {
		for _, a := range c.Attempts {
			line := a.Address
			// Later attempts share what is left of the step's budget, so the
			// per-attempt timing is worth showing before anyone concludes that
			// every address timed out on its own.
			if t.verbose && a.Error != nil {
				line += " " + t.p.wrap(t.p.dim, fmt.Sprintf("(%s, %s)", a.Error.Kind, ms(a.Duration)))
			}
			t.printf("%s %s\n", t.symbol(a.Status), line)
		}
		t.failure(c.Error)
		return
	}
	if t.verbose && len(c.Attempts) > 1 {
		// Every address before the last one was tried and failed.
		for _, a := range c.Attempts[:len(c.Attempts)-1] {
			t.printf("%s %s %s\n", t.symbol(a.Status), a.Address, t.p.wrap(t.p.dim, "unreachable"))
		}
	}
	t.printf("%s %s\n", t.symbol(check.StatusPass), c.Address)
	t.printf("  %s\n", t.p.wrap(t.p.dim, ms(c.Duration)))
}

func (t *textWriter) tls(c check.TLS) {
	// A skipped TLS step means one of two different things, and saying the
	// wrong one tells the reader something untrue about their own target.
	note := "not attempted"
	if t.plaintext {
		note = "not applicable, the target is http"
	}
	if !t.section("TLS", c.Base, note) {
		return
	}
	if c.Version != "" {
		t.printf("%s %s\n", t.symbol(c.Status), c.Version)
		if c.ALPN != "" {
			t.printf("  %s\n", c.ALPN)
		}
		if t.verbose {
			t.printf("  %s\n", t.p.wrap(t.p.dim, c.CipherSuite))
			t.printf("  %s\n", t.p.wrap(t.p.dim, "SNI "+c.ServerName))
		}
		t.printf("  %s\n", t.p.wrap(t.p.dim, ms(c.Duration)))
	}
	if c.Failed() && c.Version == "" {
		t.failure(c.Error)
	}
}

func (t *textWriter) certificate(c check.Certificate) {
	if !t.section("Certificate", c.Base, "not inspected") {
		return
	}
	t.printf("%s %s\n", t.symbol(c.Status), c.Subject)
	t.printf("  %s\n", "Issuer: "+c.Issuer)
	t.printf("  %s\n", "Expires: "+dateOnly(c.NotAfter))
	if c.DaysRemaining != nil {
		remaining := fmt.Sprintf("Remaining: %d days", *c.DaysRemaining)
		if *c.DaysRemaining < 0 {
			remaining = fmt.Sprintf("Expired %d days ago", -*c.DaysRemaining)
		}
		t.printf("  %s\n", t.colorFor(c.Status, remaining))
	}
	if t.verbose && len(c.SANs) > 0 {
		t.printf("  %s\n", t.p.wrap(t.p.dim, "SAN: "+strings.Join(c.SANs, ", ")))
	}
	if c.Failed() && c.Error != nil {
		// An expiry is already spelled out by the lines above; anything else
		// needs its reason stated.
		if c.ExpiryLevel != "expired" {
			t.printf("\n%s %s\n", t.symbol(check.StatusFail), c.Error.Message)
		}
		t.causes(c.Error)
	}
}

func (t *textWriter) http(c check.HTTP) {
	if !t.section("HTTP", c.Base, "not attempted") {
		return
	}
	if c.StatusCode != 0 {
		t.printf("%s %s\n", t.symbol(c.Status), t.colorFor(c.Status, fmt.Sprintf("%d %s", c.StatusCode, c.StatusText)))
		t.printf("  %s\n", t.p.wrap(t.p.dim, ms(c.Duration)))
		if c.Server != "" {
			t.printf("  %s\n", t.p.wrap(t.p.dim, "Server: "+c.Server))
		}
		if t.verbose {
			t.printf("  %s\n", t.p.wrap(t.p.dim, "Proto: "+c.Proto))
			if c.ContentType != "" {
				t.printf("  %s\n", t.p.wrap(t.p.dim, "Content-Type: "+c.ContentType))
			}
			if c.ContentLength != nil {
				t.printf("  %s\n", t.p.wrap(t.p.dim, fmt.Sprintf("Content-Length: %d", *c.ContentLength)))
			}
		}
		if c.Failed() && c.Error != nil {
			t.causes(c.Error)
		}
		return
	}
	t.failure(c.Error)
}

func (t *textWriter) redirect(c check.Redirect) {
	if !t.section("Redirect", c.Base, "not attempted") {
		return
	}
	if !c.Followed {
		t.printf("%s %s\n", t.symbol(check.StatusPass), t.p.wrap(t.p.dim, "not followed (--no-redirect)"))
	} else if c.Count == 0 && c.Status == check.StatusPass {
		t.printf("%s %s\n", t.symbol(check.StatusPass), "no redirect")
		return
	} else {
		t.printf("%s %s\n", t.symbol(c.Status), fmt.Sprintf("%d %s", c.Count, plural(c.Count, "hop", "hops")))
	}
	if len(c.Hops) > 0 {
		t.printf("\n")
	}
	for i, hop := range c.Hops {
		t.printf("  %s\n", hop.URL)
		if hop.StatusCode != 0 {
			arrow := fmt.Sprintf("    ↓ %d", hop.StatusCode)
			if i == len(c.Hops)-1 && hop.Location == "" {
				t.printf("%s\n", t.p.wrap(t.p.dim, arrow))
				continue
			}
			t.printf("%s\n", arrow)
		}
	}
	if host := crossHostTLS(c.Hops); host != "" {
		t.printf("\n  %s\n", t.p.wrap(t.p.dim,
			"certificate not checked for "+host+"; the Certificate step covers the initial target"))
	}
	if c.Failed() && c.Error != nil {
		t.printf("\n%s %s\n", t.symbol(check.StatusFail), c.Error.Message)
		t.causes(c.Error)
	}
}

// crossHostTLS returns the final host when a chain ends on an HTTPS host other
// than the one it started from. That host's certificate was never verified:
// the Certificate step inspects the target, and the HTTP step deliberately
// skips verification. Saying so is cheaper than letting the reader assume a
// green Certificate line covered the whole chain.
func crossHostTLS(hops []check.Hop) string {
	if len(hops) < 2 {
		return ""
	}
	first, err := url.Parse(hops[0].URL)
	if err != nil {
		return ""
	}
	last, err := url.Parse(hops[len(hops)-1].URL)
	if err != nil {
		return ""
	}
	if last.Scheme != "https" || strings.EqualFold(first.Hostname(), last.Hostname()) {
		return ""
	}
	return last.Host
}

// failure prints a step that produced nothing but an error.
func (t *textWriter) failure(e *check.Error) {
	if e == nil {
		t.printf("%s %s\n", t.symbol(check.StatusFail), "failed")
		return
	}
	t.printf("%s %s\n", t.symbol(check.StatusFail), e.Message)
	t.causes(e)
}

func (t *textWriter) causes(e *check.Error) {
	if e == nil {
		return
	}
	if len(e.Causes) > 0 {
		t.printf("\n  %s\n", t.p.wrap(t.p.bold, "Possible causes"))
		for _, c := range e.Causes {
			t.printf("  - %s\n", c)
		}
	}
	if len(e.Commands) > 0 {
		t.printf("\n  %s\n", t.p.wrap(t.p.bold, "Try"))
		for _, c := range e.Commands {
			t.printf("    %s\n", t.p.wrap(t.p.cyan, c))
		}
	}
	if t.verbose && e.Detail != "" {
		t.printf("\n  %s\n", t.p.wrap(t.p.dim, e.Detail))
	}
}

func (t *textWriter) summary(c check.Checks) {
	t.printf("%s\n", t.p.wrap(t.p.bold, "Summary"))
	rows := []struct {
		name string
		base check.Base
		note string
	}{
		{"DNS", c.DNS.Base, summaryDNS(c.DNS)},
		{"TCP", c.TCP.Base, ""},
		{"TLS", c.TLS.Base, ""},
		{"Certificate", c.Certificate.Base, summaryCert(c.Certificate)},
		{"HTTP", c.HTTP.Base, summaryHTTP(c.HTTP)},
		{"Redirect", c.Redirect.Base, summaryRedirect(c.Redirect)},
	}
	for _, row := range rows {
		note := row.note
		if row.base.Status == check.StatusSkip {
			note = ""
		} else if note == "" {
			note = ms(row.base.Duration)
		}
		line := fmt.Sprintf("%-12s %s", row.name,
			t.colorFor(row.base.Status, fmt.Sprintf("%-4s", strings.ToUpper(string(row.base.Status)))))
		if note != "" {
			line += "  " + t.p.wrap(t.p.dim, note)
		}
		t.printf("%s\n", line)
	}
}

func summaryDNS(d check.DNS) string {
	if d.Failed() || d.Status == check.StatusSkip {
		return ""
	}
	n := len(d.Addresses())
	return fmt.Sprintf("%s, %d %s", ms(d.Duration), n, plural(n, "address", "addresses"))
}

func summaryCert(c check.Certificate) string {
	// A failure that is not about expiry needs its own words: "expires in 723
	// days" next to FAIL reads as a contradiction.
	if c.Error != nil {
		switch c.Error.Kind {
		case check.KindTLSUnknownAuthority:
			return "untrusted chain"
		case check.KindTLSHostnameMismatch:
			return "hostname mismatch"
		case check.KindCertNotYetValid:
			return "not valid yet"
		}
	}
	if c.DaysRemaining == nil {
		return ""
	}
	if *c.DaysRemaining < 0 {
		return fmt.Sprintf("expired %d days ago", -*c.DaysRemaining)
	}
	return fmt.Sprintf("expires in %d days", *c.DaysRemaining)
}

func summaryHTTP(c check.HTTP) string {
	if c.StatusCode == 0 {
		return ""
	}
	return fmt.Sprintf("%s, %d %s", ms(c.Duration), c.StatusCode, c.StatusText)
}

func summaryRedirect(c check.Redirect) string {
	switch {
	case !c.Followed:
		return "not followed"
	case c.Count == 0:
		return "no redirect"
	default:
		return fmt.Sprintf("%d %s", c.Count, plural(c.Count, "hop", "hops"))
	}
}

func (t *textWriter) symbol(s check.Status) string {
	switch s {
	case check.StatusPass:
		return t.p.wrap(t.p.green, "✓")
	case check.StatusWarn:
		return t.p.wrap(t.p.yellow, "!")
	case check.StatusFail:
		return t.p.wrap(t.p.red, "✗")
	default:
		return t.p.wrap(t.p.dim, "·")
	}
}

func (t *textWriter) colorFor(s check.Status, text string) string {
	switch s {
	case check.StatusPass:
		return t.p.wrap(t.p.green, text)
	case check.StatusWarn:
		return t.p.wrap(t.p.yellow, text)
	case check.StatusFail:
		return t.p.wrap(t.p.red, text)
	default:
		return t.p.wrap(t.p.dim, text)
	}
}

// dateOnly trims an RFC 3339 timestamp to its date, which is all that matters
// when reading an expiry at a glance.
func dateOnly(ts string) string {
	if date, _, found := strings.Cut(ts, "T"); found {
		return date
	}
	return ts
}

func ms(d check.Millis) string {
	return fmt.Sprintf("%dms", d.Duration().Milliseconds())
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
