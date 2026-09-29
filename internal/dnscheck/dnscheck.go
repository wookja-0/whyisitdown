// Package dnscheck resolves the target hostname and classifies resolver
// failures.
package dnscheck

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/wookja-0/whyisitdown/internal/check"
	"github.com/wookja-0/whyisitdown/internal/target"
)

// Checker resolves hostnames. The zero value uses the system resolver.
type Checker struct {
	// Resolver overrides the system resolver, mainly for tests.
	Resolver *net.Resolver
}

func (c Checker) resolver() *net.Resolver {
	if c.Resolver != nil {
		return c.Resolver
	}
	return net.DefaultResolver
}

// Run resolves t's hostname. A target that is already an IP literal is
// reported as skipped rather than failed: there is nothing to resolve.
func (c Checker) Run(ctx context.Context, t *target.Target) check.DNS {
	if t.IP != nil {
		res := check.DNS{Host: t.Host, Literal: true}
		res.Status = check.StatusSkip
		if t.IP.To4() != nil {
			res.A = []string{t.Host}
		} else {
			res.AAAA = []string{t.Host}
		}
		return res
	}

	res := check.DNS{Host: t.Host}
	start := time.Now()
	addrs, err := c.resolver().LookupNetIP(ctx, "ip", t.Host)
	res.Duration = check.Millis(time.Since(start))

	if err != nil {
		res.Status = check.StatusFail
		res.Error = classify(t.Host, err)
		return res
	}
	for _, a := range addrs {
		if a.Is4() || a.Is4In6() {
			res.A = append(res.A, a.Unmap().String())
		} else {
			res.AAAA = append(res.AAAA, a.String())
		}
	}
	if len(res.A)+len(res.AAAA) == 0 {
		res.Status = check.StatusFail
		res.Error = &check.Error{
			Kind:    check.KindDNSNoAddress,
			Message: fmt.Sprintf("%s resolved to no usable address.", t.Host),
			Causes: []string{
				"the name exists but has no A or AAAA record",
				"only a CNAME is published and it points nowhere",
			},
			Commands: []string{"dig " + t.Host + " A", "dig " + t.Host + " AAAA"},
		}
		return res
	}
	res.Status = check.StatusPass

	// A CNAME is useful context but never worth failing over, so it is looked
	// up separately and ignored on error.
	if cname, err := c.resolver().LookupCNAME(ctx, t.Host); err == nil {
		if trimmed := strings.TrimSuffix(cname, "."); !strings.EqualFold(trimmed, t.Host) {
			res.CNAME = trimmed
		}
	}
	return res
}

// classify turns a resolver error into a stable kind plus operator guidance.
func classify(host string, err error) *check.Error {
	e := &check.Error{Kind: check.KindUnknown, Detail: err.Error()}

	var dnsErr *net.DNSError
	switch {
	case errors.As(err, &dnsErr) && dnsErr.IsNotFound:
		e.Kind = check.KindDNSNotFound
		e.Message = fmt.Sprintf("Could not resolve %s: the name does not exist (NXDOMAIN).", host)
		e.Causes = []string{
			"the DNS record was never created, or was deleted",
			"a typo in the hostname",
			"the record exists in a private zone this resolver cannot see",
		}
	case errors.Is(err, context.DeadlineExceeded),
		errors.As(err, &dnsErr) && dnsErr.IsTimeout:
		e.Kind = check.KindDNSTimeout
		e.Message = fmt.Sprintf("DNS lookup for %s timed out.", host)
		e.Causes = []string{
			"the configured resolver is unreachable or overloaded",
			"UDP/53 is blocked between here and the resolver",
			"a VPN or split-horizon resolver is required for this name",
		}
	default:
		e.Kind = check.KindDNSServerError
		e.Message = fmt.Sprintf("DNS lookup for %s failed.", host)
		e.Causes = []string{
			"the resolver returned SERVFAIL",
			"the authoritative nameserver is not responding",
			"DNS propagation for a recent change is incomplete",
		}
	}
	e.Commands = []string{"dig " + host, "dig @1.1.1.1 " + host, "nslookup " + host}
	return e
}
