// Package httpcheck performs the HTTP request and follows the redirect chain.
//
// TLS verification is deliberately disabled here: certificate problems are
// already reported by package tlscheck, and turning them into an HTTP failure
// as well would hide whether the application itself is answering. Seeing
// "certificate expired" and "HTTP 200" at the same time is the point.
package httpcheck

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/wookja-0/whyisitdown/internal/check"
	"github.com/wookja-0/whyisitdown/internal/target"
)

// DefaultMaxRedirects is how many hops are followed before giving up.
const DefaultMaxRedirects = 10

// bodyPeek is how much of the body is read before discarding it, enough to let
// the connection be reused or closed cleanly without buffering a large page.
const bodyPeek = 4 << 10

// Sentinel errors used to stop the redirect chain; they travel back inside the
// *url.Error returned by Client.Do and are matched with errors.Is.
var (
	errRedirectLoop = errors.New("redirect loop")
	errTooManyHops  = errors.New("too many redirects")
)

// Checker issues the request.
type Checker struct {
	// UserAgent is sent with every request.
	UserAgent string
	// FollowRedirects controls whether 3xx responses are followed.
	FollowRedirects bool
	// MaxRedirects bounds the chain; zero means DefaultMaxRedirects.
	MaxRedirects int
	// PinnedAddress is the ip:port the TCP step connected to. When set, the
	// first hop is dialled there so all steps describe the same endpoint.
	PinnedAddress string
}

// Result holds the reports for the final response and the chain that led to it.
type Result struct {
	HTTP     check.HTTP
	Redirect check.Redirect
}

// Skipped returns the pair of results for a target that was never reached.
func Skipped() Result {
	var r Result
	r.HTTP.Status = check.StatusSkip
	r.Redirect.Status = check.StatusSkip
	return r
}

// Run issues a GET against the target and reports the outcome.
func (c Checker) Run(ctx context.Context, t *target.Target) Result {
	res := Result{}
	res.Redirect.Followed = c.FollowRedirects

	maxHops := c.MaxRedirects
	if maxHops <= 0 {
		maxHops = DefaultMaxRedirects
	}

	transport := &http.Transport{
		DialContext: c.dialContext(t),
		// See the package comment: the certificate is validated by tlscheck.
		//
		// ServerName is deliberately left empty. http.Transport only fills it
		// in when it is unset, so pinning it here would send the original
		// host's SNI to every host the chain redirects to.
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
		ForceAttemptHTTP2:     true,
		DisableKeepAlives:     true,
		TLSHandshakeTimeout:   0, // bounded by ctx
		ResponseHeaderTimeout: 0, // bounded by ctx
	}
	defer transport.CloseIdleConnections()

	var hops []check.Hop
	seen := map[string]bool{canonical(t.URL): true}

	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if !c.FollowRedirects {
				return http.ErrUseLastResponse
			}
			if len(via) > maxHops {
				return errTooManyHops
			}
			from := via[len(via)-1].URL
			hops = append(hops, check.Hop{
				URL:        target.SanitizeURL(from),
				StatusCode: req.Response.StatusCode,
				Location:   target.SanitizeURL(req.URL),
			})
			if seen[canonical(req.URL)] {
				return errRedirectLoop
			}
			seen[canonical(req.URL)] = true
			return nil
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, t.URL.String(), nil)
	if err != nil {
		res.HTTP.Status = check.StatusFail
		res.HTTP.Error = &check.Error{Kind: check.KindUnknown, Message: "The request could not be built.", Detail: err.Error()}
		res.Redirect.Status = check.StatusSkip
		return res
	}
	req.Header.Set("User-Agent", c.UserAgent)
	req.Header.Set("Accept", "*/*")

	start := time.Now()
	resp, err := client.Do(req)
	elapsed := time.Since(start)
	res.HTTP.Duration = check.Millis(elapsed)
	res.Redirect.Hops = hops

	if err != nil {
		res.HTTP.Status = check.StatusFail
		res.HTTP.Error = classify(t, err)
		res.Redirect.Status = check.StatusSkip
		switch res.HTTP.Error.Kind {
		case check.KindRedirectLoop, check.KindRedirectTooMany:
			// The chain itself is the failure; report it there and leave the
			// HTTP line skipped so the summary points at the right layer.
			res.Redirect.Status = check.StatusFail
			res.Redirect.Error = res.HTTP.Error
			res.Redirect.Count = len(hops)
			res.HTTP.Status = check.StatusSkip
			res.HTTP.Error = nil
		}
		return res
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, bodyPeek))
		resp.Body.Close()
	}()

	res.HTTP.URL = target.SanitizeURL(resp.Request.URL)
	res.HTTP.StatusCode = resp.StatusCode
	res.HTTP.StatusText = http.StatusText(resp.StatusCode)
	res.HTTP.Proto = resp.Proto
	res.HTTP.Server = resp.Header.Get("Server")
	res.HTTP.ContentType = resp.Header.Get("Content-Type")
	if resp.ContentLength >= 0 {
		length := resp.ContentLength
		res.HTTP.ContentLength = &length
	}
	res.HTTP.Status, res.HTTP.Error = statusOf(resp)

	final := check.Hop{URL: res.HTTP.URL, StatusCode: resp.StatusCode}
	if loc := resp.Header.Get("Location"); loc != "" && !c.FollowRedirects {
		final.Location = target.SanitizeRawURL(loc)
	}
	res.Redirect.Hops = append(hops, final)
	res.Redirect.Count = len(hops)
	res.Redirect.Status = check.StatusPass
	res.Redirect.Duration = check.Millis(elapsed)
	return res
}

// dialContext pins the first hop to the address the TCP step used, so DNS
// round-robin cannot make the HTTP result describe a different server.
func (c Checker) dialContext(t *target.Target) func(context.Context, string, string) (net.Conn, error) {
	dialer := &net.Dialer{}
	pinnedFrom := t.HostPort()
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		if c.PinnedAddress != "" && addr == pinnedFrom {
			addr = c.PinnedAddress
		}
		return dialer.DialContext(ctx, network, addr)
	}
}

// statusOf maps a response code to a check status.
//
// 4xx and 5xx are failures: the connection worked, but the request did not.
// That is what makes the exit code useful in CI.
func statusOf(resp *http.Response) (check.Status, *check.Error) {
	code := resp.StatusCode
	switch {
	case code < 400:
		return check.StatusPass, nil
	case code == http.StatusNotFound, code == http.StatusGone:
		return check.StatusFail, &check.Error{
			Kind:    check.KindHTTPNotFound,
			Message: fmt.Sprintf("The server answered %d %s.", code, http.StatusText(code)),
			Causes: []string{
				"the path does not exist on this host",
				"ingress or reverse-proxy routing sends this path elsewhere",
				"the request reached a different virtual host than intended",
			},
		}
	case code == http.StatusUnauthorized, code == http.StatusForbidden:
		return check.StatusFail, &check.Error{
			Kind:    check.KindHTTPUnauthorized,
			Message: fmt.Sprintf("The server answered %d %s.", code, http.StatusText(code)),
			Causes: []string{
				"credentials are required and none were sent",
				"an IP allow-list or WAF rule is blocking this client",
				"the token or API key has expired",
			},
		}
	case code < 500:
		return check.StatusFail, &check.Error{
			Kind:    check.KindHTTPClientError,
			Message: fmt.Sprintf("The server answered %d %s.", code, http.StatusText(code)),
			Causes: []string{
				"the request was rejected by the application or its proxy",
				"rate limiting",
			},
		}
	default:
		return check.StatusFail, &check.Error{
			Kind:    check.KindHTTPServerError,
			Message: fmt.Sprintf("The server answered %d %s.", code, http.StatusText(code)),
			Causes: []string{
				"the application is erroring or still starting up",
				"an upstream or database dependency is unavailable",
				"the proxy has no healthy backend (502/503/504)",
			},
		}
	}
}

func classify(t *target.Target, err error) *check.Error {
	e := &check.Error{Kind: check.KindUnknown, Detail: redactErr(t, err)}
	e.Commands = []string{fmt.Sprintf("curl -sv -o /dev/null %s", t.Display())}

	var netErr net.Error
	switch {
	case errors.Is(err, errRedirectLoop):
		e.Kind = check.KindRedirectLoop
		e.Message = "The redirect chain loops back on itself."
		e.Causes = []string{
			"an HTTP-to-HTTPS rule is applied behind a proxy that terminates TLS",
			"two hosts redirect to each other",
			"the application redirects to a path that redirects back",
		}
	case errors.Is(err, errTooManyHops):
		e.Kind = check.KindRedirectTooMany
		e.Message = fmt.Sprintf("The redirect chain exceeded %d hops.", DefaultMaxRedirects)
		e.Causes = []string{"a redirect rule keeps rewriting the request"}
	case errors.Is(err, context.DeadlineExceeded),
		errors.As(err, &netErr) && netErr.Timeout():
		e.Kind = check.KindHTTPTimeout
		e.Message = "The HTTP request timed out."
		e.Causes = []string{
			"the application accepted the connection but never responded",
			"a slow upstream or a saturated worker pool",
			"the response is blocked by a proxy",
		}
	case errors.Is(err, io.ErrUnexpectedEOF), errors.Is(err, io.EOF):
		e.Kind = check.KindHTTPProtocol
		e.Message = "The connection closed before a complete response arrived."
		e.Causes = []string{"the server or proxy closed the connection early"}
	default:
		e.Kind = check.KindHTTPProtocol
		e.Message = "The HTTP request failed."
		e.Causes = []string{"the server sent a response the client could not parse"}
	}
	return e
}

// redactErr keeps credentials in the target URL out of error text, which the
// net/http package includes verbatim.
func redactErr(t *target.Target, err error) string {
	msg := err.Error()
	if raw := t.URL.String(); raw != "" {
		msg = strings.ReplaceAll(msg, raw, t.Display())
	}
	return msg
}

// canonical normalises a URL for loop detection.
func canonical(u *url.URL) string {
	c := *u
	c.Fragment = ""
	if c.Path == "" {
		c.Path = "/"
	}
	return strings.ToLower(c.Scheme+"://"+c.Host) + c.Path + "?" + c.RawQuery
}
