package httpcheck

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wookja-0/whyisitdown/internal/check"
	"github.com/wookja-0/whyisitdown/internal/target"
)

func newChecker() Checker {
	return Checker{UserAgent: "whyisitdown/test", FollowRedirects: true}
}

func parse(t *testing.T, raw string) *target.Target {
	t.Helper()
	tg, err := target.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return tg
}

func TestRunOK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("User-Agent"); got != "whyisitdown/test" {
			t.Errorf("User-Agent = %q", got)
		}
		w.Header().Set("Server", "test-server")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"ok":true}`)
	}))
	defer srv.Close()

	res := newChecker().Run(context.Background(), parse(t, srv.URL))
	if res.HTTP.Status != check.StatusPass {
		t.Fatalf("status = %q, error = %+v", res.HTTP.Status, res.HTTP.Error)
	}
	if res.HTTP.StatusCode != 200 || res.HTTP.StatusText != "OK" {
		t.Errorf("got %d %q", res.HTTP.StatusCode, res.HTTP.StatusText)
	}
	if res.HTTP.Server != "test-server" {
		t.Errorf("Server = %q", res.HTTP.Server)
	}
	if res.HTTP.ContentType != "application/json" {
		t.Errorf("Content-Type = %q", res.HTTP.ContentType)
	}
	if res.Redirect.Count != 0 || res.Redirect.Status != check.StatusPass {
		t.Errorf("redirect = %+v, want a clean zero-hop chain", res.Redirect)
	}
}

func TestRunStatusClassification(t *testing.T) {
	tests := []struct {
		code int
		want check.ErrorKind
	}{
		{200, ""},
		{204, ""},
		{404, check.KindHTTPNotFound},
		{410, check.KindHTTPNotFound},
		{401, check.KindHTTPUnauthorized},
		{403, check.KindHTTPUnauthorized},
		{429, check.KindHTTPClientError},
		{500, check.KindHTTPServerError},
		{502, check.KindHTTPServerError},
		{503, check.KindHTTPServerError},
	}
	for _, tc := range tests {
		t.Run(fmt.Sprint(tc.code), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.code)
			}))
			defer srv.Close()

			res := newChecker().Run(context.Background(), parse(t, srv.URL))
			if tc.want == "" {
				if res.HTTP.Status != check.StatusPass {
					t.Fatalf("status = %q, want pass", res.HTTP.Status)
				}
				return
			}
			if res.HTTP.Status != check.StatusFail {
				t.Fatalf("status = %q, want fail", res.HTTP.Status)
			}
			if res.HTTP.Error.Kind != tc.want {
				t.Errorf("kind = %q, want %q", res.HTTP.Error.Kind, tc.want)
			}
		})
	}
}

func TestRunFollowsRedirects(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/a", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/b", http.StatusMovedPermanently)
	})
	mux.HandleFunc("/b", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/c", http.StatusFound)
	})
	mux.HandleFunc("/c", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "done")
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	res := newChecker().Run(context.Background(), parse(t, srv.URL+"/a"))
	if res.HTTP.Status != check.StatusPass {
		t.Fatalf("status = %q, error = %+v", res.HTTP.Status, res.HTTP.Error)
	}
	if res.Redirect.Count != 2 {
		t.Errorf("Count = %d, want 2", res.Redirect.Count)
	}
	if len(res.Redirect.Hops) != 3 {
		t.Fatalf("Hops = %d, want 3", len(res.Redirect.Hops))
	}
	want := []struct {
		suffix string
		code   int
	}{{"/a", 301}, {"/b", 302}, {"/c", 200}}
	for i, w := range want {
		hop := res.Redirect.Hops[i]
		if !strings.HasSuffix(hop.URL, w.suffix) || hop.StatusCode != w.code {
			t.Errorf("hop %d = %+v, want %s with %d", i, hop, w.suffix, w.code)
		}
	}
	if !strings.HasSuffix(res.HTTP.URL, "/c") {
		t.Errorf("final URL = %q, want the last hop", res.HTTP.URL)
	}
}

func TestRunDetectsRedirectLoop(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/one", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/two", http.StatusFound)
	})
	mux.HandleFunc("/two", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/one", http.StatusFound)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	res := newChecker().Run(context.Background(), parse(t, srv.URL+"/one"))
	if res.Redirect.Status != check.StatusFail {
		t.Fatalf("redirect status = %q, want fail", res.Redirect.Status)
	}
	if res.Redirect.Error.Kind != check.KindRedirectLoop {
		t.Errorf("kind = %q, want %q", res.Redirect.Error.Kind, check.KindRedirectLoop)
	}
	// The failing layer is the redirect chain, not the HTTP exchange.
	if res.HTTP.Status != check.StatusSkip {
		t.Errorf("http status = %q, want skip", res.HTTP.Status)
	}
}

func TestRunStopsAfterMaxRedirects(t *testing.T) {
	// Each hop is a distinct URL, so only the hop limit can stop this.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, r.URL.Path+"0", http.StatusFound)
	}))
	defer srv.Close()

	res := newChecker().Run(context.Background(), parse(t, srv.URL+"/x"))
	if res.Redirect.Status != check.StatusFail {
		t.Fatalf("redirect status = %q, want fail", res.Redirect.Status)
	}
	if res.Redirect.Error.Kind != check.KindRedirectTooMany {
		t.Errorf("kind = %q, want %q", res.Redirect.Error.Kind, check.KindRedirectTooMany)
	}
	if res.Redirect.Count != DefaultMaxRedirects {
		t.Errorf("Count = %d, want %d", res.Redirect.Count, DefaultMaxRedirects)
	}
}

func TestRunWithoutRedirects(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://example.com/?token=secret", http.StatusMovedPermanently)
	}))
	defer srv.Close()

	c := newChecker()
	c.FollowRedirects = false
	res := c.Run(context.Background(), parse(t, srv.URL))
	if res.HTTP.StatusCode != 301 || res.HTTP.Status != check.StatusPass {
		t.Fatalf("got %d %q", res.HTTP.StatusCode, res.HTTP.Status)
	}
	if res.Redirect.Followed {
		t.Error("Followed = true, want false")
	}
	if len(res.Redirect.Hops) != 1 {
		t.Fatalf("Hops = %d, want 1", len(res.Redirect.Hops))
	}
	if got := res.Redirect.Hops[0].Location; got != "https://example.com/?token=REDACTED" {
		t.Errorf("Location = %q, want the token redacted", got)
	}
}

func TestRunRedactsCredentials(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("token") != "s3cret" {
			t.Errorf("the real query must still be sent, got %q", r.URL.RawQuery)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	res := newChecker().Run(context.Background(), parse(t, srv.URL+"/?token=s3cret"))
	if strings.Contains(res.HTTP.URL, "s3cret") {
		t.Errorf("URL = %q, want the token redacted", res.HTTP.URL)
	}
}

func TestRunTimeout(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
	}))
	defer func() {
		close(release)
		srv.Close()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	res := newChecker().Run(ctx, parse(t, srv.URL))
	if res.HTTP.Status != check.StatusFail {
		t.Fatalf("status = %q, want fail", res.HTTP.Status)
	}
	if res.HTTP.Error.Kind != check.KindHTTPTimeout {
		t.Errorf("kind = %q, want %q", res.HTTP.Error.Kind, check.KindHTTPTimeout)
	}
}

func TestSkipped(t *testing.T) {
	res := Skipped()
	if res.HTTP.Status != check.StatusSkip || res.Redirect.Status != check.StatusSkip {
		t.Errorf("Skipped() = %+v", res)
	}
}

// A redirect that crosses to another host must present that host's SNI, not
// the one the chain started from. http.Transport fills ServerName in only when
// the config leaves it empty, so pinning it would silently break virtual
// hosting on the second hop.
func TestRunDoesNotCarrySNIAcrossHosts(t *testing.T) {
	var mu sync.Mutex
	var seen []string

	second := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	second.TLS = &tls.Config{
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			mu.Lock()
			seen = append(seen, hello.ServerName)
			mu.Unlock()
			return nil, nil
		},
	}
	second.StartTLS()
	defer second.Close()

	// The first hop is reached by name and the second by IP literal, so the
	// two hops must differ in what they send.
	first := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, second.URL+"/next", http.StatusFound)
	}))
	defer first.Close()

	_, port, err := net.SplitHostPort(strings.TrimPrefix(first.URL, "https://"))
	if err != nil {
		t.Fatal(err)
	}
	res := newChecker().Run(context.Background(), parse(t, "https://localhost:"+port+"/"))
	if res.Redirect.Count != 1 {
		t.Fatalf("redirect = %+v, want one hop (%+v)", res.Redirect, res.HTTP.Error)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(seen) == 0 {
		t.Fatal("the second host was never reached")
	}
	// An IP literal sends no SNI at all; "localhost" here would mean the first
	// hop's name leaked onto the second connection.
	if seen[0] != "" {
		t.Errorf("SNI on the second hop = %q, want it derived from that hop's URL", seen[0])
	}
}
