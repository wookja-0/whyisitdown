package runner

import (
	"context"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"testing"
	"time"

	"github.com/wookja-0/whyisitdown/internal/check"
	"github.com/wookja-0/whyisitdown/internal/diagnosis"
	"github.com/wookja-0/whyisitdown/internal/target"
)

func parse(t *testing.T, raw string) *target.Target {
	t.Helper()
	tg, err := target.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return tg
}

func opts() Options {
	return Options{Timeout: 2 * time.Second, FollowRedirects: true, UserAgent: "whyisitdown/test", Version: "test"}
}

// Targets are addressed by IP literal so the whole pipeline runs without a
// resolver, which keeps these tests hermetic.
func TestRunPlainHTTP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	r := Run(context.Background(), parse(t, srv.URL), opts())
	if r.Status != check.StatusPass {
		t.Fatalf("status = %q, diagnosis = %q", r.Status, r.Diagnosis.Message)
	}
	if r.Checks.DNS.Status != check.StatusSkip || !r.Checks.DNS.Literal {
		t.Errorf("DNS = %+v, want skipped for an IP literal", r.Checks.DNS)
	}
	if r.Checks.TCP.Status != check.StatusPass {
		t.Errorf("TCP = %+v", r.Checks.TCP)
	}
	if r.Checks.TLS.Status != check.StatusSkip || r.Checks.Certificate.Status != check.StatusSkip {
		t.Errorf("TLS steps should be skipped for http://, got %q/%q", r.Checks.TLS.Status, r.Checks.Certificate.Status)
	}
	if r.Checks.HTTP.StatusCode != 200 {
		t.Errorf("HTTP = %+v", r.Checks.HTTP)
	}
	if r.Diagnosis.Message != "Service is reachable." || r.Diagnosis.LikelyArea != nil {
		t.Errorf("diagnosis = %+v", r.Diagnosis)
	}
	if r.SchemaVersion != check.SchemaVersion || r.Version != "test" {
		t.Errorf("report metadata = %+v", r)
	}
	if r.TotalDuration.Duration() <= 0 {
		t.Error("TotalDuration was not recorded")
	}
}

func TestRunHTTPS(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer srv.Close()
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())

	o := opts()
	o.RootCAs = pool
	r := Run(context.Background(), parse(t, srv.URL), o)

	if r.Status != check.StatusPass {
		t.Fatalf("status = %q, diagnosis = %q", r.Status, r.Diagnosis.Message)
	}
	if r.Checks.TLS.Status != check.StatusPass || r.Checks.TLS.Version == "" {
		t.Errorf("TLS = %+v", r.Checks.TLS)
	}
	if r.Checks.Certificate.Status != check.StatusPass || r.Checks.Certificate.DaysRemaining == nil {
		t.Errorf("Certificate = %+v", r.Checks.Certificate)
	}
	if r.Checks.HTTP.StatusCode != 200 {
		t.Errorf("HTTP = %+v", r.Checks.HTTP)
	}
}

// Later steps must be reported as skipped rather than dropped, so the output
// always shows how far the request got.
func TestRunStopsAtTCPFailure(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	r := Run(context.Background(), parse(t, "http://"+addr+"/"), opts())
	if r.Status != check.StatusFail {
		t.Fatalf("status = %q, want fail", r.Status)
	}
	if r.Checks.TCP.Status != check.StatusFail {
		t.Errorf("TCP = %+v", r.Checks.TCP)
	}
	for name, status := range map[string]check.Status{
		"tls":         r.Checks.TLS.Status,
		"certificate": r.Checks.Certificate.Status,
		"http":        r.Checks.HTTP.Status,
		"redirect":    r.Checks.Redirect.Status,
	} {
		if status != check.StatusSkip {
			t.Errorf("%s = %q, want skip", name, status)
		}
	}
	if r.Diagnosis.LikelyArea == nil || *r.Diagnosis.LikelyArea != diagnosis.AreaNetwork {
		t.Errorf("LikelyArea = %v, want %q", r.Diagnosis.LikelyArea, diagnosis.AreaNetwork)
	}
}

func TestRunServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusBadGateway)
	}))
	defer srv.Close()

	r := Run(context.Background(), parse(t, srv.URL), opts())
	if r.Status != check.StatusFail {
		t.Fatalf("status = %q, want fail", r.Status)
	}
	if *r.Diagnosis.LikelyArea != diagnosis.AreaUpstream {
		t.Errorf("LikelyArea = %q, want %q", *r.Diagnosis.LikelyArea, diagnosis.AreaUpstream)
	}
}

// An expired certificate must not stop the HTTP step: knowing the application
// still answers is what separates "expired cert" from "service down".
func TestRunContinuesPastCertificateFailure(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	// No RootCAs: the certificate is untrusted, the transport is fine.
	r := Run(context.Background(), parse(t, srv.URL), opts())
	if r.Checks.Certificate.Status != check.StatusFail {
		t.Fatalf("Certificate = %+v, want fail", r.Checks.Certificate)
	}
	if r.Checks.HTTP.StatusCode != 200 {
		t.Errorf("HTTP = %+v, want the application response despite the certificate", r.Checks.HTTP)
	}
	if r.Status != check.StatusFail || *r.Diagnosis.LikelyArea != diagnosis.AreaTLS {
		t.Errorf("status = %q, diagnosis = %+v", r.Status, r.Diagnosis)
	}
}

func TestRunWithoutRedirects(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://example.com/", http.StatusMovedPermanently)
	}))
	defer srv.Close()

	o := opts()
	o.FollowRedirects = false
	r := Run(context.Background(), parse(t, srv.URL), o)
	if r.Status != check.StatusPass {
		t.Fatalf("status = %q", r.Status)
	}
	if r.Checks.Redirect.Followed {
		t.Error("Followed = true, want false")
	}
	if r.Checks.HTTP.StatusCode != 301 {
		t.Errorf("HTTP = %+v", r.Checks.HTTP)
	}
}

func TestRunHonoursCancellation(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
	}))
	defer func() {
		close(release)
		srv.Close()
	}()

	o := opts()
	o.Timeout = 150 * time.Millisecond
	start := time.Now()
	r := Run(context.Background(), parse(t, srv.URL), o)
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("run took %v; the per-step timeout was not applied", elapsed)
	}
	if r.Checks.HTTP.Error == nil || r.Checks.HTTP.Error.Kind != check.KindHTTPTimeout {
		t.Errorf("HTTP error = %+v, want a timeout", r.Checks.HTTP.Error)
	}
}

// Nothing may outlive the run: a leaked dial or timer would accumulate in any
// process that calls this in a loop.
func TestRunLeavesNoGoroutines(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer srv.Close()
	tg := parse(t, srv.URL)

	Run(context.Background(), tg, opts()) // warm up lazily started runtime goroutines
	settle()
	before := runtime.NumGoroutine()

	for range 5 {
		Run(context.Background(), tg, opts())
	}
	settle()

	if after := runtime.NumGoroutine(); after > before+2 {
		t.Errorf("goroutines grew from %d to %d across 5 runs", before, after)
	}
}

func settle() {
	for range 20 {
		runtime.GC()
		time.Sleep(10 * time.Millisecond)
	}
}
