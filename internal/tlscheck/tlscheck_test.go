package tlscheck

import (
	"context"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/wookja-0/whyisitdown/internal/check"
	"github.com/wookja-0/whyisitdown/internal/target"
)

// tlsServer starts an HTTPS test server and returns it with a pool that trusts
// its certificate.
func tlsServer(t *testing.T) (*httptest.Server, *x509.CertPool) {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	t.Cleanup(srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	return srv, pool
}

// dial connects to addr and builds a target whose hostname is host, which is
// how a mismatched certificate is reproduced without touching DNS.
func dial(t *testing.T, addr, host string) (net.Conn, *target.Target) {
	t.Helper()
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	tg, err := target.Parse("https://" + net.JoinHostPort(host, port) + "/")
	if err != nil {
		t.Fatal(err)
	}
	return conn, tg
}

func TestRunTrustedCertificate(t *testing.T) {
	srv, pool := tlsServer(t)
	conn, tg := dial(t, srv.Listener.Addr().String(), "127.0.0.1")

	res := Checker{RootCAs: pool}.Run(context.Background(), tg, conn)
	if res.TLS.Status != check.StatusPass {
		t.Fatalf("tls status = %q, error = %+v", res.TLS.Status, res.TLS.Error)
	}
	if !res.HandshakeOK {
		t.Error("HandshakeOK = false")
	}
	if res.TLS.Version == "" || res.TLS.CipherSuite == "" {
		t.Errorf("missing negotiated parameters: %+v", res.TLS)
	}
	if res.TLS.ServerName != "127.0.0.1" {
		t.Errorf("ServerName = %q", res.TLS.ServerName)
	}
	if res.Certificate.Status != check.StatusPass {
		t.Fatalf("certificate status = %q, error = %+v", res.Certificate.Status, res.Certificate.Error)
	}
	if res.Certificate.DaysRemaining == nil || *res.Certificate.DaysRemaining < 0 {
		t.Errorf("DaysRemaining = %v", res.Certificate.DaysRemaining)
	}
	if res.Certificate.Issuer == "" || res.Certificate.NotAfter == "" {
		t.Errorf("certificate detail missing: %+v", res.Certificate)
	}
}

func TestRunUntrustedCertificate(t *testing.T) {
	srv, _ := tlsServer(t)
	conn, tg := dial(t, srv.Listener.Addr().String(), "127.0.0.1")

	// No RootCAs: the system trust store does not know this self-signed cert.
	res := Checker{}.Run(context.Background(), tg, conn)
	if res.Certificate.Status != check.StatusFail {
		t.Fatalf("certificate status = %q, want fail", res.Certificate.Status)
	}
	if res.Certificate.Error.Kind != check.KindTLSUnknownAuthority {
		t.Errorf("kind = %q, want %q", res.Certificate.Error.Kind, check.KindTLSUnknownAuthority)
	}
	// The handshake worked, so the HTTP step must still be allowed to run and
	// the certificate detail must still be readable.
	if !res.HandshakeOK {
		t.Error("HandshakeOK = false, want true for a completed handshake")
	}
	if res.Certificate.Subject == "" {
		t.Error("Subject is empty; a rejected certificate must still be reported")
	}
	// The transport came up, so the TLS line stays green: trust is the
	// Certificate line's job.
	if res.TLS.Status != check.StatusPass {
		t.Errorf("tls status = %q, want pass for a completed handshake", res.TLS.Status)
	}
}

func TestRunHostnameMismatch(t *testing.T) {
	srv, pool := tlsServer(t)
	conn, tg := dial(t, srv.Listener.Addr().String(), "wrong.invalid")

	res := Checker{RootCAs: pool}.Run(context.Background(), tg, conn)
	if res.Certificate.Status != check.StatusFail {
		t.Fatalf("certificate status = %q, want fail", res.Certificate.Status)
	}
	if res.Certificate.Error.Kind != check.KindTLSHostnameMismatch {
		t.Errorf("kind = %q, want %q", res.Certificate.Error.Kind, check.KindTLSHostnameMismatch)
	}
}

func TestRunExpiredCertificate(t *testing.T) {
	addr, pool := certServer(t, time.Now().AddDate(-1, 0, 0), time.Now().Add(-48*time.Hour))
	conn, tg := dial(t, addr, "127.0.0.1")

	res := Checker{RootCAs: pool}.Run(context.Background(), tg, conn)
	if res.Certificate.Status != check.StatusFail {
		t.Fatalf("certificate status = %q, want fail", res.Certificate.Status)
	}
	if res.Certificate.Error.Kind != check.KindCertExpired {
		t.Errorf("kind = %q, want %q", res.Certificate.Error.Kind, check.KindCertExpired)
	}
	if res.Certificate.ExpiryLevel != LevelExpired {
		t.Errorf("ExpiryLevel = %q, want %q", res.Certificate.ExpiryLevel, LevelExpired)
	}
	if res.Certificate.DaysRemaining == nil || *res.Certificate.DaysRemaining >= 0 {
		t.Errorf("DaysRemaining = %v, want a negative number", res.Certificate.DaysRemaining)
	}
	// An expired certificate is still worth printing in full.
	if res.Certificate.Subject != "whyisitdown-test" {
		t.Errorf("Subject = %q", res.Certificate.Subject)
	}
	if res.TLS.Duration.Duration() < 0 {
		t.Error("handshake duration is negative; it must use the real clock")
	}
}

func TestRunNotYetValidCertificate(t *testing.T) {
	addr, pool := certServer(t, time.Now().Add(24*time.Hour), time.Now().AddDate(1, 0, 0))
	conn, tg := dial(t, addr, "127.0.0.1")

	res := Checker{RootCAs: pool}.Run(context.Background(), tg, conn)
	if res.Certificate.Error == nil || res.Certificate.Error.Kind != check.KindCertNotYetValid {
		t.Fatalf("error = %+v, want %q", res.Certificate.Error, check.KindCertNotYetValid)
	}
}

func TestRunExpiringCertificateWarns(t *testing.T) {
	tests := []struct {
		name      string
		in        time.Duration
		wantLevel string
	}{
		{"inside the warning window", 18 * 24 * time.Hour, LevelWarn},
		{"inside the critical window", 3 * 24 * time.Hour, LevelCritical},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// A few extra minutes keep the day count off the boundary.
			addr, pool := certServer(t, time.Now().Add(-time.Hour), time.Now().Add(tc.in+time.Hour))
			conn, tg := dial(t, addr, "127.0.0.1")

			res := Checker{RootCAs: pool}.Run(context.Background(), tg, conn)
			if res.Certificate.Status != check.StatusWarn {
				t.Fatalf("certificate status = %q, want warn (%+v)", res.Certificate.Status, res.Certificate.Error)
			}
			if res.Certificate.ExpiryLevel != tc.wantLevel {
				t.Errorf("ExpiryLevel = %q, want %q", res.Certificate.ExpiryLevel, tc.wantLevel)
			}
			if res.TLS.Status != check.StatusPass {
				t.Errorf("tls status = %q, want pass: a warning is not a TLS failure", res.TLS.Status)
			}
		})
	}
}

func TestRunPlaintextServer(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	done := make(chan struct{})
	defer close(done)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		// Answer a TLS ClientHello with plain HTTP, as a misconfigured port
		// does. The ClientHello is read first and the connection is held open
		// afterwards: closing immediately can reset the socket before the
		// client has read the reply, which loses the response on Windows.
		conn.Read(make([]byte, 1024))
		conn.Write([]byte("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"))
		<-done
	}()

	conn, tg := dial(t, ln.Addr().String(), "127.0.0.1")
	res := Checker{}.Run(context.Background(), tg, conn)
	if res.TLS.Status != check.StatusFail {
		t.Fatalf("tls status = %q, want fail", res.TLS.Status)
	}
	if res.TLS.Error.Kind != check.KindTLSNotTLS {
		t.Errorf("kind = %q, want %q", res.TLS.Error.Kind, check.KindTLSNotTLS)
	}
	if res.Certificate.Status != check.StatusSkip {
		t.Errorf("certificate status = %q, want skip", res.Certificate.Status)
	}
}

func TestExpiryStatus(t *testing.T) {
	tests := []struct {
		days      int
		wantState check.Status
		wantLevel string
	}{
		{365, check.StatusPass, LevelOK},
		{WarnDays, check.StatusPass, LevelOK},
		{WarnDays - 1, check.StatusWarn, LevelWarn},
		{CriticalDays, check.StatusWarn, LevelWarn},
		{CriticalDays - 1, check.StatusWarn, LevelCritical},
		{0, check.StatusWarn, LevelCritical},
		{-1, check.StatusFail, LevelExpired},
	}
	for _, tc := range tests {
		t.Run(strconv.Itoa(tc.days), func(t *testing.T) {
			status, level := expiryStatus(tc.days)
			if status != tc.wantState || level != tc.wantLevel {
				t.Errorf("expiryStatus(%d) = %q/%q, want %q/%q", tc.days, status, level, tc.wantState, tc.wantLevel)
			}
		})
	}
}

func TestSkipped(t *testing.T) {
	res := Skipped()
	if res.TLS.Status != check.StatusSkip || res.Certificate.Status != check.StatusSkip {
		t.Errorf("Skipped() = %+v", res)
	}
	if res.HandshakeOK {
		t.Error("HandshakeOK = true on a skipped step")
	}
}

// Guard against the handshake being made to verify the chain itself, which
// would hide the certificate whenever it is the thing that is wrong.
func TestHandshakeDoesNotVerify(t *testing.T) {
	srv, _ := tlsServer(t)
	conn, tg := dial(t, srv.Listener.Addr().String(), "127.0.0.1")
	res := Checker{RootCAs: x509.NewCertPool()}.Run(context.Background(), tg, conn)
	if !res.HandshakeOK {
		t.Fatal("HandshakeOK = false against an empty trust store")
	}
	if res.Certificate.ChainLength == 0 {
		t.Error("ChainLength = 0, want the presented chain")
	}
}
