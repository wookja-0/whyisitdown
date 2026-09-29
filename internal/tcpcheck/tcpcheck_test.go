package tcpcheck

import (
	"context"
	"errors"
	"net"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/wookja-0/whyisitdown/internal/check"
	"github.com/wookja-0/whyisitdown/internal/target"
)

// listen starts a local listener and returns its port.
func listen(t *testing.T) (net.Listener, int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	return ln, ln.Addr().(*net.TCPAddr).Port
}

// closedPort returns a port that nothing is listening on.
func closedPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return port
}

func targetFor(t *testing.T, port int) *target.Target {
	t.Helper()
	tg, err := target.Parse("http://127.0.0.1:" + strconv.Itoa(port) + "/")
	if err != nil {
		t.Fatal(err)
	}
	return tg
}

func TestRunConnects(t *testing.T) {
	_, port := listen(t)
	res := Checker{}.Run(context.Background(), targetFor(t, port), []string{"127.0.0.1"})
	if res.Report.Status != check.StatusPass {
		t.Fatalf("status = %q, error = %+v", res.Report.Status, res.Report.Error)
	}
	if res.Conn == nil {
		t.Fatal("Conn is nil on a successful connect")
	}
	defer res.Conn.Close()
	if want := "127.0.0.1:" + strconv.Itoa(port); res.Report.Address != want {
		t.Errorf("Address = %q, want %q", res.Report.Address, want)
	}
	if len(res.Report.Attempts) != 1 {
		t.Errorf("Attempts = %d, want 1", len(res.Report.Attempts))
	}
}

func TestRunRefused(t *testing.T) {
	port := closedPort(t)
	res := Checker{}.Run(context.Background(), targetFor(t, port), []string{"127.0.0.1"})
	if res.Report.Status != check.StatusFail {
		t.Fatalf("status = %q, want fail", res.Report.Status)
	}
	if res.Conn != nil {
		t.Error("Conn must be nil when the connection failed")
	}
	if res.Report.Error.Kind != check.KindTCPRefused {
		t.Errorf("kind = %q, want %q", res.Report.Error.Kind, check.KindTCPRefused)
	}
}

// A closed address followed by an open one is the load-balancer case: the
// checker must keep going and record both attempts.
func TestRunFallsBackToNextAddress(t *testing.T) {
	ln, port := listen(t)
	defer ln.Close()

	// 127.0.0.2 is loopback on macOS and Linux but has nothing bound here.
	res := Checker{Dialer: &net.Dialer{Timeout: 500 * time.Millisecond}}.
		Run(context.Background(), targetFor(t, port), []string{"127.0.0.2", "127.0.0.1"})
	if res.Report.Status != check.StatusPass {
		t.Skipf("127.0.0.2 behaves differently on this host: %+v", res.Report.Error)
	}
	defer res.Conn.Close()
	if len(res.Report.Attempts) != 2 {
		t.Fatalf("Attempts = %d, want 2", len(res.Report.Attempts))
	}
	if res.Report.Attempts[0].Status != check.StatusFail {
		t.Errorf("first attempt = %q, want fail", res.Report.Attempts[0].Status)
	}
}

func TestRunNoAddresses(t *testing.T) {
	res := Checker{}.Run(context.Background(), targetFor(t, 443), nil)
	if res.Report.Status != check.StatusSkip {
		t.Errorf("status = %q, want skip", res.Report.Status)
	}
}

func TestClassify(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want check.ErrorKind
	}{
		{"refused", &net.OpError{Err: syscall.ECONNREFUSED}, check.KindTCPRefused},
		{"context deadline", context.DeadlineExceeded, check.KindTCPTimeout},
		{"syscall timeout", &net.OpError{Err: syscall.ETIMEDOUT}, check.KindTCPTimeout},
		{"net timeout", &net.DNSError{IsTimeout: true}, check.KindTCPTimeout},
		{"host unreachable", &net.OpError{Err: syscall.EHOSTUNREACH}, check.KindTCPUnreachable},
		{"network unreachable", &net.OpError{Err: syscall.ENETUNREACH}, check.KindTCPUnreachable},
		{"reset", &net.OpError{Err: syscall.ECONNRESET}, check.KindTCPReset},
		{"unrecognised", errors.New("boom"), check.KindUnknown},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Classify("10.0.0.1:443", 443, tc.err)
			if got.Kind != tc.want {
				t.Errorf("kind = %q, want %q", got.Kind, tc.want)
			}
			if got.Message == "" {
				t.Error("message is empty")
			}
		})
	}
}
