package cmd

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func execute(args ...string) (code int, stdout, stderr string) {
	var out, errBuf bytes.Buffer
	code = Execute("test", args, &out, &errBuf)
	return code, out.String(), errBuf.String()
}

func TestExitOK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	code, stdout, stderr := execute(srv.URL)
	if code != ExitOK {
		t.Fatalf("exit = %d, want %d\n%s%s", code, ExitOK, stdout, stderr)
	}
	if !strings.Contains(stdout, "Everything looks good.") {
		t.Errorf("stdout = %q", stdout)
	}
}

func TestExitFailure(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	code, stdout, _ := execute("http://"+addr, "--timeout", "2s")
	if code != ExitFailure {
		t.Fatalf("exit = %d, want %d\n%s", code, ExitFailure, stdout)
	}
	if !strings.Contains(stdout, "Likely area") {
		t.Errorf("a failing run must name an area to investigate\n%s", stdout)
	}
}

func TestExitUsage(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{"no argument", nil},
		{"two arguments", []string{"example.com", "example.org"}},
		{"unsupported scheme", []string{"ftp://example.com"}},
		{"unknown flag", []string{"example.com", "--nope"}},
		{"zero timeout", []string{"example.com", "--timeout", "0s"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			code, _, stderr := execute(tc.args...)
			if code != ExitUsage {
				t.Errorf("exit = %d, want %d (stderr: %s)", code, ExitUsage, stderr)
			}
		})
	}
}

// A warning is worth printing but must not fail a pipeline, so --json on a
// healthy target has to stay parseable and exit zero.
func TestJSONOutput(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	code, stdout, _ := execute(srv.URL, "--json")
	if code != ExitOK {
		t.Fatalf("exit = %d", code)
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(stdout), &doc); err != nil {
		t.Fatalf("stdout is not JSON: %v\n%s", err, stdout)
	}
	if doc["status"] != "pass" {
		t.Errorf("status = %v", doc["status"])
	}
	if strings.Contains(stdout, "\x1b[") {
		t.Error("JSON output must never contain escape sequences")
	}
}

func TestNoColorOnBuffer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	_, stdout, _ := execute(srv.URL)
	if strings.Contains(stdout, "\x1b[") {
		t.Error("colour must be disabled when the output is not a terminal")
	}
}
