package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/wookja-0/whyisitdown/internal/check"
	"github.com/wookja-0/whyisitdown/internal/diagnosis"
)

func dur(d time.Duration) check.Millis { return check.Millis(d) }

func passingReport() check.Report {
	days := 74
	length := int64(1256)
	return check.Report{
		SchemaVersion: check.SchemaVersion,
		Tool:          "whyisitdown",
		Version:       "test",
		Target:        "https://example.com/",
		Status:        check.StatusPass,
		TotalDuration: dur(259 * time.Millisecond),
		Checks: check.Checks{
			DNS: check.DNS{
				Base: check.Base{Status: check.StatusPass, Duration: dur(18 * time.Millisecond)},
				Host: "example.com",
				A:    []string{"93.184.216.34"},
			},
			TCP: check.TCP{
				Base:    check.Base{Status: check.StatusPass, Duration: dur(42 * time.Millisecond)},
				Port:    443,
				Address: "93.184.216.34:443",
			},
			TLS: check.TLS{
				Base:        check.Base{Status: check.StatusPass, Duration: dur(61 * time.Millisecond)},
				Version:     "TLS 1.3",
				CipherSuite: "TLS_AES_256_GCM_SHA384",
				ALPN:        "h2",
				ServerName:  "example.com",
			},
			Certificate: check.Certificate{
				Base:          check.Base{Status: check.StatusPass},
				Subject:       "example.com",
				Issuer:        "Let's Encrypt",
				NotAfter:      "2026-12-01T00:00:00Z",
				DaysRemaining: &days,
			},
			HTTP: check.HTTP{
				Base:          check.Base{Status: check.StatusPass, Duration: dur(138 * time.Millisecond)},
				URL:           "https://example.com/",
				StatusCode:    200,
				StatusText:    "OK",
				Proto:         "HTTP/2.0",
				Server:        "nginx",
				ContentLength: &length,
			},
			Redirect: check.Redirect{
				Base:     check.Base{Status: check.StatusPass},
				Followed: true,
			},
		},
		Diagnosis: check.Diagnosis{Message: "Service is reachable."},
	}
}

func failingReport() check.Report {
	area := diagnosis.AreaNetwork
	r := check.Report{
		SchemaVersion: check.SchemaVersion,
		Target:        "https://api.example.com/?token=REDACTED",
		Status:        check.StatusFail,
		TotalDuration: dur(5 * time.Second),
		Checks: check.Checks{
			DNS: check.DNS{
				Base: check.Base{Status: check.StatusPass, Duration: dur(21 * time.Millisecond)},
				Host: "api.example.com",
				A:    []string{"10.0.3.18"},
			},
			TCP: check.TCP{
				Base: check.Base{Status: check.StatusFail, Duration: dur(5 * time.Second), Error: &check.Error{
					Kind:     check.KindTCPTimeout,
					Message:  "Connection to 10.0.3.18:443 timed out.",
					Causes:   []string{"a security group, NACL or firewall is dropping the packets"},
					Commands: []string{"nc -vz 10.0.3.18 443"},
				}},
				Port:     443,
				Attempts: []check.TCPAttempt{{Address: "10.0.3.18:443", Status: check.StatusFail}},
			},
			TLS:         check.TLS{Base: check.Base{Status: check.StatusSkip}},
			Certificate: check.Certificate{Base: check.Base{Status: check.StatusSkip}},
			HTTP:        check.HTTP{Base: check.Base{Status: check.StatusSkip}},
			Redirect:    check.Redirect{Base: check.Base{Status: check.StatusSkip}},
		},
		Diagnosis: check.Diagnosis{
			Message:    "DNS resolution succeeded, but the TCP connection to port 443 timed out.",
			LikelyArea: &area,
		},
	}
	return r
}

func TestTextPassing(t *testing.T) {
	var buf bytes.Buffer
	if err := Text(&buf, passingReport(), TextOptions{}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{
		"WhyIsItDown", "https://example.com/", "93.184.216.34:443",
		"TLS 1.3", "h2", "Let's Encrypt", "2026-12-01", "Remaining: 74 days",
		"200 OK", "no redirect", "Everything looks good.", "Total: 259ms",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output is missing %q\n%s", want, out)
		}
	}
	// A passing run has nothing to diagnose, so the summary table stays away.
	if strings.Contains(out, "Summary") {
		t.Errorf("passing output should not print a summary table\n%s", out)
	}
	if strings.Contains(out, "\x1b[") {
		t.Error("colour escapes leaked into a no-colour render")
	}
}

func TestTextFailing(t *testing.T) {
	var buf bytes.Buffer
	if err := Text(&buf, failingReport(), TextOptions{}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{
		"Connection to 10.0.3.18:443 timed out.",
		"Possible causes",
		"security group",
		"Try",
		"nc -vz 10.0.3.18 443",
		"Summary",
		"TCP          FAIL",
		"TLS          SKIP",
		"Likely area",
		diagnosis.AreaNetwork,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output is missing %q\n%s", want, out)
		}
	}
	if strings.Contains(out, "token=") && !strings.Contains(out, "token=REDACTED") {
		t.Error("an unredacted token reached the terminal")
	}
}

func TestTextColor(t *testing.T) {
	var buf bytes.Buffer
	if err := Text(&buf, passingReport(), TextOptions{Color: true}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "\x1b[32m") {
		t.Error("colour was requested but no escapes were written")
	}
}

func TestTextVerbose(t *testing.T) {
	r := passingReport()
	r.Checks.Certificate.SANs = []string{"example.com", "www.example.com"}
	var buf bytes.Buffer
	if err := Text(&buf, r, TextOptions{Verbose: true}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"TLS_AES_256_GCM_SHA384", "SNI example.com", "www.example.com", "Content-Length: 1256"} {
		if !strings.Contains(out, want) {
			t.Errorf("verbose output is missing %q\n%s", want, out)
		}
	}
}

func TestJSONShape(t *testing.T) {
	var buf bytes.Buffer
	if err := JSON(&buf, passingReport()); err != nil {
		t.Fatal(err)
	}

	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	for _, key := range []string{"schema_version", "tool", "version", "target", "status", "total_duration_ms", "checks", "diagnosis"} {
		if _, ok := doc[key]; !ok {
			t.Errorf("missing top-level key %q", key)
		}
	}
	if doc["total_duration_ms"].(float64) != 259 {
		t.Errorf("total_duration_ms = %v, want 259", doc["total_duration_ms"])
	}

	checks := doc["checks"].(map[string]any)
	// Every step keeps its key even when it did not run, so consumers never
	// have to distinguish "absent" from "skipped".
	for _, key := range []string{"dns", "tcp", "tls", "certificate", "http", "redirect"} {
		step, ok := checks[key].(map[string]any)
		if !ok {
			t.Fatalf("checks.%s is missing", key)
		}
		if _, ok := step["status"]; !ok {
			t.Errorf("checks.%s has no status", key)
		}
	}

	d := doc["diagnosis"].(map[string]any)
	if d["likely_area"] != nil {
		t.Errorf("likely_area = %v, want null on a healthy run", d["likely_area"])
	}
}

func TestJSONFailure(t *testing.T) {
	var buf bytes.Buffer
	if err := JSON(&buf, failingReport()); err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	tcp := doc["checks"].(map[string]any)["tcp"].(map[string]any)
	errObj, ok := tcp["error"].(map[string]any)
	if !ok {
		t.Fatal("checks.tcp.error is missing")
	}
	if errObj["kind"] != string(check.KindTCPTimeout) {
		t.Errorf("kind = %v, want %q", errObj["kind"], check.KindTCPTimeout)
	}
	if doc["diagnosis"].(map[string]any)["likely_area"] != diagnosis.AreaNetwork {
		t.Errorf("likely_area = %v", doc["diagnosis"].(map[string]any)["likely_area"])
	}
}

// The document must survive a round trip, which is what lets a stored report
// be re-rendered by a later version.
func TestJSONRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	if err := JSON(&buf, passingReport()); err != nil {
		t.Fatal(err)
	}
	var back check.Report
	if err := json.Unmarshal(buf.Bytes(), &back); err != nil {
		t.Fatal(err)
	}
	if back.TotalDuration.Duration() != 259*time.Millisecond {
		t.Errorf("TotalDuration = %v", back.TotalDuration.Duration())
	}
	if back.Checks.HTTP.StatusCode != 200 || back.Checks.TLS.ALPN != "h2" {
		t.Errorf("round trip lost data: %+v", back.Checks)
	}
}
