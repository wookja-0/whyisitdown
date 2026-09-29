# WhyIsItDown

Find out why a service is down before opening five terminals.

DNS → TCP → TLS → Certificate → HTTP → Redirect

[![ci](https://github.com/wookja-0/whyisitdown/actions/workflows/ci.yml/badge.svg)](https://github.com/wookja-0/whyisitdown/actions/workflows/ci.yml)
[![release](https://img.shields.io/github/v/release/wookja-0/whyisitdown)](https://github.com/wookja-0/whyisitdown/releases/latest)
[![Go Report Card](https://goreportcard.com/badge/github.com/wookja-0/whyisitdown)](https://goreportcard.com/report/github.com/wookja-0/whyisitdown)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

`whyisitdown` takes one URL and walks the request down the stack the way it
actually happens, then tells you which layer it stopped at, what usually causes
that, and which command to run next. One binary, no daemon, no root.

![whyisitdown checking a healthy service](docs/demo.gif)

## When something breaks

The failing layer is the part you see, with the likely cause and the next
command to run:

```
DNS
✓ 10.0.3.18
  21ms

TCP
✗ 10.0.3.18:443
✗ Connection to 10.0.3.18:443 timed out.

  Possible causes
  - a security group, NACL or firewall is dropping the packets
  - the service is not listening on port 443
  - the load balancer has no healthy target
  - asymmetric routing or a missing return route

  Try
    nc -vz 10.0.3.18 443
    curl -v --connect-timeout 5 https://10.0.3.18:443/

────────────────────────────────────

Summary
DNS          PASS  21ms, 1 address
TCP          FAIL  5000ms
TLS          SKIP
Certificate  SKIP
HTTP         SKIP
Redirect     SKIP

Diagnosis
DNS resolution succeeded, but the TCP connection to port 443 timed out.

Likely area
Network / Firewall / Load Balancer
```

## Install

Every release ships a `checksums.txt` next to the archives if you want to
verify the download.

### macOS

#### Apple Silicon

```bash
curl -sSL https://github.com/wookja-0/whyisitdown/releases/latest/download/whyisitdown_Darwin_arm64.tar.gz | tar -xzf - whyisitdown
sudo mv whyisitdown /usr/local/bin/
whyisitdown --version
```

#### Intel

```bash
curl -sSL https://github.com/wookja-0/whyisitdown/releases/latest/download/whyisitdown_Darwin_x86_64.tar.gz | tar -xzf - whyisitdown
sudo mv whyisitdown /usr/local/bin/
whyisitdown --version
```

The binaries are unsigned. Downloading with `curl` is fine; if you download an
archive with a browser instead, clear the quarantine flag with
`xattr -d com.apple.quarantine whyisitdown`.

### Linux

#### x86_64

```bash
curl -sSL https://github.com/wookja-0/whyisitdown/releases/latest/download/whyisitdown_Linux_x86_64.tar.gz | tar -xzf - whyisitdown
sudo mv whyisitdown /usr/local/bin/
whyisitdown --version
```

#### arm64

```bash
curl -sSL https://github.com/wookja-0/whyisitdown/releases/latest/download/whyisitdown_Linux_arm64.tar.gz | tar -xzf - whyisitdown
sudo mv whyisitdown /usr/local/bin/
whyisitdown --version
```

### Windows

PowerShell:

```powershell
Invoke-WebRequest -Uri https://github.com/wookja-0/whyisitdown/releases/latest/download/whyisitdown_Windows_x86_64.zip -OutFile whyisitdown.zip
Expand-Archive -Path whyisitdown.zip -DestinationPath .
.\whyisitdown.exe --version
```

Move `whyisitdown.exe` somewhere on your `PATH` to run it from any directory.

### Go

```bash
go install github.com/wookja-0/whyisitdown@latest
whyisitdown --version
```

### From source

```bash
git clone https://github.com/wookja-0/whyisitdown
cd whyisitdown
go build -o whyisitdown .
./whyisitdown --version
```

### Homebrew

Coming soon.

## Quick start

```bash
whyisitdown https://example.com
whyisitdown api.example.com --timeout 2s
whyisitdown api.example.com --json
```

## Usage

```bash
whyisitdown <target> [flags]
```

The scheme defaults to `https`, and the port defaults to the scheme's. All of
these are valid targets:

```text
example.com
https://example.com
http://example.com
example.com:8443
https://example.com:8443/api/health
10.0.3.18
https://[2606:4700::1]/
```

| Flag | Default | Description |
| --- | --- | --- |
| `--timeout` | `5s` | Per-step timeout. Each step gets its own budget, so one slow layer cannot starve the next. |
| `--no-color` | off | Disable ANSI colour. Also honours `NO_COLOR` and `TERM=dumb`, and turns itself off when the output is not a terminal. |
| `--json` | off | Print the machine-readable report instead of the terminal one. |
| `--verbose`, `-v` | off | Add cipher suite, SNI, SAN list, protocol, content length, failed connection attempts and raw error text. |
| `--no-redirect` | off | Report the first response instead of following redirects. |

## Examples

```bash
# A health endpoint behind a non-standard port
whyisitdown https://api.example.com:8443/health

# See the 301 instead of what it points at
whyisitdown example.com --no-redirect

# Feed a dashboard or an alert
whyisitdown api.example.com --json | jq '.checks.certificate.days_remaining'

# Gate a deploy
whyisitdown https://api.example.com/health || echo "rollback"
```

## Checks

| Check | What it reports | Failure modes it distinguishes |
| --- | --- | --- |
| **DNS** | A and AAAA records, CNAME, lookup latency | NXDOMAIN, no address record, resolver timeout, SERVFAIL |
| **TCP** | Connected address, port, connect latency, every address attempted | refused, timeout, unreachable, reset |
| **TLS** | Version, cipher suite, ALPN, SNI, handshake latency | handshake failure, timeout, a port that does not speak TLS |
| **Certificate** | Subject, issuer, SANs, validity window, days remaining | expired, not yet valid, hostname mismatch, untrusted or self-signed chain |
| **HTTP** | Status, latency, `Server`, `Content-Type`, `Content-Length` | 4xx, 5xx, timeout, malformed response |
| **Redirect** | The full chain with the status at each hop | redirect loop, chain longer than 10 hops |

Four details are worth knowing:

- **The certificate is verified separately from the handshake.** The handshake
  is made without verification so the certificate can be read and reported even
  when it is the thing that is wrong; the chain and hostname are then checked
  explicitly. This is why you can see `Certificate FAIL` and `HTTP 200` in the
  same output — which is exactly the distinction between "the cert expired" and
  "the service is down".
- **The HTTP step therefore does not re-validate the certificate.** Its job is
  to report what the application answered.
- **The first HTTP request is pinned to the address the TCP step connected
  to**, so DNS round-robin cannot make the initial HTTP result describe a
  different server than the one that was probed. Later hops in a redirect chain
  are resolved normally.
- **The certificate check covers the target, not the whole redirect chain.** If
  the chain ends on a different HTTPS host, that host's certificate is not
  verified in v0.1 — the output says so when it happens:

  ```text
    https://example.com/
      ↓ 301
    https://www.example.org/
      ↓ 200

    certificate not checked for www.example.org; the Certificate step covers the initial target
  ```

Response bodies are never printed, and only the first few kilobytes are read.

### Certificate expiry thresholds

| Remaining | Status |
| --- | --- |
| more than 30 days | PASS |
| 7 to 30 days | WARN (`expiry_level: warn`) |
| less than 7 days | WARN (`expiry_level: critical`) |
| expired | FAIL (`expiry_level: expired`) |

A certificate that expires next week still serves traffic today, so it warns
rather than fails. The thresholds live in `internal/tlscheck` as constants.

### Credentials are redacted

Basic-auth userinfo and the values of sensitive query parameters (`token`,
`key`, `secret`, `password`, `signature`, `session`, …) are replaced with
`REDACTED` in everything printed or serialised, including redirect targets and
error text. The request itself is still sent with the real values.

## JSON output

`--json` prints one JSON document, with no colour and no decoration.

```json
{
  "schema_version": 1,
  "tool": "whyisitdown",
  "version": "0.1.2",
  "target": "https://example.com/",
  "status": "fail",
  "total_duration_ms": 259,
  "checks": {
    "dns": {
      "status": "pass",
      "duration_ms": 18,
      "host": "example.com",
      "literal_ip": false,
      "a": ["93.184.216.34"]
    },
    "tcp": {
      "status": "pass",
      "duration_ms": 42,
      "port": 443,
      "address": "93.184.216.34:443",
      "attempts": [
        {"address": "93.184.216.34:443", "status": "pass", "duration_ms": 42}
      ]
    },
    "tls": {
      "status": "pass",
      "duration_ms": 61,
      "version": "TLS 1.3",
      "cipher_suite": "TLS_AES_256_GCM_SHA384",
      "alpn": "h2",
      "server_name": "example.com"
    },
    "certificate": {
      "status": "fail",
      "duration_ms": 0,
      "error": {
        "kind": "cert_expired",
        "message": "The certificate expired 12 days ago (2026-09-17T00:00:00Z).",
        "causes": ["certificate renewal failed or was never automated"],
        "commands": ["openssl s_client -connect example.com:443 -servername example.com"]
      },
      "subject": "example.com",
      "issuer": "Let's Encrypt",
      "sans": ["example.com", "www.example.com"],
      "not_before": "2026-06-19T00:00:00Z",
      "not_after": "2026-09-17T00:00:00Z",
      "days_remaining": -12,
      "expiry_level": "expired",
      "chain_length": 2
    },
    "http": {"status": "pass", "duration_ms": 138, "status_code": 200, "status_text": "OK"},
    "redirect": {"status": "pass", "duration_ms": 138, "followed": true, "count": 0}
  },
  "diagnosis": {
    "message": "The connection works, but the TLS certificate has expired.",
    "likely_area": "TLS / Certificate"
  }
}
```

Stability rules:

- Every step key under `checks` is always present. A step that did not run has
  `"status": "skip"`, never a missing key or `null`.
- `status` is one of `pass`, `warn`, `fail`, `skip`.
- `error.kind` is a stable enum (`dns_not_found`, `tcp_refused`, `tls_timeout`,
  `cert_expired`, `http_server_error`, `redirect_loop`, …). Match on it rather
  than on `message`, which is prose and may be reworded.
- `diagnosis.likely_area` is `null` when nothing failed.
- New fields may be added in a minor release; `schema_version` is incremented
  only when an existing field changes meaning or disappears.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Every check passed, or warned. WARN does not fail a pipeline. |
| `1` | A check failed: the service is unreachable, the certificate is invalid, the redirect chain is broken, or HTTP answered 4xx/5xx. |
| `2` | Bad usage: unparseable target, unsupported scheme, unknown flag. |

## Roadmap

Not implemented yet, and not promised:

- certificate verification for each HTTPS host in a redirect chain
- internationalised domain names (punycode via `golang.org/x/net/idna`)
- `--dns-server` to query a specific resolver
- custom HTTP headers, and `HEAD` / `POST`
- proxy support
- mTLS client certificates
- HTTP/3
- CDN detection
- DNSSEC validation
- traceroute-style path inspection
- Kubernetes Service / Ingress diagnosis
- an interactive web playground
- a GitHub Action

Out of scope by design: this is a single-shot diagnostic CLI. No daemon, no
metrics exporter, no stored history, no accounts, no LLM. Every diagnosis is
rule-based and deterministic.

## Contributing

```bash
go build ./...
go vet ./...
go test ./...
gofmt -l .
```

Tests must not depend on the public internet: use `httptest.Server`, a local
`net.Listener`, or a generated certificate. Everything in the suite runs
offline today, and it should stay that way.

A new failure mode usually means three small changes: an `ErrorKind` in
`internal/check`, a branch in the relevant checker's `classify` function with
its causes and suggested commands, and a rule in `internal/diagnosis`.

If a change alters what the terminal output looks like, re-record the demo:

```bash
brew install asciinema agg
docs/record-demo.sh
```

### Releasing

1. Update the `version` field in the JSON example above to the version being
   released. It is the one place in this file that names a specific version,
   and nothing enforces it.
2. Tag and push: `git tag -a vX.Y.Z -m "..." && git push origin vX.Y.Z`. The
   release workflow runs the tests and publishes the binaries.

## License

MIT. See [LICENSE](LICENSE).
