# SentinelKit

**Offline, dependency-free CLI toolkit for defensive security analysis (SOC / Blue Team).**

SentinelKit gives analysts scriptable command-line utilities for IOC extraction, IP classification, file hashing, and authentication-log triage. It is deliberately small (~600 lines), has zero third-party dependencies, makes no network calls, and keeps every triage decision explainable: priorities are heuristic and always ship with stated reasons, never an opaque score.

> Built for authorized defensive analysis. Not an exploitation framework. See [SECURITY.md](SECURITY.md).

## Capabilities

- **Hash Inspector** — identify digest families (MD5, SHA-1, SHA-256, SHA-384, SHA-512) and compute SHA-256 for files
- **IP Inspector** — validate and classify IPv4/IPv6 addresses
- **IOC Extractor** — extract IPv4/IPv6, domains, URLs, emails, and hashes from arbitrary text, including defanged forms (`hxxps://example[.]org`, `malware(dot)test`)
- **Offline IOC enrichment** — flag RFC1918/CGNAT addresses, suspicious TLD/host patterns (punycode, long labels, IP-literal URL hosts), and analyst-supplied hash/domain blocklists (TOML or YAML), folded into triage reasons
- **Triage** — deterministic IOC counts plus an explainable high/medium/low priority with reasons
- **Log Analyzer** — summarize SSH auth events from syslog, systemd-journal, and CSV logs; sliding-window brute-force suspect detection (`--threshold`, `--window`)
- **STIX 2.1 export** — emit extracted IOCs as a STIX 2.1 bundle for threat-intel platforms
- **CLI-first** — structured JSON output (default), human-readable text mode, stdin piping via `-`

## Installation

Requires Python 3.10+.

Install from the repository (pre-release; no tagged release yet):

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
python -m pip install "git+https://github.com/REV3R5ED/SentinelKit.git"
sentinelkit --help
```

For a reproducible evaluation, pin the commit you intend to review:

```bash
python -m pip install "git+https://github.com/REV3R5ED/SentinelKit.git@<commit-sha>"
```

For development or running the test suite, use an editable checkout:

```bash
git clone https://github.com/REV3R5ED/SentinelKit.git
cd SentinelKit
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
python -m pip install -e . pytest ruff mypy coverage
pytest -q
```

## Usage

Global options: `--format {json,text,stix}` (default `json`; `stix` is only valid for `ioc`), `--version`. Any command that takes a file also accepts `-` for stdin, so piping works: `journalctl | sentinelkit logs -`.

### `hash` — identify digests and hash files

```bash
sentinelkit hash ./sample.bin
sentinelkit hash 5d41402abc4b2a76b9719d911017c592   # digest string
echo -n "data" | sentinelkit hash -                  # hash stdin bytes
```

```json
{
  "value": "5d41402abc4b2a76b9719d911017c592",
  "likely_type": "MD5"
}
```

### `ip` — classify an address

```bash
sentinelkit ip 8.8.8.8
```

```json
{
  "address": "8.8.8.8",
  "version": 4,
  "private": false,
  "global": true,
  "loopback": false,
  "multicast": false,
  "reserved": false
}
```

### `ioc` — extract indicators

`case.txt`:

```text
Reported sender: security@accounts[.]example
Message URL: hxxps://accounts[.]example/verify
Proxy observation: 198.51.100.42
```

```bash
sentinelkit ioc ./case.txt
```

```json
{
  "ipv4": ["198.51.100.42"],
  "url": ["https://accounts.example/verify"],
  "email": ["security@accounts.example"],
  "hash": [],
  "ipv6": [],
  "domain": ["accounts.example"]
}
```

Defanging (`[.]`, `(.)`, `[dot]`, `(dot)`, `hxxp://`, `hxxps://`) is normalized before parsing. IPv6 literals are validated, canonicalized, and deduplicated; bracketed IPv6 URL hosts are kept out of the domain list. SHA-384 and SHA-512 digests are extracted alongside MD5/SHA-1/SHA-256.

STIX 2.1 export (deterministic IDs, no dependencies, no network):

```bash
sentinelkit ioc --format stix ./case.txt
```

```json
{
  "type": "bundle",
  "id": "bundle--366cfc76-2c10-5c6b-938d-08c31cbfebde",
  "objects": [
    {
      "type": "identity",
      "spec_version": "2.1",
      "id": "identity--5cb58d1a-04da-50aa-a73d-2b6b19b83af6",
      "name": "SentinelKit",
      "identity_class": "tool"
    },
    {
      "type": "indicator",
      "spec_version": "2.1",
      "id": "indicator--2a1a6932-53ce-53ce-8d49-20333af67899",
      "name": "SentinelKit IOC: domain accounts.example",
      "indicator_types": ["anomalous-activity"],
      "pattern": "[domain-name:value = 'accounts.example']",
      "pattern_type": "stix",
      "valid_from": "2026-10-02T21:53:53.819Z"
    }
  ]
}
```

### `triage` — counts, enrichment, and explainable priority

```bash
sentinelkit triage ./case.txt
sentinelkit triage --enrich ./blocklists.toml ./case.txt
```

```json
{
  "total_indicators": 5,
  "counts": {"ipv4": 1, "ipv6": 0, "url": 1, "email": 1, "hash": 1, "domain": 1},
  "triage_priority": "high",
  "reasons": [
    "URL present",
    "cryptographic hash present",
    "network address present"
  ],
  "enrichment": {
    "private_addresses": [],
    "cgnat_addresses": [],
    "suspicious_hosts": [],
    "blocklisted": []
  }
}
```

Priority rules (heuristic, not a verdict):

- **high** — a URL, a cryptographic hash, or a blocklist match is present
- **medium** — network addresses present, none of the above
- **low** — other indicators only

Enrichment is fully offline and appends to `reasons`, for example:

- `private address: 192.168.1.5 (RFC1918 192.168.0.0/16)`
- `CGNAT address: 100.64.0.9 (CGNAT 100.64.0.0/10)`
- `suspicious host: invoice-update.zip (suspicious TLD: .zip)`
- `domain evil.example (blocklisted domain)` — also escalates priority to high

Analyst blocklists are supplied as TOML (Python 3.11+; stdlib `tomllib`) or YAML (tiny built-in parser, no dependency):

```toml
# blocklists.toml
[blocklists]
hashes = ["<sha256 hex digest>"]
domains = ["evil.example"]
suspicious_tlds = ["zip", "top"]   # optional; overrides the built-in set
```

```yaml
# blocklists.yaml
hashes:
  - "<sha256 hex digest>"
domains:
  - evil.example
```

### `logs` — summarize authentication logs

Auto-detects syslog, systemd-journal (classic and ISO-8601), and CSV formats; override with `--log-format`. Output format (`--format`) works before or after the subcommand. Brute-force suspects are flagged when a source reaches `--threshold` failed logins (default 5) inside a sliding `--window` minutes window (default 10). Without timestamps the threshold applies to per-source totals and the reason says so.

```bash
sentinelkit logs ./auth.log
sentinelkit logs --log-format journal --threshold 5 --window 10 ./journal-export.log
journalctl -u sshd --since today | sentinelkit logs -
```

`auth.log`:

```text
Sep 22 10:14:01 lab sshd[1001]: Failed password for invalid user guest from 192.0.2.44 port 51111 ssh2
Sep 22 10:14:08 lab sshd[1002]: Failed password for analyst from 192.0.2.44 port 51112 ssh2
Sep 22 10:15:10 lab sshd[1003]: Accepted publickey for analyst from 198.51.100.23 port 51113 ssh2
```

```json
{
  "log_format": "syslog",
  "failed_attempts": 2,
  "successful_logins": 1,
  "top_failed_sources": [["192.0.2.44", 2]],
  "successful_sources": ["198.51.100.23"],
  "invalid_user_attempts": 1,
  "top_invalid_usernames": [["guest", 1]],
  "brute_force_suspects": [
    {
      "source": "192.0.2.44",
      "failures": 2,
      "window_minutes": 10,
      "max_failures_in_window": 2,
      "first_seen": "2026-09-22T10:14:01",
      "last_seen": "2026-09-22T10:14:08",
      "reason": "2 failed logins within 10 minutes"
    }
  ]
}
```

CSV input uses flexible headers (`timestamp`/`time`, `host`/`hostname`, `process`/`service`, `message`/`msg`):

```csv
timestamp,host,process,message
2026-10-02T14:31:05+00:00,web,sshd,Failed password for root from 203.0.113.9 port 40211 ssh2
```

## Offline guarantee

SentinelKit performs no DNS resolution, no HTTP requests, and no other network calls. IOC normalization, enrichment, and STIX export are pure local computation. Do not add network-dependent enrichment that silently changes this guarantee (see [CONTRIBUTING.md](CONTRIBUTING.md)).

## Project principles

- Defensive and authorization-first
- Standard library first; zero third-party dependencies
- Explainable output instead of opaque scores
- Testable, typed Python (ruff, mypy, and coverage enforced in CI)
- Useful both interactively and in automation

## Roadmap

- [x] Project architecture
- [x] Hash inspection
- [x] IP classification
- [x] IOC extraction (incl. SHA-384/512, IPv6, defang normalization, domains)
- [x] Authentication log summary
- [x] Structured JSON output
- [x] Automated test suite
- [x] GitHub Actions workflow
- [x] Reproducible defensive portfolio demo
- [x] Rule-based offline IOC enrichment
- [x] Multi-format log parsing and brute-force detection
- [x] STIX 2.1 export
- [ ] Packaged releases

Deferred: a plugin interface via `importlib.metadata` entry points — premature at 0.1.0.

## Related portfolio projects

- [LogLens](https://github.com/REV3R5ED/LogLens) — deterministic log analysis and anomaly reporting
- [NetScope](https://github.com/REV3R5ED/NetScope) — bounded network visibility and diagnostics
- [AutoOPS](https://github.com/REV3R5ED/AutoOPS) — safe IT operations checks and automation

Together, the projects cover a practical defensive workflow from operational readiness and network diagnostics through log analysis and SOC-oriented triage.

## Responsible use

Use SentinelKit only on systems, files, and data you own or are explicitly authorized to analyze. The project intentionally focuses on defensive inspection and does not include exploitation, credential theft, persistence, or evasion features.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Keep contributions defensive, documented, and covered by tests. Reviewer walkthrough: [docs/REVIEWER_GUIDE.md](docs/REVIEWER_GUIDE.md). Reproducible demo: [docs/portfolio-demo.md](docs/portfolio-demo.md).

## License

MIT — see [LICENSE](LICENSE).
