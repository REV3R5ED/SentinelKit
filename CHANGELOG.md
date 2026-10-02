# Changelog

All notable changes to SentinelKit are recorded here. The project is pre-release (0.1.0); there is no tagged release yet.

## Unreleased

### Fixed

- Hash extraction regex now matches SHA-384 (96 hex) and SHA-512 (128 hex) digests. Previously `identify_hash` advertised these families but the IOC extractor only matched 32/40/64 hex, so SHA-384/512 IOCs were silently never extracted.
- `sha256_file()` now raises a clean `SentinelKitError` (reported by the CLI as an argparse error, no traceback) when a file cannot be read, e.g. permission denied.

### Added

- `--version` flag printing the package version.
- `-` accepted as a file argument for `ioc`, `triage`, and `logs` (reads stdin, e.g. `journalctl | sentinelkit logs -`); `sentinelkit hash -` hashes stdin bytes.
- Rule-based offline IOC enrichment layered onto `summarize_iocs` / `triage`: RFC1918 and CGNAT (100.64.0.0/10) address flags, suspicious TLD/host patterns (punycode, long DNS labels, IP-literal URL hosts), and analyst-supplied hash/domain blocklists loaded from TOML (stdlib `tomllib`, Python 3.11+) or YAML (tiny built-in parser). Findings fold into the `reasons` array; blocklist matches escalate priority to high. No network calls.
- Multi-format log parsing for `logs`: syslog, systemd-journal (classic and ISO-8601 timestamps), and CSV with flexible headers, plus auto-detection (override with `--log-format`). Sliding-window brute-force suspect detection via `--threshold` (default 5) and `--window` minutes (default 10), with a documented fallback when timestamps are absent. Output `--format` is accepted before or after the subcommand.
- STIX 2.1 export: `sentinelkit ioc --format stix ./case.txt` emits a deterministic bundle (identity + indicators with STIX patterns) for import into threat-intel platforms. Hand-rolled, dependency-free.
- `mypy` type checking in CI; coverage configuration (`[tool.coverage.*]`) with a CI coverage job (`--fail-under=90`).
- Expanded test suite: 84 tests covering error paths, edge cases, and every new behavior; 97% total coverage.

### Changed

- `summarize_iocs()` accepts an optional `EnrichmentConfig` and now includes an `enrichment` findings object in its output alongside `reasons`.
- `summarize_auth_log()` accepts `failed_threshold` / `window_minutes` and reports `log_format` plus `brute_force_suspects`.
- README rewritten: real install instructions, per-command sample input/output, less emoji; roadmap updated.
- Pinned ruff lint rule set in `pyproject.toml` for stable CI; documented exclusion of DTZ (syslog timestamps are inherently naive and normalized to naive UTC).
