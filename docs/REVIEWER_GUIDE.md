# SentinelKit reviewer guide

This guide gives recruiters, maintainers, and security practitioners a focused path for evaluating SentinelKit as a defensive Python portfolio project.

## Five-minute review

### 1. Install locally

```bash
python -m venv .venv
# Linux/macOS: source .venv/bin/activate
# Windows: .venv\Scripts\activate
pip install -e .
sentinelkit --help
```

### 2. Run the automated tests

```bash
python -m pytest
```

The test suite is the quickest way to verify that parsing, normalization, classification, and CLI behavior remain deterministic as the project evolves.

### 3. Exercise representative defensive workflows

```bash
sentinelkit hash ./sample.bin
sentinelkit ip 8.8.8.8
sentinelkit ioc ./sample.log
sentinelkit logs ./auth.log
```

These commands cover the project's core portfolio story: local artifact inspection, network-indicator classification, IOC extraction, and authentication-log triage.

### 4. Inspect the implementation

Useful areas to review include:

- IOC extraction and defang normalization, including IPv4/IPv6 validation and canonicalization.
- Authentication-log parsing and explainable summaries rather than opaque scoring.
- Structured JSON output intended for scripting and reproducible analysis.
- Tests and GitHub Actions as the regression boundary for supported behavior.

## Security and trust boundaries

SentinelKit is intentionally defensive and local-first. IOC extraction normalizes analyst-friendly defanged indicators but does not resolve domains, request URLs, scan hosts, exploit services, steal credentials, establish persistence, or attempt evasion. Inputs should still come from systems, files, and datasets you own or are authorized to analyze.

This boundary is important to the project design: useful SOC/Blue Team analysis should remain auditable and safe to reproduce in a lab, code review, or interview setting.

## What this project demonstrates

A reviewer should be able to evaluate:

- Python CLI and package design.
- Deterministic parsing and normalization of security telemetry.
- Defensive network and IOC handling.
- Automated regression testing and CI discipline.
- Clear separation between inspection/analysis and active or offensive behavior.

## Suggested deeper review

After the five-minute path, compare the README roadmap with the implementation and tests, inspect recent pull requests for change discipline, and review CI before relying on a commit or future release. Packaged releases and additional rule-based enrichment remain roadmap work rather than implied finished functionality.
