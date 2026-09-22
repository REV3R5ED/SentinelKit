# 🛡️ SentinelKit

**Python Blue Team and SOC analyst CLI for fast, explainable defensive security analysis.**

SentinelKit is a lightweight defensive cybersecurity toolkit for Blue Team and SOC workflows. It gives security analysts, system administrators, students, and developers auditable command-line utilities for IOC extraction, IP analysis, file hashing, and authentication-log triage without requiring a heavy security platform.

> SentinelKit is built for authorized defensive analysis. It is not an exploitation framework.

## ✨ Current capabilities

- 🔐 **Hash Inspector** — identify common digest formats and calculate SHA-256 for files
- 🌐 **IP Inspector** — validate and classify IPv4/IPv6 addresses
- 📄 **Log Analyzer** — summarize SSH authentication failures, successful logins, and invalid-user attempts
- 🧩 **IOC Extractor** — extract IPv4/IPv6 addresses, domains, URLs, emails, and hashes from text, including common defanged forms such as `hxxps://example[.]org`
- 💻 **CLI-first design** — scriptable commands with structured JSON output

## 🎯 Who it is for

SentinelKit is designed as a small, inspectable security tool for SOC analysts and Blue Team practitioners who want deterministic local analysis that can also fit into scripts, incident-response notes, SIEM-adjacent workflows, and cybersecurity labs.

### Reviewer quick path

Want to see the project working without external infrastructure? Run the [reproducible defensive triage demo](docs/portfolio-demo.md). It uses synthetic evidence to exercise authentication-log triage, defanged IOC normalization, IP classification, and evidence hashing entirely locally.

## 🚀 Quick start

```bash
git clone https://github.com/REV3R5ED/SentinelKit.git
cd SentinelKit
python -m venv .venv
# Linux/macOS: source .venv/bin/activate
# Windows: .venv\Scripts\activate
pip install -e .
sentinelkit --help
```

## Examples

```bash
sentinelkit hash ./sample.bin
sentinelkit ip 8.8.8.8
sentinelkit ioc ./sample.log
sentinelkit logs ./auth.log
```

The IOC extractor safely normalizes common analyst defanging such as `[.]`, `(.)`, `[dot]`, `(dot)`, `hxxp://`, and `hxxps://` before parsing. IPv6 literals are validated with Python's `ipaddress` module, canonicalized, and deduplicated; bracketed IPv6 URL hosts are kept out of the domain list. Normalization and validation are local processing only; SentinelKit does not resolve, request, or otherwise contact extracted indicators.

Example IOC output:

```json
{
  "ipv4": ["192.168.1.5"],
  "url": ["https://sub.example.org/path"],
  "email": ["admin@example.com"],
  "hash": [],
  "ipv6": ["2001:db8::1"],
  "domain": ["example.com", "sub.example.org"]
}
```

## 🔎 Discoverability keywords

SentinelKit focuses on defensive cybersecurity, Blue Team operations, SOC analyst workflows, incident response, IOC extraction and normalization, authentication-log analysis, Python security tooling, and command-line security automation.

## 🧱 Project principles

- Defensive and authorization-first
- Standard library first where practical
- Explainable output instead of opaque scores
- Testable, typed Python
- Useful both interactively and in automation

## 🗺️ Roadmap

- [x] Project architecture
- [x] Hash inspection
- [x] IP classification
- [x] IOC extraction
- [x] IPv6 IOC extraction
- [x] Defanged IOC normalization
- [x] Domain extraction
- [x] Authentication log summary
- [x] Structured JSON output
- [x] Automated test suite
- [x] GitHub Actions workflow
- [x] Reproducible defensive portfolio demo
- [ ] Rule-based IOC enrichment
- [ ] Plugin interface
- [ ] Packaged releases

## 🔗 Related portfolio projects

- [LogLens](https://github.com/REV3R5ED/LogLens) — deterministic log analysis and anomaly reporting
- [NetScope](https://github.com/REV3R5ED/NetScope) — bounded network visibility and diagnostics
- [AutoOPS](https://github.com/REV3R5ED/AutoOPS) — safe IT operations checks and automation

Together, the projects cover a practical defensive workflow from operational readiness and network diagnostics through log analysis and SOC-oriented triage.

## ⚖️ Responsible use

Use SentinelKit only on systems, files, and data you own or are explicitly authorized to analyze. The project intentionally focuses on defensive inspection and does not include exploitation, credential theft, persistence, or evasion features.

## 🤝 Contributing

Issues and pull requests are welcome. Keep contributions defensive, documented, and covered by tests when possible.

## 📜 License

MIT
