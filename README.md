# 🛡️ SentinelKit

**Defensive security utilities for fast, explainable analysis.**

SentinelKit is a Python toolkit for blue-team analysts, system administrators, students, and developers who need small, auditable security utilities without a heavy platform.

> SentinelKit is built for authorized defensive analysis. It is not an exploitation framework.

## ✨ Initial capabilities

- 🔐 **Hash Inspector** — identify common digest formats and compare file hashes
- 🌐 **IP Inspector** — validate and classify IPv4/IPv6 addresses
- 📄 **Log Analyzer** — summarize authentication events and surface suspicious patterns
- 🧩 **IOC Extractor** — extract IP addresses, domains, URLs, emails, and hashes from text
- 💻 **CLI-first design** — scriptable commands with human-readable output

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
- [x] Authentication log summary
- [ ] JSON output for SIEM pipelines
- [ ] Rule-based IOC enrichment
- [ ] Plugin interface
- [ ] Packaged releases

## ⚖️ Responsible use

Use SentinelKit only on systems, files, and data you own or are explicitly authorized to analyze. The project intentionally focuses on defensive inspection and does not include exploitation, credential theft, persistence, or evasion features.

## 🤝 Contributing

Issues and pull requests are welcome. Keep contributions defensive, documented, and covered by tests when possible.

## 📜 License

MIT
