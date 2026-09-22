# SentinelKit reproducible portfolio demo

This scenario gives reviewers a short, local, defensive workflow that exercises SentinelKit without contacting external systems or requiring sensitive data.

## Scenario

A SOC analyst receives a small sanitized authentication-log excerpt plus a text note containing indicators copied from an internal investigation. The goal is to quickly summarize authentication activity, normalize indicators, classify an IP literal, and hash an evidence file while keeping the workflow local and auditable.

Use only synthetic or sanitized data. SentinelKit does not need to resolve or contact extracted indicators for this demo.

## 1. Install the project

```bash
git clone https://github.com/REV3R5ED/SentinelKit.git
cd SentinelKit
python -m venv .venv
# Linux/macOS: source .venv/bin/activate
# Windows: .venv\Scripts\activate
python -m pip install -e .
sentinelkit --help
```

## 2. Create synthetic evidence

Create `demo-auth.log`:

```text
Sep 22 10:14:01 lab sshd[1001]: Failed password for invalid user guest from 192.0.2.44 port 51111 ssh2
Sep 22 10:14:08 lab sshd[1002]: Failed password for analyst from 192.0.2.44 port 51112 ssh2
Sep 22 10:15:10 lab sshd[1003]: Accepted publickey for analyst from 198.51.100.23 port 51113 ssh2
```

Create `demo-indicators.txt`:

```text
Review hxxps://portal[.]example[.]org/login and 192.0.2.44.
Contact observed: admin@example.org
Reference digest: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

The documentation-only example addresses and domains are reserved for examples; do not replace them with third-party targets for the demo.

## 3. Summarize authentication activity

```bash
sentinelkit logs ./demo-auth.log
```

Review the reported failed/successful authentication counts and invalid-user activity. The purpose is triage and summarization, not an incident verdict.

## 4. Normalize indicators locally

```bash
sentinelkit ioc ./demo-indicators.txt
```

Confirm that the defanged URL/domain is normalized and that IP, email, and hash indicators are extracted. This processing is local: the IOC extractor does not resolve or request the indicators.

## 5. Classify an address

```bash
sentinelkit ip 192.0.2.44
```

This demonstrates deterministic literal-address inspection without scanning a network.

## 6. Hash the evidence file

```bash
sentinelkit hash ./demo-indicators.txt
```

Record the SHA-256 value alongside the analysis notes to demonstrate evidence-integrity handling.

## What this demonstrates

A reviewer can verify four portfolio skills in a few minutes:

- defensive authentication-log triage;
- safe IOC extraction and defang normalization;
- deterministic IP classification;
- local evidence hashing and CLI-oriented workflows.

The workflow is intentionally small and explainable. It avoids exploitation, credential attacks, broad scanning, persistence, or contacting third-party infrastructure.

## Portfolio context

SentinelKit is the SOC/triage layer of the portfolio. For adjacent workflows see:

- [LogLens](https://github.com/REV3R5ED/LogLens) for deeper deterministic log analysis and anomaly reporting;
- [NetScope](https://github.com/REV3R5ED/NetScope) for bounded network diagnostics;
- [AutoOPS](https://github.com/REV3R5ED/AutoOPS) for safe IT operations checks and automation.
