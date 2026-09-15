# SOC case study

This directory contains a synthetic incident showing how SentinelKit fits into a defensive analyst workflow. The same fixture is exercised by `tests/test_soc_scenario.py`, making the example executable documentation rather than a static demo.

## Credential-phishing triage

A user reports a suspicious verification message. The case contains a defanged sender/domain, a defanged URL, IPv4 and IPv6 observations, and a sample SHA-256 value. The indicators use documentation-only namespaces and synthetic values.

Run the extractor locally:

```bash
sentinelkit ioc examples/soc_phishing_case.txt
```

Expected normalized findings include:

```text
email   security@accounts.example
domain  accounts.example
url     https://accounts.example/verify
ip      198.51.100.42
ip      2001:db8::42
```

SentinelKit should normalize the defanged indicators (`[.]` and `hxxps://`) before extraction. The workflow is deliberately offline: it does not resolve the domain, visit the URL, scan either address, or make other network requests.

## Regression protection

`tests/test_soc_scenario.py` reads this exact case and asserts the expected analyst findings. The repository CI therefore checks this documented workflow whenever the test suite runs. Parser or normalization regressions fail CI instead of silently changing the example.
