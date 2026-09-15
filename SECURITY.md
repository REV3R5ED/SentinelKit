# Security Policy

## Scope

SentinelKit is a defensive, local-analysis toolkit. Security reports are welcome for vulnerabilities in the package, CLI, parsing logic, packaging, or project automation.

Please do **not** include live credentials, private customer data, malware samples, or sensitive production logs in a public report. Use minimal synthetic reproductions whenever possible.

## Reporting a vulnerability

For a suspected vulnerability, use GitHub's private vulnerability reporting feature for this repository when it is available. If private reporting is unavailable, open a public issue containing only non-sensitive details and ask the maintainer for a private channel before sharing exploit details or sensitive evidence.

A useful report includes:

- affected SentinelKit version or commit;
- operating system and Python version;
- minimal reproduction steps using synthetic data;
- expected and observed behavior;
- security impact and any known mitigations.

## Supported versions

SentinelKit is currently pre-1.0. Security fixes are applied to the latest code on `main`; older snapshots are not maintained as separate supported release lines.

## Defensive-use boundary

SentinelKit is intended for authorized blue-team analysis. Reports or feature requests that add credential theft, persistence, evasion, exploitation, destructive behavior, or unauthorized access are out of scope for this project.
