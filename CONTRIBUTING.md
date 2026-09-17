# Contributing to SentinelKit

Thanks for helping improve SentinelKit. Contributions should keep the project focused on defensive, authorized security analysis and predictable CLI behavior.

## Development setup

SentinelKit supports Python 3.10 through 3.13.

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
python -m pip install --upgrade pip
python -m pip install -e . pytest ruff
```

## Validate a change

Run the same core checks enforced by CI before opening a pull request:

```bash
ruff check src tests
ruff format --check src tests
pytest -q
sentinelkit --help
```

When changing packaging behavior, also build and inspect the distributions:

```bash
python -m pip install build
python -m build
python -m pip install dist/*.whl
sentinelkit --help
```

## Contribution expectations

- Add or update tests for behavior changes and bug fixes.
- Keep CLI output deterministic where practical, especially JSON intended for automation.
- Update README examples or other documentation when user-facing behavior changes.
- Prefer small, reviewable pull requests with a clear problem statement and validation notes.
- Do not commit credentials, tokens, private logs, customer data, or other sensitive material. Use synthetic fixtures and documentation-safe IP/domain ranges in examples.

## Defensive-use boundary

SentinelKit is a Blue-Team/SOC utility. Contributions should support defensive analysis such as IOC extraction, log review, incident-response workflows, validation, and explainable triage.

Do not add exploit delivery, credential theft, persistence, evasion, destructive actions, unauthorized scanning, or other offensive capability. Network-dependent enrichment should not silently change the project's offline/passive analysis guarantees.

For security vulnerabilities in SentinelKit itself, follow [SECURITY.md](SECURITY.md) instead of opening a public issue with sensitive details.

## Pull requests

Before submitting a pull request:

1. Rebase or update your branch from current `main`.
2. Run the validation commands above.
3. Describe what changed, why it matters, and how it was tested.
4. Call out any CLI, JSON schema, packaging, or compatibility impact explicitly.

CI tests supported Python versions and validates the package artifact. A pull request should be considered ready to merge only after its required checks pass.
