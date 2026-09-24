# Release readiness checklist

SentinelKit releases should represent a reproducible, tested defensive-analysis tool rather than a version number alone. Use this checklist before creating a Git tag or GitHub release.

## 1. Version and release notes

- Choose the release version using semantic versioning.
- Update `project.version` in `pyproject.toml`.
- Record user-visible changes in release notes, including compatibility or output-contract changes.
- Confirm the README capability list and examples describe the version being released.

## 2. Quality and compatibility gates

The release candidate must pass the same gates enforced by CI:

```bash
python -m pip install -e . pytest ruff build twine
ruff check src tests
ruff format --check src tests
pytest -q
python -m build
python -m twine check dist/*
```

CI additionally runs the test suite on every supported Python version declared by the project (currently Python 3.10–3.13). Do not tag a release until the exact candidate commit is green across that matrix.

## 3. Installed-package smoke test

Test the built artifact rather than only the editable source tree:

```bash
python -m venv .release-venv
# Linux/macOS: source .release-venv/bin/activate
# Windows: .release-venv\Scripts\activate
python -m pip install dist/*.whl
sentinelkit --help
```

Run at least one local, synthetic-input command from `docs/portfolio-demo.md` to confirm the installed CLI behaves as documented.

## 4. Defensive-safety review

Before release, verify that new behavior:

- operates only on local input or explicitly authorized targets;
- does not add exploitation, credential theft, persistence, evasion, or destructive behavior;
- does not silently resolve, request, or contact extracted indicators;
- keeps structured output deterministic enough for automation and review;
- avoids embedding secrets, private evidence, or real incident data in tests/examples.

## 5. Tag and publish

After CI passes on the exact candidate commit:

1. Create an annotated `vX.Y.Z` tag pointing to that commit.
2. Create a GitHub release from the same tag with concise user-facing notes.
3. Attach or publish only artifacts produced from the verified source revision.
4. Re-run the documented install/quick-start path against the released artifact when distribution is enabled.

## Current status

The repository declares version `0.1.0`, but a version in package metadata is not by itself evidence of a published release. Until a corresponding verified tag and GitHub release exist, treat the project as unreleased development software.
