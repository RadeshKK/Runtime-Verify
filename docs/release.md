# RuntimeVerify Release Procedures

This document defines the formal procedures for building, validating, and publishing official releases of **RuntimeVerify** (`runtimeverify`).

---

## 1. Release Philosophy & Versioning

RuntimeVerify strictly follows [Semantic Versioning 2.0.0](https://semver.org/):

- **MAJOR (`X.0.0`)**: Incompatible API breaks, major security model restructuring, or removed policy primitives.
- **MINOR (`0.X.0`)**: Backwards-compatible new features, new verification engines, or additional telemetry collectors.
- **PATCH (`0.0.X`)**: Backwards-compatible bug fixes, security patches, and performance optimizations.

---

## 2. Release Security & Access Control

1. **Publishing Security (OIDC / Trusted Publishing)**:
   - Releases are published to PyPI using **GitHub Actions OpenID Connect (OIDC)** Trusted Publishing (`pypa/gh-action-pypi-publish`).
   - No long-lived PyPI API tokens or passwords are stored in repository secrets.
   - GitHub dynamically issues short-lived cryptographic tokens linked specifically to the `runtimeverify` package on PyPI.
2. **Environment Protection**:
   - The `publish-pypi` job is scoped to the protected `pypi` GitHub environment.
   - Publishing can only occur through tagged commits (`refs/tags/v*.*.*`) or explicit manual approval by repository maintainers.
3. **Artifact Integrity**:
   - Every release generates cryptographic SHA-256 checksums (`CHECKSUMS.sha256`) for both the source distribution (`.tar.gz`) and binary wheel (`.whl`).
   - Artifacts are verified with strict metadata checks (`twine check --strict`).

---

## 3. Pre-Release Checklist

Before tagging a release, maintainers must perform the following validation:

```bash
# 1. Ensure working directory is clean and up to date
git checkout master
git pull origin master

# 2. Run the complete local CI suite
uv sync --extra all --extra dev
uv run ruff format --check src/ tests/ examples/
uv run ruff check src/ tests/ examples/
uv run mypy src/
uv run pytest --cov=runtimeverify tests/
uv run pip-audit

# 3. Test packaging build and Twine metadata validation
uv build
uv run twine check --strict dist/*
```

### Version Consistency Check

1. Update the version string in [`pyproject.toml`](file:///D:/runtime-verify/pyproject.toml):
   ```toml
   [project]
   version = "0.1.0"
   ```
2. Update [`CHANGELOG.md`](file:///D:/runtime-verify/CHANGELOG.md) with notes under the target version section:
   - Added capabilities
   - Bug fixes & security hardening
   - Breaking changes or deprecations
3. Commit the changes:
   ```bash
   git commit -am "chore(release): bump version to v0.1.0"
   git push origin master
   ```

---

## 4. Release Execution Workflow

Releases can be initiated through either **Git Tagging** or **Manual Workflow Dispatch**.

### Method A: Tagged Release (Standard)

Creating and pushing an annotated Git tag matching `v*.*.*` automatically triggers the `.github/workflows/release.yml` pipeline:

```bash
# 1. Create an annotated git tag
git tag -a v0.1.0 -m "Release v0.1.0: Production Runtime Verification Pipeline"

# 2. Push tag to GitHub
git push origin v0.1.0
```

The release pipeline executes the following stages:
1. **`build-and-validate`**:
   - Confirms that the Git tag version matches the `pyproject.toml` version.
   - Builds distribution wheels and source archives using `uv build`.
   - Validates package metadata using `twine check --strict`.
   - Generates SHA-256 hashes (`CHECKSUMS.sha256`).
   - Runs a smoke test by installing the generated wheel into a clean virtual environment and running CLI checks.
2. **`github-release`**:
   - Creates an official GitHub Release with release notes and attaches distribution archives and `CHECKSUMS.sha256`.
3. **`publish-pypi`**:
   - Publishes the verified distribution packages directly to PyPI via OIDC Trusted Publishing.

---

### Method B: Manual Workflow Dispatch (Dry-Run / Staged)

Maintainers can also trigger the release pipeline manually from the GitHub Actions UI:

1. Navigate to **Actions** -> **Release** workflow.
2. Click **Run workflow**.
3. Select parameters:
   - `publish_pypi`: `false` (for dry-run artifact validation) or `true` (for publishing).
   - `dry_run`: `true` to skip PyPI publication and only verify packaging.

---

## 5. Post-Release Verification

After the release workflow completes, verify that the package is available on PyPI from an external clean environment:

```bash
# In an isolated environment without local repo imports
python -m venv test_pypi_env
source test_pypi_env/bin/activate  # or test_pypi_env\Scripts\activate on Windows

# Install from PyPI
pip install runtimeverify

# Validate CLI
runtimeverify version
runtimeverify check --command "git status"
runtimeverify check --command "cat /etc/shadow"

# Validate SDK import
python -c "import runtimeverify; print(runtimeverify.__version__)"
```

---

## 6. Emergency Deprecation & Rollback

In the event of a critical security regression or accidental broken release:

1. **Yank the Release on PyPI**:
   - PyPI does not permit deleting or re-uploading the same version string.
   - Use the PyPI Management Console or API to mark the broken version as **Yanked** (preventing new installs while preserving reproducibility for pinned dependencies).
2. **Issue Emergency Hotfix**:
   - Create a hotfix branch: `git checkout -b fix/emergency-hotfix`.
   - Address the regression and increment the patch version (e.g. `0.1.1`).
   - Run the pre-release checklist and tag `v0.1.1`.
3. **Publish Post-Mortem**:
   - Add security advisory or post-mortem notes to [`SECURITY.md`](file:///D:/runtime-verify/SECURITY.md) and [`CHANGELOG.md`](file:///D:/runtime-verify/CHANGELOG.md).
