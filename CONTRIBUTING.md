# Contributing to RuntimeVerify

Thank you for your interest in contributing to **RuntimeVerify**! We welcome community contributions to strengthen runtime security, behavioral verification, and policy enforcement for autonomous AI agents.

This guide outlines our development environment, testing philosophy, coding standards, and Pull Request procedures.

---

## 1. Development Setup

The project uses [`uv`](https://github.com/astral-sh/uv) for fast, deterministic Python environment and dependency management.

### Prerequisites

- Python 3.10, 3.11, 3.12, or 3.13 installed
- `uv` installed (`curl -LsSf https://astral.sh/uv/install.sh | sh` or `pip install uv`)
- Git

### Initializing the Workspace

```bash
# 1. Clone the repository
git clone https://github.com/RadeshKK/Runtime-Verify.git
cd Runtime-Verify

# 2. Synchronize virtual environment with all optional extras and dev tools
uv sync --extra all --extra dev

# 3. Verify local environment by running the test suite
uv run pytest
```

---

## 2. Pull Request Quality Gates

Every Pull Request must pass our automated CI pipeline across all supported Python versions (**3.10, 3.11, 3.12, 3.13**).

Before opening a PR, run the local verification checklist:

| Verification Stage | Command | Purpose |
| :--- | :--- | :--- |
| **Formatting** | `uv run ruff format --check src/ tests/ examples/` | Enforces uniform code style (120 char limit) |
| **Linting** | `uv run ruff check src/ tests/ examples/` | Catches syntax errors, unused imports, anti-patterns |
| **Type Checking** | `uv run mypy src/` | Ensures strict type safety without missing types |
| **Unit & Integration Tests** | `uv run pytest --cov=runtimeverify tests/` | Validates functional behavior and code coverage |
| **Security Hardening Tests** | `uv run pytest tests/test_security_hardening.py -v` | Validates path traversal, IMDS/SSRF, replay defense |
| **Security Benchmarks** | `uv run pytest tests/test_security_benchmark.py -v` | Validates comparative detection across strategies |
| **Dependency Audit** | `uv run pip-audit` | Ensures zero known supply-chain vulnerabilities |
| **Package Validation** | `uv build && uv run twine check --strict dist/*` | Ensures distribution artifacts build and validate cleanly |

### Auto-Formatting Code

To format all files automatically with Ruff:

```bash
uv run ruff format src/ tests/ examples/
uv run ruff check --fix src/ tests/ examples/
```

---

## 3. Testing Policy & Integrity

> [!IMPORTANT]
> **Do not weaken tests merely to make CI pass.**
> - Never skip or delete existing test assertions to bypass failures.
> - Never loosen security boundaries (e.g. relaxing SSRF, path normalization, or replay defense) without formal design review.
> - When fixing a bug, first write a failing test reproducing the issue, then implement the fix.
> - All new features, policies, or engine detectors must include comprehensive unit and integration tests.

---

## 4. Branching & Commit Conventions

1. **Branch Names**: Use clear prefixes:
   - `feature/description` for new features or capabilities
   - `fix/description` for bug fixes
   - `security/description` for security mitigations or hardening
   - `docs/description` for documentation improvements
2. **Commit Messages**: Follow standard conventional commits:
   - `feat(policy): add support for CIDR subnet matching`
   - `fix(interceptor): prevent race condition during session disposal`
   - `security(network): block alternative hexadecimal IP notations`
   - `test(sprt): add edge case for zero variance transitions`

---

## 5. Submitting a Pull Request

1. Push your branch to your fork or origin:
   ```bash
   git push origin feature/my-feature-branch
   ```
2. Open a Pull Request targeting the `master` branch.
3. Complete the PR template description:
   - **Summary of Changes**: What was added, modified, or fixed?
   - **Threat / Security Impact**: Does this affect trust boundaries or policy enforcement?
   - **Test Evidence**: Provide output of `uv run pytest` and `uv run mypy src/`.
4. Ensure all CI checks (Formatting, Linting, MyPy, Tests, Security Audit, Package Check) turn green.

For questions or security vulnerability reports, please refer to our [Security Policy](file:///D:/runtime-verify/SECURITY.md).
