# Contributing to `runtimeverify`

Thank you for your interest in contributing to `runtimeverify`! We welcome community contributions to make AI agent behavior more secure, robust, and verifiable.

## Development Setup

The project uses `uv` for python package and dependency management.

1. **Fork and Clone the Repository**
2. **Setup the Virtual Environment & Dependencies**
   ```bash
   uv sync
   ```
3. **Run the Test Suite**
   Ensure all tests pass before making any changes:
   ```bash
   uv run pytest
   ```

## Code Style & Standards

We enforce strict linting and type-safety rules:

* **Format and Lint Checks:** We use `ruff` to lint the code. Run before committing:
  ```bash
  uv run ruff check src/
  ```
* **Static Type Safety:** We use `mypy` with strict pydantic plugins. Run to ensure no type issues:
  ```bash
  uv run mypy src/
  ```
* **Code Coverage:** All new features must include unit tests. Total package coverage must stay above **90%**:
  ```bash
  uv run pytest --cov=src
  ```

## Pull Request Guidelines

1. Create a descriptive feature branch: `git checkout -b feature/my-cool-improvement`.
2. Commit your modifications with clean, structured messages.
3. Ensure Ruff checks, MyPy type checks, and pytest coverage are passing.
4. Submit a Pull Request targeting the `main` branch.
