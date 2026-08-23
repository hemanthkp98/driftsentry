# Development

Set up a local development environment, run test suites, check code formatting, and contribute to DriftSentry.

---

## Local Environment Setup

Clone the repository and install DriftSentry in editable mode with development dependencies:

```bash
git clone https://github.com/hemanthkp98/driftsentry.git
cd driftsentry

# Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install package with development tools
pip install -e ".[dev]"
```

Alternatively, use the provided Makefile:

```bash
make dev
```

---

## Running Tests

DriftSentry uses [pytest](https://docs.pytest.org/) with [pytest-cov](https://pytest-cov.readthedocs.io/) for unit and integration testing.

```bash
# Run all unit tests with verbose output
pytest tests/ -v

# Run tests with code coverage report
pytest tests/ -v --cov=driftsentry --cov-report=term-missing

# Using Makefile
make test
```

---

## Linting & Type Checking

DriftSentry enforces strict code standards using [Ruff](https://docs.astral.sh/ruff/) and [MyPy](https://mypy.readthedocs.io/):

```bash
# Check code style with Ruff
ruff check src/ tests/

# Check formatting without modifying files
ruff format --check src/ tests/

# Format code automatically
ruff format src/ tests/

# Run static type checking
mypy src/driftsentry/

# Run all checks via Makefile
make lint
```

---

## Project Conventions

- **Code Structure**: All core logic lives under `src/driftsentry/` with functional separation for collectors, providers, diff engine, attribution, policy, remediation, and CLI.
- **Provider Abstraction**: Cloud resource collection is abstracted under `src/driftsentry/providers/`.
- **Contribution Workflow**: For complete PR checklists and contribution guidelines, see [CONTRIBUTING.md](../CONTRIBUTING.md).
