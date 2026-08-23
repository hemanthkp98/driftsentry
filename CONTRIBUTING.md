# Contributing to DriftSentry

Guidelines and workflow for contributing bug reports, feature enhancements, documentation, and code to DriftSentry.

---

## Development Setup

For complete local setup instructions, test commands, and quality checks, see [Development Guide](docs/development.md).

### Quickstart

```bash
git clone https://github.com/hemanthkp98/driftsentry.git
cd driftsentry

python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

---

## Running Tests & Quality Checks

We use `pytest` for testing, `ruff` for linting and formatting, and `mypy` for static type checking:

```bash
# Run all unit tests
make test

# Run tests with coverage
make test-cov

# Run linter and type checker
make lint

# Auto-format code
make format

# Run full CI check locally
make ci
```

---

## Adding Support for a New AWS Resource Type

To add support for a new AWS resource type (e.g. `aws_sqs_queue`), see the detailed guide in [Custom Resources](docs/custom-resources.md):

1. **Add resource mapping** in `src/driftsentry/providers/aws/mapping.py`:
   Define the Terraform type, AWS service, security-critical attributes, and noise attributes.
2. **Implement scanner** in `src/driftsentry/providers/aws/resources/`:
   Implement `list_all()`, `get_by_id()`, and `normalize()`.
3. **Register scanner** in `src/driftsentry/providers/aws/provider.py`.
4. **Add CloudTrail event mapping** in `src/driftsentry/attribution/cloudtrail.py`.
5. **Add unit tests** in `tests/unit/`.

---

## Pull Request Guidelines

- Ensure all existing and new tests pass (`make ci`).
- Add tests for any new features or bug fixes.
- Follow PEP 8 and the project's formatting style (enforced by Ruff).
- Provide descriptive commit messages and PR summaries.

---

## License

By contributing to DriftSentry, you agree that your contributions will be licensed under the [Apache License 2.0](LICENSE).
