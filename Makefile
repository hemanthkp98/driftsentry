.PHONY: install dev test lint format clean ci build publish

# ─── Development ─────────────────────────────────────────────
install:
	pip install -e .

dev:
	pip install -e ".[dev]"

# ─── Quality ─────────────────────────────────────────────────
lint:
	ruff check src/ tests/
	ruff format --check src/ tests/
	mypy src/driftsentry/

format:
	ruff check --fix src/ tests/
	ruff format src/ tests/

# ─── Testing ─────────────────────────────────────────────────
test:
	pytest tests/ -v --tb=short

test-cov:
	pytest tests/ -v --tb=short --cov=driftsentry --cov-report=term-missing --cov-report=html

# ─── CI Pipeline ─────────────────────────────────────────────
ci: lint test

# ─── Build & Publish ─────────────────────────────────────────
build:
	python -m build

publish: build
	twine upload dist/*

# ─── Docker ──────────────────────────────────────────────────
docker-build:
	docker build -t driftsentry:latest .

docker-run:
	docker run --rm -v ~/.aws:/root/.aws:ro driftsentry:latest scan --help

# ─── Cleanup ─────────────────────────────────────────────────
clean:
	rm -rf dist/ build/ *.egg-info src/*.egg-info
	rm -rf .pytest_cache .mypy_cache .ruff_cache htmlcov/
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
