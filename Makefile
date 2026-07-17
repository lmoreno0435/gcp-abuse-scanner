.PHONY: install test lint format typecheck clean docker-build run-example

install:
	pip install -e ".[dev]"
	pre-commit install

test:
	pytest -v

test-cov:
	pytest --cov=gcp_abuse_scanner --cov-report=html --cov-report=term-missing

lint:
	ruff check gcp_abuse_scanner tests
	black --check gcp_abuse_scanner tests

format:
	ruff check --fix gcp_abuse_scanner tests
	black gcp_abuse_scanner tests

typecheck:
	mypy gcp_abuse_scanner

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete
	rm -rf .pytest_cache .mypy_cache .ruff_cache htmlcov coverage.xml dist build

docker-build:
	docker build -t gcp-abuse-scanner:dev .

# Run against a real project (requires GCP credentials)
run-example:
	gcp-abuse-scanner scan --project $(PROJECT_ID) --format console

list-checks:
	gcp-abuse-scanner list-checks
