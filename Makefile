.PHONY: install lint format test check build example clean

PY ?= uv run

install:
	uv sync

lint:
	$(PY) ruff check .
	$(PY) ruff format --check .

format:
	$(PY) ruff format .
	$(PY) ruff check --fix .

test:
	$(PY) pytest -q

check: lint test

build:
	rm -rf dist
	uv build

example:
	$(PY) agent-config-audit examples/sample-project --format markdown --output examples/report.md
	$(PY) agent-config-audit examples/sample-project --format sarif --output examples/report.sarif

clean:
	rm -rf dist build .pytest_cache .ruff_cache
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
