.PHONY: check schemas test

check:
	uv run ruff check .
	uv run mypy src
	uv run pytest

schemas:
	uv run python scripts/export_schemas.py

test:
	uv run pytest
