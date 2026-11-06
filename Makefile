.PHONY: build test lint install

build:
	uv build

test:
	uv run pytest

lint:
	uv run ruff check .
	uv run ruff format --check .

install:
	uv tool install --reinstall .
