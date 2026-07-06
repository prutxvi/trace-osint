.PHONY: test lint clean

test:
	python -m pytest tests/

lint:
	ruff check src/

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true

