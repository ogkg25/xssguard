# XSSGuard Makefile
# Targets: benchmark, benchmark-synthetic, test, lint, baseline, help

.PHONY: benchmark benchmark-synthetic test lint baseline help

help:
	@echo "XSSGuard Makefile targets:"
	@echo "  make benchmark          - Run full benchmark suite"
	@echo "  make benchmark-synthetic- Run synthetic/smoke benchmarks only"
	@echo "  make test               - Run pytest"
	@echo "  make lint               - Run linter (black --check)"
	@echo "  make baseline           - Save current results as new baseline"
benchmark:
	python benchmarks/run_smoke_test.py --mode all
benchmark-synthetic:
	python benchmarks/run_smoke_test.py --mode whitebox
	python benchmarks/run_smoke_test.py --mode blackbox
	python benchmarks/run_smoke_test.py --mode matrix
test:
	pytest
lint:
	black --check .
baseline:
	python benchmarks/run_smoke_test.py --generate --mode all
