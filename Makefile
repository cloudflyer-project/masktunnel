# Makefile for masktunnel project
.PHONY: help build clean test python-clean python-install python-test python-wheel

# Python binding targets
PYTHON_OUTPUT_DIR = _bindings/python
PYBIN ?= python3
PIP ?= $(PYBIN) -m pip

# Default target
help:
	@echo "Available targets:"
	@echo "  build           - Build Go binaries"
	@echo "  test            - Run Go tests"
	@echo "  clean           - Clean build artifacts"
	@echo "  python-clean    - Clean Python bindings"
	@echo "  python-install  - Install Python bindings to current python environment"
	@echo "  python-wheel    - Build Python wheel"
	@echo "  python-test     - Test Python bindings"

# Go targets
build:
	GOFLAGS="${GOFLAGS} -buildvcs=false" go build -o bin/masktunnel cmd/masktunnel/main.go

test:
	go test -v -race -coverprofile="coverage.txt" -covermode=atomic ./tests

clean:
	rm -rf bin

python-clean:
	rm -rf $(PYTHON_OUTPUT_DIR)/masktunnellib
	rm -rf $(PYTHON_OUTPUT_DIR)/masktunnel.egg-info
	rm -rf $(PYTHON_OUTPUT_DIR)/build
	rm -rf $(PYTHON_OUTPUT_DIR)/dist

python-test-deps:
	@echo "Installing Python dev dependencies..."
	cd $(PYTHON_OUTPUT_DIR) && $(PYBIN) -m pip install -e .[dev]

python-test:
	@echo "Running Python tests..."
	cd $(PYTHON_OUTPUT_DIR) && $(PYBIN) -m pytest tests -v --tb=short -n auto

python-install:
	@echo "Installing Python bindings via pip (setup.py will drive the build)..."
	cd $(PYTHON_OUTPUT_DIR) && $(PYBIN) -m pip install -e .

python-wheel:
	@echo "Building Python wheel via PEP 517 (setup.py logic is reused)..."
	cd $(PYTHON_OUTPUT_DIR) && $(PYBIN) -m build --wheel
