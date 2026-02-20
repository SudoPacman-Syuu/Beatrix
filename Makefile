# ═══════════════════════════════════════════════════════════
#  BEATRIX CLI — The Black Mamba
#  Makefile for install/uninstall/dev
# ═══════════════════════════════════════════════════════════

PYTHON   ?= python3
VENV_DIR ?= $(HOME)/.beatrix
BIN_DIR  ?= /usr/local/bin
SHELL    := /bin/bash

.PHONY: help install uninstall install-dev install-venv clean test lint

# ── Default ──────────────────────────────────────────────

help: ## Show this help
	@echo ""
	@echo "  ⚔️  BEATRIX CLI — Makefile"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'
	@echo ""

# ── Install ──────────────────────────────────────────────

install: ## Install globally (tries pipx → pip --user → system pip → venv)
	@chmod +x install.sh && ./install.sh

install-pipx: ## Install via pipx (recommended)
	pipx install --force .

install-user: ## Install to ~/.local/bin via pip
	$(PYTHON) -m pip install --user --break-system-packages . 2>/dev/null || \
		$(PYTHON) -m pip install --user .

install-system: ## Install system-wide (requires sudo)
	sudo $(PYTHON) -m pip install --break-system-packages . 2>/dev/null || \
		sudo $(PYTHON) -m pip install .

install-venv: ## Install in dedicated venv at ~/.beatrix + symlink to /usr/local/bin
	$(PYTHON) -m venv $(VENV_DIR)
	$(VENV_DIR)/bin/pip install --upgrade pip
	$(VENV_DIR)/bin/pip install .
	@if [ -w "$(BIN_DIR)" ]; then \
		ln -sf $(VENV_DIR)/bin/beatrix $(BIN_DIR)/beatrix; \
	else \
		sudo ln -sf $(VENV_DIR)/bin/beatrix $(BIN_DIR)/beatrix; \
	fi
	@echo "✓ Installed to $(VENV_DIR), linked at $(BIN_DIR)/beatrix"

install-dev: ## Install in editable mode for development
	$(PYTHON) -m pip install -e ".[dev]" --break-system-packages 2>/dev/null || \
		$(PYTHON) -m pip install -e ".[dev]"
	@echo "✓ Dev install complete"

# ── Uninstall ────────────────────────────────────────────

uninstall: ## Uninstall beatrix from everywhere
	@echo "Removing beatrix..."
	-pipx uninstall beatrix-cli 2>/dev/null || true
	-$(PYTHON) -m pip uninstall -y beatrix-cli 2>/dev/null || true
	-sudo $(PYTHON) -m pip uninstall -y beatrix-cli 2>/dev/null || true
	-rm -f $(BIN_DIR)/beatrix 2>/dev/null || true
	-rm -rf $(VENV_DIR) 2>/dev/null || true
	@echo "✓ Uninstalled"

# ── Dev ──────────────────────────────────────────────────

test: ## Run tests
	$(PYTHON) -m pytest tests/ -v

lint: ## Run linter
	$(PYTHON) -m ruff check beatrix/

clean: ## Clean build artifacts
	rm -rf build/ dist/ *.egg-info .eggs __pycache__
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	@echo "✓ Cleaned"

# ── Info ─────────────────────────────────────────────────

check: ## Check if beatrix is installed and show info
	@echo ""
	@if command -v beatrix &>/dev/null; then \
		echo "  ✓ beatrix is installed"; \
		echo "  Location: $$(which beatrix)"; \
		beatrix --version; \
	else \
		echo "  ✗ beatrix is not on PATH"; \
		echo "  Run: make install"; \
	fi
	@echo ""
