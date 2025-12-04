UV ?= uv run 
PYM ?= python -m 

.PHONY: help cli gui link format

help:
	@echo "Common commands:"
	@echo "  make cli        Runs password manager in cli-mode
	@echo "  make gui        Runs password manager in gui-mode
	@echo "  make gui        Runs password manager in gui-mode
	@echo "  make gui        Runs password manager in gui-mode

cli:
	@echo "Starting CLI Password Manager"
	$(UV) $(PYM) src.main

gui:
	@echo "Starting GUI Password Manager"
	$(UV) $(PYM) src.gui

format:
	$(UV) ruff check . --select I --fix
	$(UV) ruff format .

lint:
	$(UV) ruff check .