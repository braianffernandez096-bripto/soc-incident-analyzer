# SOC Incident Analyzer - developer tasks.  Run `make help` to list them.
# Works on Linux/macOS/WSL. Windows users: use WSL or Docker (see README).

PYTHON   ?= python3
VENV     := .venv
PY       := $(VENV)/bin/python
PORT     ?= 8000
RUN_DIR  := .run
PID_FILE := $(RUN_DIR)/app.pid
LOG_FILE := $(RUN_DIR)/app.log
MIN_COV  ?= 85

.DEFAULT_GOAL := help
.PHONY: help install start stop restart status test test-cov logs clean backup lint audit

help: ## Show this help
	@grep -E '^[a-z-]+:.*##' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  make %-10s %s\n", $$1, $$2}'

$(PY): requirements-dev.lock
	@echo "📦 Creando entorno virtual e instalando dependencias (versiones exactas con hash)..."
	@$(PYTHON) -m venv $(VENV)
	@$(VENV)/bin/pip install --quiet --require-hashes -r requirements-dev.lock
	@touch $(PY)

install: $(PY) ## Create the virtualenv and install pinned dependencies
	@echo "✅ Listo. Inicia la app con: make start"

start: $(PY) ## Start the app in the background (127.0.0.1, port 8000 by default)
	@mkdir -p $(RUN_DIR)
	@if [ -f $(PID_FILE) ] && kill -0 $$(cat $(PID_FILE)) 2>/dev/null; then \
	  echo "🟡 Ya está corriendo (PID $$(cat $(PID_FILE))). Usa: make restart"; \
	else \
	  nohup $(PY) -m uvicorn backend.main:app --host 127.0.0.1 --port $(PORT) > $(LOG_FILE) 2>&1 & echo $$! > $(PID_FILE); \
	  for i in $$(seq 1 30); do \
	    if $(PY) -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:$(PORT)/api/health', timeout=2)" 2>/dev/null; then \
	      echo "🟢 CORRIENDO en http://127.0.0.1:$(PORT)  (PID $$(cat $(PID_FILE)))"; exit 0; fi; \
	    sleep 1; done; \
	  echo "🔴 No respondió en 30 s. Revisa: make logs"; rm -f $(PID_FILE); exit 1; \
	fi

stop: ## Stop the app
	@if [ -f $(PID_FILE) ] && kill -0 $$(cat $(PID_FILE)) 2>/dev/null; then \
	  kill $$(cat $(PID_FILE)) && rm -f $(PID_FILE) && echo "⏹  Detenida."; \
	else rm -f $(PID_FILE); echo "🟡 No estaba corriendo."; fi

restart: stop start ## Stop and start again

status: ## Show whether the app is running
	@if [ -f $(PID_FILE) ] && kill -0 $$(cat $(PID_FILE)) 2>/dev/null; then echo "🟢 CORRIENDO (PID $$(cat $(PID_FILE)))"; else echo "⚪ DETENIDA"; fi

test: $(PY) ## Run the test suite
	@echo "🧪 Ejecutando tests..."
	@$(PY) -m pytest

test-cov: $(PY) ## Run tests with coverage (fails below 85%)
	@echo "📊 Cobertura..."
	@$(PY) -m pytest --cov=backend --cov-report=term-missing --cov-fail-under=$(MIN_COV)

logs: ## Show the last 100 log lines
	@if [ -f $(LOG_FILE) ]; then tail -n 100 $(LOG_FILE); else echo "Todavía no hay logs (¿corriste make start?)."; fi

lint: $(PY) ## Syntax checks: Python, JavaScript, shell scripts, compose file
	@$(PY) -m compileall -q backend tests
	@if command -v node >/dev/null; then node --check frontend/app.js && echo "✅ JavaScript OK"; else echo "🟡 node no instalado: se omite el chequeo de JS"; fi
	@if ls scripts/*.sh >/dev/null 2>&1; then for f in scripts/*.sh; do bash -n $$f || exit 1; done; echo "✅ Shell OK"; \
	  if command -v shellcheck >/dev/null; then shellcheck scripts/*.sh; else echo "🟡 shellcheck no instalado"; fi; fi
	@if command -v docker >/dev/null && docker compose version >/dev/null 2>&1; then docker compose config -q && echo "✅ docker-compose.yml OK"; fi
	@echo "✅ Lint terminado"

audit: $(PY) ## Security audit: static analysis (bandit) + known vulnerabilities (pip-audit)
	@echo "🔎 bandit (análisis estático)..."
	@$(VENV)/bin/bandit -q -r backend
	@echo "🔎 pip-audit (vulnerabilidades conocidas en dependencias)..."
	@$(VENV)/bin/pip-audit -r requirements.lock --require-hashes --disable-pip
	@echo "✅ Auditoría limpia"

backup: ## Save a copy of your .env (the app stores no data: sessions live in memory)
	@mkdir -p backups
	@if [ -f .env ]; then umask 077; cp .env backups/env-$$(date +%Y%m%d-%H%M%S).bak && echo "💾 Copia de .env guardada en backups/ (permisos 600)."; \
	else echo "🟡 No hay .env para respaldar. La app no guarda datos propios."; fi

clean: ## Remove caches and run files (keeps .venv and .env)
	@rm -rf $(RUN_DIR) .pytest_cache htmlcov .coverage
	@find . -name __pycache__ -type d -not -path "./$(VENV)/*" -prune -exec rm -rf {} +
	@echo "🧹 Limpio."
