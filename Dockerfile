# syntax=docker/dockerfile:1
# ---- Stage 1: build the virtualenv from the hashed lock file (pip refuses anything that does not match) ----
FROM python:3.15-slim-bookworm AS builder
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /build
COPY requirements.lock .
RUN python -m venv /opt/venv \
 && /opt/venv/bin/pip install --require-hashes -r requirements.lock

# ---- Stage 2: runtime image: no compiler, no pip cache, no tests, no .env ----
FROM python:3.15-slim-bookworm AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH"

# Unprivileged user; application files stay root-owned and read-only for it
RUN useradd --create-home --uid 10001 --shell /usr/sbin/nologin appuser
COPY --from=builder /opt/venv /opt/venv
WORKDIR /app
COPY backend ./backend
COPY frontend ./frontend
COPY sample_data ./sample_data

USER 10001:10001
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=3)"]

CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
