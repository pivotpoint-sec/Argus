# syntax=docker/dockerfile:1.6
# -----------------------------------------------------------------------------
# Argus bridge + dashboard image.
# Ollama runs in a sibling container (see docker-compose.yml). This image
# bundles only the Python pieces and connects to Ollama over the compose
# network.
# -----------------------------------------------------------------------------

FROM python:3.11-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

# Security: run as non-root.
RUN useradd -r -u 10001 -s /usr/sbin/nologin argus

WORKDIR /app

COPY requirements.txt .
RUN pip install --upgrade pip && pip install -r requirements.txt

COPY . .
RUN mkdir -p logs storage && chown -R argus:argus /app

USER argus

# Bridge is the default entry point; dashboard is run by docker-compose as
# a separate service sharing the same volume.
EXPOSE 8765
CMD ["uvicorn", "llm_bridge.bridge:app", "--host", "0.0.0.0", "--port", "8765"]
