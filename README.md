# Argus — Local LLM-assisted Web Application Pentest Pipeline

Argus is an offline-first triage assistant for web application pentesting.
A Burp Suite extension forwards every interesting request/response pair to
a local FastAPI bridge. The bridge runs a fast deterministic detector tier,
consults a content-addressed LLM response cache, routes to the best-fit
local **Ollama** model, runs a self-critique pass to prune hallucinations,
persists structured findings to SQLite, indexes them in a local
**ChromaDB** vector store with semantic dedup, and exposes a Streamlit
dashboard for live triage and Markdown reporting.

**Nothing leaves the machine.** No cloud APIs, no remote model endpoints,
no telemetry. Every component binds to `127.0.0.1`. The bridge enforces a
shared-secret bearer token so other local processes cannot poison findings.

## What's Argus Is.

- **Deterministic detector tier** — JWTs, cloud/API keys, stack traces,
  missing/weak security headers, private-IP leakage. These run in
  microseconds before the LLM and always persist, regardless of what the
  model says. They also seed the LLM prompt so it doesn't re-raise them.
- **Content-addressed LLM cache** — `(model, system_prompt, normalised
  user_prompt, URL shape)` → SHA-256 → SQLite. Numeric IDs, UUIDs and hex
  blobs are replaced with placeholders, so `/users/1`, `/users/2`, … all
  share one cached verdict. Typical real-engagement hit rate is very high.
- **Multi-model router** — CodeLlama for JS/uploads/SSTI, LLaMA-3 for auth
  flows, Mistral for everything else. Unavailable models fall back silently
  to the default.
- **Self-critique pass** — after primary analysis, a cheap model prunes
  findings whose evidence doesn't actually appear in the pair. Can only
  remove, never invent.
- **Semantic dedup** — ChromaDB distance ≤ config threshold collapses
  near-duplicates; the dashboard shows `×N` occurrences instead of N rows.
- **Redaction** of JWTs, cookies, passwords, private keys, API keys before
  logging and before storing evidence in embeddings.
- **Bearer-token auth** on every bridge endpoint (configurable).
- **CWE + CVSS fields** on every finding, alongside OWASP.
- **New endpoints:** `/state` (one-shot bundle for the dashboard),
  `/metrics` (Prometheus text), `/diff` (two responses compared),
  `/poc` (minimal reproduction snippet), `/session/report` (Markdown
  engagement report), `/probe` (agentic follow-up; off by default).
- **JSON-structured logs** with correlation IDs propagated from Burp into
  DB rows so a specific exchange can be traced end-to-end.
- **Docker-compose** spinning up Ollama + bridge + dashboard with one
  command, all bound to 127.0.0.1.
- **Pytest suite** covering filter, detectors, redaction, cache, JSON
  extraction, and an end-to-end pipeline run.

## Project layout

```
llm-pentest/
├── burp_extension/
│   ├── llm_analyser.py        # Burp Montoya extension (Python / Jython)
│   └── prompts.py             # Versioned system + user prompts
├── llm_bridge/
│   ├── bridge.py              # FastAPI server — Burp talks to this
│   ├── analyser.py            # LLM call logic, retry, cache, critique
│   ├── filter.py              # Pre-filter heuristics
│   ├── detectors.py           # Deterministic regex detectors
│   ├── cache.py               # Content-addressed LLM response cache
│   ├── router.py              # Multi-model dispatcher
│   ├── critique.py            # Self-critique / pruning pass
│   ├── memory.py              # ChromaDB session memory + dedup
│   ├── redact.py              # Sensitive-data scrubbing
│   ├── auth.py                # Bearer-token guard
│   ├── metrics.py             # In-memory counters + histograms
│   ├── probe.py               # Agentic follow-up probes (gated)
│   ├── report.py              # Markdown engagement report generator
│   ├── models.py              # Pydantic schemas
│   └── config.py              # Loader for config.yaml + JSON logging
├── storage/
│   ├── db.py                  # SQLite via SQLModel (with migrations)
│   ├── schema.sql             # Authoritative table definitions
│   ├── chroma/                # (created at runtime) vector store
│   ├── findings.db            # (created at runtime)
│   └── llm_cache.db           # (created at runtime)
├── dashboard/
│   └── app.py                 # Streamlit live findings dashboard
├── tests/                     # pytest suite
├── logs/                      # Rotating structured JSON logs
├── config.yaml                # ALL runtime knobs
├── Dockerfile                 # Non-root Python 3.11-slim image
├── docker-compose.yml         # Ollama + bridge + dashboard, all local
├── requirements.txt
└── README.md
```

## Setup — native

1. Install [Ollama](https://ollama.ai) and pull at least one model:

   ```bash
   ollama pull mistral
   ollama pull llama3       # optional: used by the auth router lane
   ollama pull codellama    # optional: used by the code router lane
   ollama pull phi3         # optional: used by the critique pass
   ```

2. Install Python dependencies (Python 3.11+):

   ```bash
   pip install -r requirements.txt
   ```

3. Set a shared secret in `config.yaml`:

   ```yaml
   auth:
     enabled: true
     token: your-long-random-string
   ```

   Also export it for the Burp extension so it can send `X-Argus-Token`:

   ```bash
   export ARGUS_TOKEN=your-long-random-string
   ```

4. Start the bridge:

   ```bash
   uvicorn llm_bridge.bridge:app --host 127.0.0.1 --port 8765
   ```

5. Start the dashboard (in another terminal):

   ```bash
   streamlit run dashboard/app.py
   ```

6. Load the Burp extension:
   - In Burp, install **Jython 2.7** under *Settings → Extensions → Python
     environment*.
   - *Extensions → Add → Extension type: Python →* select
     `burp_extension/llm_analyser.py`.
   - Confirm `ARGUS_TOKEN` is exported in the shell you launched Burp from,
     or create `burp_extension/argus_config.json`:

     ```json
     {"bridge_url": "http://127.0.0.1:8765/analyse",
      "auth_token": "your-long-random-string"}
     ```

7. Verify the pipeline:

   ```bash
   curl -s http://127.0.0.1:8765/health | python3 -m json.tool
   curl -s -H "X-Argus-Token: $ARGUS_TOKEN" \
        http://127.0.0.1:8765/state | python3 -m json.tool | head -40
   ```

## Setup — Docker

```bash
docker compose up --build
# Bridge:    http://127.0.0.1:8765
# Dashboard: http://127.0.0.1:8501
# Ollama:    http://127.0.0.1:11434 (run `docker exec argus-ollama ollama pull mistral`)
```

Every service is bound to 127.0.0.1 on the host; the compose network is
how they reach each other.

## Recommended models

| Model          | Size  | Best for                              | Min RAM |
|----------------|-------|---------------------------------------|---------|
| Mistral 7B     | 4GB   | Fast general triage, good JSON output | 8GB     |
| LLaMA 3 8B     | 5GB   | Stronger reasoning, recommended start | 8GB     |
| LLaMA 3 70B    | 40GB  | Highest quality, report writing       | 48GB    |
| CodeLlama 34B  | 20GB  | Code-level vulns: SSTI, deserialise   | 24GB    |
| Phi-3 Mini     | 2GB   | High-volume triage, critique pass     | 4GB     |
| Mixtral 8x7B   | 26GB  | Balanced breadth + depth              | 32GB    |

Switch models via `config.yaml` (`model:`) or enable the multi-model router
under `router:` to route per vulnerability class.

## Endpoints

| Method | Path                  | Purpose                                        |
|--------|-----------------------|------------------------------------------------|
| POST   | `/analyse`            | Triage one request/response pair               |
| POST   | `/diff`               | Differential analysis of two samples           |
| POST   | `/poc`                | Generate a curl/httpie/python PoC by finding   |
| POST   | `/probe`              | Agentic follow-up probes (opt-in)              |
| GET    | `/findings`           | List findings in the current session           |
| GET    | `/findings/summary`   | Per-risk / per-OWASP counts                    |
| GET    | `/state`              | Health + summary + findings + metrics (one go) |
| GET    | `/metrics`            | Prometheus exposition                          |
| POST   | `/session/clear`      | Archive current session and start a fresh one  |
| GET    | `/session/report`     | Markdown engagement report                     |
| GET    | `/health`             | Liveness                                       |

All endpoints except `/health` require the `X-Argus-Token` header when
`auth.enabled` is true.

## License

MIT. Use only on systems you are authorised to test.
