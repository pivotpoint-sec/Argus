# Argus — Air-gapped LLM-assisted Web Application Pentest Triage

[![tests](https://github.com/pivotpoint-sec/Argus/actions/workflows/tests.yml/badge.svg)](https://github.com/pivotpoint-sec/Argus/actions/workflows/tests.yml)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![python: 3.11-3.13](https://img.shields.io/badge/python-3.11--3.13-blue.svg)](https://www.python.org/)

Argus is a Burp Suite extension paired with a local FastAPI bridge that runs
a locally-hosted LLM (Ollama, phi3 by default) plus a tier of deterministic
OWASP-aligned detectors to triage web application traffic in real time. It
sits next to Burp, reads every request/response flowing through the proxy,
persists findings to SQLite, indexes them in ChromaDB for cross-request
semantic memory, and surfaces results in a Streamlit dashboard.

## What's Argus Is.

**Everything runs on the operator's machine.** No cloud APIs, no remote
model endpoints, no telemetry. Every component binds to `127.0.0.1`. The
bridge enforces a shared-secret bearer token so other local processes
cannot poison findings.

## Features

- **Lean install footprint** — embeddings via
  [fastembed](https://github.com/qdrant/fastembed) (ONNX runtime, no torch,
  no CUDA wheels). Whole venv is ~500 MB on Linux, ~750 MB on Windows.
- **20+ deterministic detectors** covering the OWASP Top 10 (2021): SQLi,
  XSS, command injection, XXE, SSRF, JWT misconfiguration, HTTP request
  smuggling, GraphQL misconfiguration, insecure deserialisation, mass
  assignment / parameter pollution, SSTI, NoSQL injection, missing SRI,
  vulnerable-component fingerprinting, debug-endpoint exposure, cloud
  secret leakage, stack-trace leakage, missing / weak security headers.
- **Cross-request chain detection** — IDOR chains (same URL shape,
  different IDs, distinct user identities in evidence), auth-bypass
  chains (403 then 200 to the same endpoint), privilege-escalation paths
  (same parameter in `/user/` and `/admin/`), session-token reuse across
  hours. Findings a per-request scanner cannot see.
- **Closed-loop confirmer** — targeted follow-up probes that prove or
  disprove flagged findings: time-based SQLi (`SLEEP(2)` timing delta),
  XSS reflection (unique canary in HTML context), command-injection
  (output echo), SSRF (manual review, needs OOB callback). Gated by
  `agentic.enabled`.
- **Stack-aware payload recommender** — reads the attack-surface graph
  and existing findings, returns ranked (payload, target, rationale,
  lateral targets) tuples. Intrusive payloads gated by
  `recommender.intrusive`.
- **Content-addressed LLM cache** — `(model, system_prompt, normalised
  user_prompt, URL shape)` → SHA-256 → SQLite. Numeric IDs, UUIDs and
  hex blobs are placeholderised so `/users/1`, `/users/2`, … share a
  cached verdict.
- **Multi-model router** — CodeLlama for JS/SSTI, LLaMA-3 for auth
  flows, Mistral for everything else. Unavailable models fall back
  silently to the default.
- **LLM self-critique pass** — a second pass prunes findings whose
  evidence doesn't appear in the pair. Can only remove, never invent.
- **LLM self-consistency voting** (opt-in) — run analyse() N times,
  keep only findings that survive a majority vote. Cuts hallucinations
  at N× compute cost.
- **Business-logic correlation** — `POST /correlate` asks the LLM to
  surface logic bugs that span multiple existing findings on the same
  host (token reuse, state-machine violations, cross-flow privilege
  drift). Every emitted finding cites the contributing finding IDs.
- **ChromaDB semantic memory** — per-session vector store, dedup on
  cosine distance, FIFO-capped at 10 000 entries.
- **Redaction** of JWTs, cookies, passwords, private keys, API keys
  before logging and before embedding text is stored.
- **Bearer-token auth** on every bridge endpoint.
- **CWE + CVSS + OWASP category** on every finding.
- **Markdown engagement report** with executive summary, per-finding
  write-up, target / duration / volume counters.
- **SARIF 2.1.0 export** for GitHub code-scanning, DefectDojo, JIRA
  Compass, Splunk.
- **Prometheus metrics endpoint** — LLM calls, cache hit/miss, filter
  kept/dropped, dedup collapsed, detector findings.
- **JSON-structured logs** with correlation IDs propagated from Burp
  into DB rows.
- **One-command lifecycle** — `./bin/argus start | stop | status |
  smoke | logs` runs and inspects the whole stack. No manual
  `export ARGUS_TOKEN`, no juggling three terminals.
- **Docker-compose** starts Ollama + bridge + dashboard in one command,
  all bound to `127.0.0.1`.
- **83 automated tests** covering filter, detectors, redaction, cache,
  JSON extraction, chain detection, confirmer, recommender, consistency
  voting, SARIF shape, and an end-to-end pipeline run.

## Project layout

```
argus/
├── bin/
│   └── argus                  # One-command lifecycle: start/stop/status/logs/smoke
├── burp_extension/
│   ├── llm_analyser.py        # Burp legacy IBurpExtender extension (Jython 2.7)
│   └── prompts.py             # Versioned system + user prompts
├── llm_bridge/
│   ├── bridge.py              # FastAPI server - Burp talks to this
│   ├── analyser.py            # LLM call logic, retry, cache, critique
│   ├── filter.py              # Pre-filter heuristics
│   ├── detectors.py           # Deterministic regex detectors (core tier)
│   ├── owasp_extras.py        # Extended A06/A08/A10 + SSTI/NoSQL/debug
│   ├── chains.py              # Cross-request chain detector
│   ├── confirmer.py           # Closed-loop confirmation probes
│   ├── recommender.py         # Payload recommender + /recommend endpoint
│   ├── payloads.py            # Stack-aware payload library
│   ├── surface.py             # Attack-surface graph builder
│   ├── cache.py               # Content-addressed LLM response cache
│   ├── router.py              # Multi-model dispatcher
│   ├── critique.py            # Self-critique / pruning pass
│   ├── consistency.py         # LLM self-consistency voting
│   ├── memory.py              # ChromaDB session memory + fastembed dedup
│   ├── sarif.py               # SARIF 2.1.0 export
│   ├── redact.py              # Sensitive-data scrubbing
│   ├── auth.py                # Bearer-token guard
│   ├── metrics.py             # In-memory counters + histograms
│   ├── probe.py               # Agentic follow-up probes (opt-in)
│   ├── report.py              # Markdown engagement report generator
│   ├── models.py              # Pydantic schemas
│   └── config.py              # Loader for config.yaml + JSON logging
├── storage/
│   ├── db.py                  # SQLite via SQLModel (with migrations)
│   └── schema.sql             # Authoritative table definitions
├── dashboard/
│   └── app.py                 # Streamlit live findings dashboard
├── installer/
│   ├── install.sh             # Linux / macOS installer
│   ├── install.ps1            # Windows installer
│   └── requirements.txt       # Pinned dependencies
├── tests/                     # 83 pytest tests
├── config.yaml                # ALL runtime knobs
├── Dockerfile                 # Non-root Python 3.11-slim image
├── docker-compose.yml         # Ollama + bridge + dashboard, all local
├── requirements.txt
├── README.md
├── USAGE.md                   # Step-by-step usage guide
├── TEST_LOCAL.md              # Local verification guide
├── SECURITY.md                # Vulnerability disclosure policy
└── CONTRIBUTING.md            # How to contribute
```

## Quick install

Requires Python 3.11, 3.12, or 3.13 (not 3.14 — chromadb's transitive
`tokenizers` dependency has no cp314 wheels yet).

**Linux / macOS / Kali:**

```bash
git clone https://github.com/pivotpoint-sec/Argus.git
cd Argus
./installer/install.sh
./bin/argus start
```

**Windows (PowerShell):**

```powershell
git clone https://github.com/pivotpoint-sec/Argus.git
cd Argus
.\installer\install.ps1
# bin/argus is a bash script; run under WSL or use the manual 3-terminal
# flow described below.
```

The installer creates a venv, installs deps (fastembed embeddings, no
torch/CUDA), pulls the default Ollama model (phi3, ~2 GB), and generates
a fresh auth token in `config.yaml`. `./bin/argus start` then brings up
Ollama, bridge, and dashboard in the background.

## First run

Once `argus start` returns, the dashboard is at `http://127.0.0.1:8501`
and the bridge accepts `/analyse` at `http://127.0.0.1:8765`. Everything
else lives under `./bin/argus`:

| Command             | Effect                                                          |
| ------------------- | --------------------------------------------------------------- |
| `argus start`       | Start ollama (if not running), bridge, dashboard. Idempotent.   |
| `argus stop`        | Clean teardown of bridge, dashboard, and any ollama we started. |
| `argus restart`     | stop && start.                                                  |
| `argus status`      | Show running state and URLs.                                    |
| `argus logs [name]` | Tail a log (`bridge` default; also `ollama`, `dashboard`).      |
| `argus smoke`       | POST a synthetic SQLi to `/analyse` and print the JSON.         |
| `argus token`       | Print the auth token from `config.yaml`.                        |

PIDs and logs land under `.run/` (gitignored). The launcher reads
`auth.token` straight out of `config.yaml`, so no `export ARGUS_TOKEN`
in your shell.

## Manual install

If you'd rather assemble each piece yourself, or you need to debug the
bridge with foreground logs:

1. Install [Ollama](https://ollama.com/download) and pull the default model:

    ```bash
    ollama pull phi3         # ~2 GB, the default
    ollama pull mistral      # optional: broader general triage
    ollama pull llama3       # optional: used by the auth router lane
    ollama pull codellama    # optional: used by the code / SSTI router lane
    ```

2. Install Python dependencies (Python 3.11-3.13):

    ```bash
    python3 -m venv .venv
    source .venv/bin/activate   # Windows: .venv\Scripts\Activate.ps1
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
    # Windows PowerShell:
    $env:ARGUS_TOKEN = "your-long-random-string"
    ```

4. Start the bridge:

    ```bash
    python -m llm_bridge.bridge
    ```

5. Start the dashboard (in another terminal):

    ```bash
    streamlit run dashboard/app.py
    ```

6. Load the Burp extension:

    - In Burp, install a **Jython 2.7 standalone JAR** under
      *Settings → Extensions → Python environment*.
    - *Extensions → Add → Extension type: Python →* select
      `burp_extension/llm_analyser.py`.
    - Confirm `ARGUS_TOKEN` is exported in the shell you launched Burp
      from, or create `burp_extension/argus_config.json`:

      ```json
      {"bridge_url": "http://127.0.0.1:8765/analyse",
       "auth_token": "your-long-random-string"}
      ```

7. Verify the pipeline:

    ```bash
    curl -s http://127.0.0.1:8765/health | python -m json.tool
    curl -s -H "X-Argus-Token: $ARGUS_TOKEN" \
         http://127.0.0.1:8765/state | python -m json.tool | head -40
    ```

Everything from step 3 onward is what `./bin/argus start` automates. Use
the manual flow when you want foreground logs, want to run a debugger
against the bridge, or want to swap out one component at a time.

For a step-by-step first-run guide, see [USAGE.md](USAGE.md) and
[TEST_LOCAL.md](TEST_LOCAL.md).

## Docker

```bash
docker compose up --build
# Bridge:    http://127.0.0.1:8765
# Dashboard: http://127.0.0.1:8501
# Ollama:    http://127.0.0.1:11434 (run: docker exec argus-ollama ollama pull phi3)
```

Every service binds to `127.0.0.1` on the host; the compose network is
how they reach each other.

## Recommended models

| Model         | Size | Best for                              | Min RAM |
| ------------- | ---- | ------------------------------------- | ------- |
| Phi-3 Mini    | 2GB  | **Default.** High-volume triage, critique pass | 4GB     |
| Mistral 7B    | 4GB  | Fast general triage, good JSON output | 8GB     |
| LLaMA 3 8B    | 5GB  | Stronger reasoning                    | 8GB     |
| LLaMA 3 70B   | 40GB | Highest quality, report writing       | 48GB    |
| CodeLlama 34B | 20GB | Code-level vulns: SSTI, deserialise   | 24GB    |
| Mixtral 8x7B  | 26GB | Balanced breadth + depth              | 32GB    |

Switch models via `config.yaml` (`model:`) or enable the multi-model
router under `router:` to route per vulnerability class.

## Endpoints

| Method | Path                | Purpose                                        |
| ------ | ------------------- | ---------------------------------------------- |
| POST   | `/analyse`          | Triage one request/response pair               |
| POST   | `/diff`             | Differential analysis of two samples           |
| POST   | `/poc`              | Generate a curl / httpie / python PoC          |
| POST   | `/probe`            | Agentic follow-up probes (opt-in)              |
| POST   | `/confirm`          | Closed-loop confirmation of a finding          |
| POST   | `/correlate`        | Business-logic bugs spanning existing findings |
| POST   | `/recommend`        | Ranked payload recommendations                 |
| GET    | `/findings`         | List findings in the current session           |
| GET    | `/findings/summary` | Per-risk / per-OWASP counts                    |
| GET    | `/chains`           | Cross-request chain findings                   |
| GET    | `/state`            | Health + summary + findings + metrics          |
| GET    | `/metrics`          | Prometheus exposition                          |
| POST   | `/session/clear`    | Archive current session and start a fresh one  |
| GET    | `/session/report`   | Markdown engagement report                     |
| GET    | `/session/sarif`    | SARIF 2.1.0 export                             |
| GET    | `/health`           | Liveness                                       |

All endpoints except `/health` require the `X-Argus-Token` header when
`auth.enabled` is `true`.

## Safety and authorisation

Argus is a pentest tool. Two config switches gate any active behaviour:

- `agentic.enabled` (default: `false`) — allows follow-up HTTP probes.
- `recommender.intrusive` (default: `false`) — allows intrusive payloads
  in `/recommend` output.

Both default to off. Only enable them for targets you are explicitly
authorised to test. `MIT License` grants you the right to use the code,
not permission to attack anyone's systems.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Bug reports and detector
contributions are especially welcome. For security issues in Argus
itself, see [SECURITY.md](SECURITY.md).

## License

MIT. Use only on systems you are authorised to test.
