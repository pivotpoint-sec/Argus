# Argus — Step-by-Step Usage Guide

A local, LLM-assisted pentest triage pipeline. Burp (or any other local tool)
hands request/response pairs to a FastAPI bridge; the bridge runs deterministic
detectors, consults a local Ollama model, deduplicates against session memory,
persists findings to SQLite, and exposes a Streamlit dashboard.

Everything runs on `127.0.0.1`. No traffic leaves your machine.

---

## 1. Prerequisites

| Component          | Minimum      | Notes                                            |
|--------------------|--------------|--------------------------------------------------|
| OS                 | Linux / macOS / Windows (WSL2) | Tested on Ubuntu 22.04 + WSL2        |
| Python             | 3.11+        | 3.10 works but is not the primary target          |
| RAM                | 8 GB         | 16 GB if running Mistral 7B + Burp simultaneously |
| Disk               | 10 GB free   | 4 GB model weights + Chroma + SQLite              |
| Ollama             | 0.1.30+      | https://ollama.com/download                       |
| Burp Suite         | Community or Pro | Needed only for the Burp integration          |
| Java (for Burp)    | JRE 17+      | Required to load the Montoya extension            |

Confirm Python and Ollama are on the PATH:

```bash
python3 --version        # -> 3.11.x
ollama --version         # -> 0.1.30 or newer
```

---

## 2. Install the Ollama model

Argus expects a local model. Mistral 7B is a good default:

```bash
ollama pull mistral
ollama serve &           # listens on http://127.0.0.1:11434
```

Other supported models (switch in `config.yaml` under `model:`):
`llama3`, `llama3:8b`, `codellama:34b`, `phi3:mini`, `mixtral:8x7b`.

---

## 3. Clone and install Argus

```bash
git clone https://github.com/your-fork/Argus.git
cd Argus

python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -U pip
pip install -r requirements.txt
```

Alternative (Docker):

```bash
docker compose up --build
# Bridge:    http://127.0.0.1:8765
# Dashboard: http://127.0.0.1:8501
# Ollama:    http://127.0.0.1:11434
docker exec argus-ollama ollama pull mistral
```

---

## 4. Configure

Open `config.yaml`. Every runtime knob lives here — there are no hardcoded
defaults scattered through the code. The keys you will almost always edit:

```yaml
model: mistral                   # Ollama model name
ollama_url: http://localhost:11434
bridge_host: 127.0.0.1
bridge_port: 8765

auth:
  enabled: true
  token: change-me-before-first-run   # <- SET THIS to a random string
```

Generate a random token once and keep it:

```bash
python3 -c "import secrets; print(secrets.token_urlsafe(24))"
# paste the output into auth.token
```

Optional sections worth reviewing before your first engagement:

- `rate_limit_per_minute` — throttles calls to the local LLM
- `filter.enabled` — set false to disable the pre-filter (not recommended)
- `memory.enabled` — set false to disable ChromaDB-backed session memory
- `agentic.enabled` — set **true** only if you want the bridge to issue
  follow-up HTTP probes autonomously (opt-in, cross-origin-safe)

---

## 5. Start the bridge

In a dedicated terminal:

```bash
source .venv/bin/activate
export ARGUS_TOKEN="$(grep '^  token' config.yaml | awk '{print $2}')"
python3 -m llm_bridge.bridge
```

You should see a banner:

```
========================================================
 Argus - local LLM-assisted pentest bridge (v1.1)
 model         : mistral   (router: off)
 ollama        : OK (http://localhost:11434)
 chromadb      : OK
 sqlite        : OK
 llm cache     : OK  rows=0
 auth          : ENFORCED
 agentic probe : off
 session_id    : <uuid>
 listening     : http://127.0.0.1:8765
========================================================
```

Quick health check from another terminal:

```bash
curl -s http://127.0.0.1:8765/health | python3 -m json.tool
# {"ollama": true, "chroma": true, "db": true, "cache": true}
```

---

## 6. Start the Streamlit dashboard

In a second terminal:

```bash
source .venv/bin/activate
export ARGUS_TOKEN="<same token>"
streamlit run dashboard/app.py
# opens http://127.0.0.1:8501 in your browser
```

The dashboard polls `/state` every few seconds and shows:

- Risk-by-category chart
- Findings table (CWE, CVSS, source, occurrences columns)
- Sidebar metrics (LLM calls, cache hit/miss, filter kept/dropped, dedup)
- Per-finding `curl`/`httpie`/`python` PoC generator
- Per-finding agentic-probe trigger (if `agentic.enabled: true`)

---

## 7. Install the Burp extension

1. In Burp: **Extensions -> Installed -> Add**
2. **Extension type**: Python, **Extension file**:
   `burp_extension/llm_analyser.py`
3. Environment variable Burp must have: `ARGUS_TOKEN=<your token>`
   (set it before launching Burp, e.g. `export ARGUS_TOKEN=... && BurpSuiteCommunity`)
4. Open the extension output log — you should see:
   `Argus extension ready; bridge = http://127.0.0.1:8765/analyse`

Now every request/response pair flowing through Burp's proxy is posted to
`/analyse`. Interesting ones get highlighted in the HTTP history with an
`Argus[...]` comment; findings appear live in the dashboard.

---

## 8. Run your first engagement

A typical session looks like this.

1. Browse the target through Burp as you normally would. The pre-filter
   drops static assets, health checks, and oversized responses; anything
   parameterised, authed, or erroring goes to the LLM.
2. Watch the dashboard. Each new finding shows risk, OWASP category,
   source (detector vs LLM vs critique vs probe), CWE, and CVSS.
3. Click **Generate PoC** on a finding to get a copy-pasteable reproducer.
4. If `agentic.enabled: true`, click **Probe** to let the bridge design and
   run a small number of follow-up HTTP requests (same-origin only).
5. When done, archive the session:

   ```bash
   curl -s -X POST -H "X-Argus-Token: $ARGUS_TOKEN" \
        http://127.0.0.1:8765/session/clear | python3 -m json.tool
   ```

6. Export a markdown engagement report:

   ```bash
   curl -s -H "X-Argus-Token: $ARGUS_TOKEN" \
        http://127.0.0.1:8765/session/report > engagement.md
   ```

---

## 9. Endpoint reference

All endpoints except `/health` require the `X-Argus-Token` header.

| Method | Path                  | Purpose                                        |
|--------|-----------------------|------------------------------------------------|
| POST   | `/analyse`            | Triage one request/response pair               |
| POST   | `/diff`               | Differential analysis of two samples           |
| POST   | `/poc`                | Generate a `curl`/`httpie`/`python` PoC        |
| POST   | `/probe`              | Agentic follow-up probes (opt-in)              |
| GET    | `/findings`           | List findings in the current session           |
| GET    | `/findings/summary`   | Per-risk / per-OWASP counts                    |
| GET    | `/state`              | Health + summary + findings + metrics (one go) |
| GET    | `/metrics`            | Prometheus text-format exposition              |
| POST   | `/session/clear`      | Archive current session, start a new one       |
| GET    | `/session/report`     | Markdown engagement report                     |
| GET    | `/health`             | Liveness                                       |

Example: analyse an arbitrary request/response pair from the CLI

```bash
curl -s -X POST http://127.0.0.1:8765/analyse \
  -H "Content-Type: application/json" \
  -H "X-Argus-Token: $ARGUS_TOKEN" \
  -d '{
    "url":"https://target/api/login",
    "tool":"manual",
    "request":"POST /api/login HTTP/1.1\nHost: target\nContent-Type: application/json\n\n{\"u\":\"admin\",\"p\":\"\"}",
    "response":"HTTP/1.1 200 OK\nContent-Type: application/json\n\n{\"token\":\"...\"}"
  }' | python3 -m json.tool
```

---

## 10. Operational tasks

Check metrics:

```bash
curl -s -H "X-Argus-Token: $ARGUS_TOKEN" http://127.0.0.1:8765/metrics
```

Inspect the SQLite findings log directly:

```bash
sqlite3 storage/findings.db \
  "SELECT id, risk, owasp_category, url FROM findings ORDER BY id DESC LIMIT 20;"
```

Tail structured JSON logs:

```bash
tail -f logs/argus.log | jq .
```

Run the test suite:

```bash
pytest -q
```

---

## 11. Troubleshooting

**Banner shows `ollama: UNREACHABLE`** — `ollama serve` is not running, or
`ollama_url` in `config.yaml` points to the wrong host/port.

**Banner shows `chromadb: DISABLED/ERROR`** — either `memory.enabled: false`
in config, or the persist directory is not writable. Check
`storage/chroma/`.

**Bridge returns 401 `Unauthorized`** — the `X-Argus-Token` header is
missing or wrong. Regenerate and re-export `ARGUS_TOKEN` in every shell
that talks to the bridge (bridge itself, dashboard, Burp launcher, curl
examples).

**Bridge returns 413 `request too large`** — raw Burp body exceeded
`max_request_body_bytes` (default 2 MiB). Raise it in `config.yaml`.

**LLM is slow** — lower `max_request_chars`/`max_response_chars`, enable
`critique` only for medium+ risk, or switch `model:` to a smaller
variant (`phi3:mini`). Model weights stay resident between calls because
of `ollama_keep_alive`.

**Dashboard is empty** — confirm the bridge is reachable and the token
matches. The dashboard polls `/state` with the same `X-Argus-Token`
header; a 401 will silently render an empty table.

**Tests fail with `Table 'findings' is already defined`** — ensure
`storage/db.py` has `__table_args__ = {"extend_existing": True}` on the
`Finding` class. This lets the test suite reload `storage.db` cleanly
between tests.

---

## 12. Uninstall / wipe

```bash
# Stop services (Ctrl-C in the bridge + dashboard terminals)
deactivate
rm -rf Argus/.venv Argus/storage/findings.db Argus/storage/chroma \
       Argus/storage/llm_cache.db Argus/logs/argus.log*
ollama rm mistral          # only if you want the model gone too
```

---

## License

MIT. Use only on systems you are authorised to test.
