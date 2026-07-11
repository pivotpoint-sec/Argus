# Argus — Local Test Guide

Step-by-step verification from the `Argus/` directory on your own machine.
Two phases: **Phase A** needs no Ollama (offline, stubbed) and proves the
pipeline wiring. **Phase B** runs the real stack against a local model.

All commands assume you are inside the repo root:

```bash
cd C:\Users\[PROFILE_NAME]\[ARGUS_DIRECTORY]
# On WSL / Git Bash:
cd /c/Users/[PROFILE_NAME]/[ARGUS_DIRECTORY]
```

---

## Phase A — Offline sanity check (no Ollama required)

### A.1 Create a venv and install

```bash
# Requires Python 3.11, 3.12, or 3.13 (not 3.14 -- chromadb/tokenizers has no cp314 wheels)
python3 -m venv .venv
source .venv/bin/activate              # PowerShell: .venv\Scripts\Activate.ps1
pip install -U pip
pip install -r requirements.txt
```

Expect pip to resolve `fastapi`, `uvicorn`, `httpx`, `pydantic`, `sqlmodel`,
`chromadb`, `fastembed`, `PyYAML`, `streamlit`, `pandas`,
`pytest`, `pytest-asyncio`.

### A.2 Syntax sweep

```bash
python3 - <<'PY'
import ast, pathlib
bad = []
for p in pathlib.Path(".").rglob("*.py"):
    if ".venv" in p.parts or "__pycache__" in p.parts: continue
    try: ast.parse(p.read_text())
    except SyntaxError as e: bad.append((str(p), e))
print("FAIL" if bad else "OK", len(bad), "errors")
for b in bad: print(" -", b)
PY
```

Expected: `OK 0 errors`.

### A.3 Run the unit + integration test suite

```bash
pytest -q
```

Expected output (tail):

```
.................................                                        [100%]
33 passed, 2 warnings in ~2s
```

The 2 SAWarnings about `storage.db.Finding` are expected — conftest reloads
`storage.db` across tests and SQLModel warns on re-registration.

### A.4 One-command end-to-end stub

This spins the bridge inside `TestClient`, stubs the Ollama call, POSTs a
SQLi sample twice, and asserts dedup fires:

```bash
python3 - <<'PY'
import json, sys, types, shutil, tempfile, pathlib
root = pathlib.Path(tempfile.mkdtemp(prefix="argus-"))
shutil.copytree(".", root/"argus", dirs_exist_ok=True,
                ignore=shutil.ignore_patterns(".venv", "__pycache__", "*.db"))
sys.path.insert(0, str(root/"argus"))

import yaml
cfg_path = root/"argus"/"config.yaml"
cfg = yaml.safe_load(cfg_path.read_text())
cfg["auth"]["enabled"] = False
cfg_path.write_text(yaml.safe_dump(cfg))

# Stub chromadb + sentence_transformers so no heavy deps are touched.
class _C:
    def __init__(s): s._r=[]
    def add(s, ids, documents=None, embeddings=None, metadatas=None):
        for i,_id in enumerate(ids): s._r.append((_id, metadatas[i] if metadatas else {}, []))
    def query(s, query_embeddings=None, n_results=1, where=None):
        hits=[r for r in s._r if not where or all(r[1].get(k)==v for k,v in where.items())][:n_results]
        return {"ids":[[r[0] for r in hits]],"documents":[[""]*len(hits)],
                "metadatas":[[r[1] for r in hits]],"distances":[[0.0]*len(hits)]}
    def count(s): return len(s._r)
    def delete(s, where=None): pass
class _Cl:
    def get_or_create_collection(s,*a,**kw): return _C()
    def delete_collection(s,*a,**kw): pass
cd=types.ModuleType("chromadb"); cd.PersistentClient=lambda *a,**kw:_Cl()
cc=types.ModuleType("chromadb.config"); cc.Settings=lambda **kw:None
sys.modules["chromadb"]=cd; sys.modules["chromadb.config"]=cc
fe=types.ModuleType("fastembed")
class _StubTE:
    def __init__(s,*a,**kw): pass
    def embed(s, texts, **kw): return iter([[0.0]*8 for _ in list(texts)])
fe.TextEmbedding=_StubTE
sys.modules["fastembed"]=fe

import llm_bridge; llm_bridge.PROJECT_ROOT = root/"argus"
from llm_bridge import analyser
analyser.ping_ollama = lambda *a,**kw: True
analyser._call_ollama = lambda model, system, user, **kw: json.dumps({
    "risk":"high","owasp_category":"A03:2021-Injection",
    "findings":[{"type":"SQLi","parameter":"id","evidence":"OR 1=1",
                 "confidence":"likely","detail":"boolean OR","source":"llm",
                 "cwe":"CWE-89","cvss":8.1}],
    "recommend":["Use parameterised queries"],
    "interesting_for_follow_up":"Try UNION extraction"})

from fastapi.testclient import TestClient
from llm_bridge import bridge
c = TestClient(bridge.app)
body = {"request":"GET /api/users/1?id=1 OR 1=1 HTTP/1.1\nHost: target\n\n",
        "response":"HTTP/1.1 200 OK\nContent-Type: application/json\n\n{\"ok\":true}",
        "url":"https://target/api/users/1?id=1 OR 1=1","tool":"burp",
        "method":"GET","status_code":200,"correlation_id":"a"}
r1 = c.post("/analyse", json=body).json()
body["correlation_id"]="b"
r2 = c.post("/analyse", json=body).json()
m  = c.get("/metrics").text
findings = c.get("/findings").json()
assert r1["risk"] == "high", r1
print("first  risk :", r1["risk"])
print("second risk :", r2["risk"], "from_cache:", r2["from_cache"])
for line in m.splitlines():
    if any(k in line for k in ("requests_total","filter_kept","dedup_collapsed","cache_hit","cache_miss")):
        print("  ", line)
print("findings stored:", len(findings))
print("E2E OK")
PY
```

Expected (values may differ by 1):

```
first  risk : high
second risk : high from_cache: False
   argus_requests_total 2
   argus_filter_kept 2
   argus_cache_hits 0
   argus_cache_misses 2
   argus_dedup_collapsed 3
findings stored: 2
E2E OK
```

If all three phases passed, the code is wired correctly.

---

## Phase B — Real local stack (with Ollama)

### B.1 Start Ollama

In its own terminal:

```bash
ollama serve
```

In another terminal:

```bash
ollama pull mistral       # ~4 GB download; only on first run
```

Sanity:

```bash
curl -s http://127.0.0.1:11434/api/tags | python3 -m json.tool
```

### B.2 Set a real auth token

```bash
python3 -c "import secrets; print(secrets.token_urlsafe(24))"
```

Paste the output into `config.yaml` under `auth.token`, then export it in
every terminal that will talk to the bridge:

```bash
export ARGUS_TOKEN='<paste token here>'
```

PowerShell:

```powershell
$env:ARGUS_TOKEN = "<paste token here>"
```

### B.3 Start the bridge

```bash
source .venv/bin/activate
python3 -m llm_bridge.bridge
```

You should see the banner with `ollama: OK`, `chromadb: OK`, `sqlite: OK`,
`llm cache: OK`, `auth: ENFORCED`, `listening: http://127.0.0.1:8765`.

### B.4 Smoke test the bridge from the CLI

New terminal, same `ARGUS_TOKEN` exported:

```bash
# 1. Health (no auth required)
curl -s http://127.0.0.1:8765/health | python3 -m json.tool

# 2. State (auth required)
curl -s -H "X-Argus-Token: $ARGUS_TOKEN" \
     http://127.0.0.1:8765/state | python3 -m json.tool | head -40

# 3. Send a real request/response pair
curl -s -X POST http://127.0.0.1:8765/analyse \
  -H "Content-Type: application/json" \
  -H "X-Argus-Token: $ARGUS_TOKEN" \
  -d '{
    "url":"https://target/api/login",
    "tool":"manual",
    "request":"POST /api/login HTTP/1.1\nHost: target\nContent-Type: application/json\n\n{\"u\":\"admin\",\"p\":\"\"}",
    "response":"HTTP/1.1 200 OK\nContent-Type: application/json\n\n{\"token\":\"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.abc\"}"
  }' | python3 -m json.tool
```

The third call will take a few seconds on the first run (model warmup).
Subsequent calls are faster thanks to `ollama_keep_alive` and the
content-addressed response cache.

### B.5 Start the dashboard

In a third terminal:

```bash
source .venv/bin/activate
export ARGUS_TOKEN='<same token>'
streamlit run dashboard/app.py
```

Streamlit opens `http://127.0.0.1:8501`. You should see:

- Risk counters at the top
- Findings table with CWE / CVSS / source / occurrences columns
- Sidebar with LLM metrics, cache hit/miss ratio, filter stats, dedup

### B.6 Hook up Burp (optional)

1. Launch Burp with the same `ARGUS_TOKEN` in its environment.
2. **Extensions -> Add -> Python**, point at
   `burp_extension/llm_analyser.py`.
3. Browse the target through the Burp proxy. Interesting items appear in
   the dashboard within ~1-2 seconds of capture.

### B.7 Generate a report and archive the session

```bash
# Engagement report (markdown)
curl -s -H "X-Argus-Token: $ARGUS_TOKEN" \
     http://127.0.0.1:8765/session/report > engagement.md

# Archive this session, start a new one
curl -s -X POST -H "X-Argus-Token: $ARGUS_TOKEN" \
     http://127.0.0.1:8765/session/clear | python3 -m json.tool
```

---

## Quick commands cheat sheet

| Action                   | Command                                                                 |
|--------------------------|-------------------------------------------------------------------------|
| Activate venv            | `source .venv/bin/activate`                                             |
| Run tests                | `pytest -q`                                                             |
| Start bridge             | `python3 -m llm_bridge.bridge`                                          |
| Start dashboard          | `streamlit run dashboard/app.py`                                        |
| Health                   | `curl -s http://127.0.0.1:8765/health \| python3 -m json.tool`          |
| State (auth)             | `curl -sH "X-Argus-Token: $ARGUS_TOKEN" http://127.0.0.1:8765/state`    |
| Metrics                  | `curl -sH "X-Argus-Token: $ARGUS_TOKEN" http://127.0.0.1:8765/metrics`  |
| Report                   | `curl -sH "X-Argus-Token: $ARGUS_TOKEN" http://127.0.0.1:8765/session/report` |
| Archive session          | `curl -sX POST -H "X-Argus-Token: $ARGUS_TOKEN" http://127.0.0.1:8765/session/clear` |
| Inspect SQLite           | `sqlite3 storage/findings.db "SELECT id,risk,url FROM findings"`        |

---

## Troubleshooting

**`pytest` fails with `ModuleNotFoundError: No module named 'llm_bridge'`** —
run from the repo root (`Argus/`). `pytest` adds the CWD to `sys.path`.

**Bridge banner shows `ollama: UNREACHABLE`** — `ollama serve` is not
running, or `ollama_url` in `config.yaml` points somewhere else.

**Every `/analyse` returns `risk: none`** — the pre-filter decided the
request was noise. Check the URL: static assets, `/health`, `/favicon.ico`,
oversized responses (>100 KiB by default) all get dropped. Lower the filter
thresholds or disable it in `config.yaml` while debugging.

**Dashboard shows empty table** — token mismatch. The dashboard reads
`ARGUS_TOKEN` from the environment at launch; stopping it, re-exporting,
and restarting Streamlit is the fix.

**`storage/findings.db` locked** — some other process (old bridge?
aborted test run?) still holds it. `lsof storage/findings.db`, kill the
holder, or run the smoke test in `/tmp/` like Phase A does.
