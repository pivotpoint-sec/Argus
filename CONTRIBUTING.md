# Contributing to Argus

Thanks for considering a contribution. A few notes on what's welcome,
how to set up, and what I'll push back on.

## What I'll happily merge

- **New detectors.** If you've hit a real-world vulnerability class
  Argus doesn't cover, a regex-based detector in
  `llm_bridge/detectors.py` or `llm_bridge/owasp_extras.py` with a test
  in `tests/test_enhancements.py` is the fastest kind of contribution
  to land.
- **New payloads** in `llm_bridge/payloads.py`, especially
  stack-specific ones. The library leans MySQL / PHP heavy at the
  moment — Java, .NET, Go and Ruby payloads are all welcome.
- **Bug fixes with a failing test that reproduces the problem first.**
  Test first, fix second, in the same PR.
- **Documentation clarifications.** If something in `README.md`,
  `USAGE.md`, or `TEST_LOCAL.md` confused you, it'll confuse the next
  person too.
- **Better installer coverage** — right now Linux, macOS and Windows
  work, but the installer scripts have rough edges around Ollama
  auto-detection.

## What I'll push back on

- **Anything that phones home.** Argus is deliberately air-gapped. The
  only outbound HTTP happens to the operator's own Ollama and (in
  agentic mode) to the operator's own target. A PR that calls a third
  party for embeddings, telemetry or anything else needs a very strong
  argument.
- **Multi-session / cross-engagement memory.** Mixing findings from
  Client A's session into Client B's session is the single biggest
  liability this kind of tool can carry. Not going there.
- **Large framework rewrites.** FastAPI + Pydantic + SQLite + ChromaDB
  is a deliberate stack. If you'd rather swap SQLite for Postgres or
  FastAPI for Litestar, please fork rather than PR.
- **Widening the automatic-attack surface** without an explicit,
  operator-visible opt-in (same pattern as `agentic.enabled` and
  `recommender.intrusive`).
- **Reformatting untouched files.** Please don't run `black` over
  half the tree in a PR that's supposed to be a bug fix.

## Setting up

```bash
python -m venv .venv
source .venv/bin/activate         # PowerShell: .venv\Scripts\Activate.ps1
pip install -r requirements.txt
pytest -q
```

If `pytest -q` doesn't come back with the full suite passing, stop and
figure out what's different in your environment before writing anything
new. Common causes: Python < 3.11, missing native deps for
`sentence-transformers`, or an active Ollama on a non-default port.

## Code style

- **Bridge, dashboard, tests:** Python 3.11+. Type hints where they
  help readability, not for their own sake.
- **`burp_extension/`:** must stay Jython 2.7-compatible. No f-strings,
  no walrus, no `from __future__ import annotations`, no dataclasses,
  no `|` type-union syntax. Burp's Python loader is Jython — this is
  an infrastructure constraint, not a preference.
- **Line length:** up to 100 characters is fine.
- **Formatter:** I'm not picky about black vs autopep8. Match the file
  you're editing.

## Pull requests

1. Fork, branch off `main`, write the change with tests.
2. `pytest -q` locally, all green.
3. Open a PR describing: what problem this solves, how you verified it,
   anything I should test manually before merging.
4. For a new detector, include a real request/response snippet in the
   PR body. It makes review much faster and gives us a regression case.

Small PRs land quickly. If you're planning something over ~200 lines,
please open an issue first so we can agree on the shape before you
spend the time.

## Review and timing

This is a side project. Aim for a first response within a week; usually
faster. Please bear with me during busy periods at the day job.

Thanks for reading this far, and thanks in advance for the PR.
