"""
Self-critique pass.

Security intent: local 7B models hallucinate. The primary analyser's output
is re-scored by a cheap second model instructed to drop any finding whose
evidence cannot actually be found in the request/response it reviewed. This
typically cuts the false-positive rate materially without meaningfully
affecting recall, because the critique is only allowed to *remove*
findings, never to invent new ones.
"""
from __future__ import annotations

import json
from typing import Any

from .config import configure_logging, load_config

_log = configure_logging()

_SYSTEM = """\
You are a strict reviewer of another tool's findings. You will be given an
HTTP request/response pair and a JSON list of proposed findings.

Your ONLY job is to decide, for each finding, whether the evidence text it
cites actually appears (verbatim, or as an obvious paraphrase) in the
request/response. Do NOT invent new findings. Do NOT rewrite findings.
Output JSON ONLY, in this exact schema:

{
  "keep_indices": [integer, ...],
  "reason": "one short sentence"
}

Where keep_indices lists the zero-based positions of findings whose evidence
can be located in the provided pair. Anything not listed is dropped.
"""


def _user_prompt(request: str, response: str, findings: list[dict]) -> str:
    lines = [
        "HTTP REQUEST:\n" + request,
        "HTTP RESPONSE:\n" + response,
        "PROPOSED FINDINGS:",
    ]
    for i, f in enumerate(findings):
        lines.append(
            f"[{i}] type={f.get('type')} param={f.get('parameter')} "
            f"evidence={f.get('evidence', '')[:200]} detail={f.get('detail', '')}"
        )
    lines.append("Return the JSON object as specified.")
    return "\n\n".join(lines)


def review(
    *,
    request: str,
    response: str,
    findings: list[dict],
    call_model: Any,
) -> list[dict]:
    """
    Review and prune `findings`. `call_model` is an injected callable of the
    shape `(model: str, system: str, user: str) -> str`, kept pluggable so
    tests can supply a stub without touching Ollama.
    """
    cfg = load_config().get("critique", {})
    if not cfg.get("enabled", True) or not findings:
        return findings

    max_in = int(cfg.get("max_findings_in", 20))
    if len(findings) > max_in:
        _log.info("critique: skipping (%d findings > max %d)", len(findings), max_in)
        return findings

    model = cfg.get("model") or load_config()["model"]
    user = _user_prompt(request, response, findings)
    try:
        raw = call_model(model, _SYSTEM, user)
    except Exception as exc:
        _log.warning("critique: model call failed (%s) — keeping all findings", exc)
        return findings

    try:
        parsed = json.loads(raw) if raw.strip().startswith("{") else _extract(raw)
        keep = {int(i) for i in (parsed or {}).get("keep_indices", [])}
    except Exception as exc:
        _log.warning("critique: could not parse critique response: %s", exc)
        return findings

    if not keep:
        # Model returned an empty keep-list — be conservative and keep everything
        # rather than silently discard all findings on a parse failure.
        _log.info("critique: empty keep_indices — keeping original findings")
        return findings

    pruned = [f for i, f in enumerate(findings) if i in keep]
    for f in pruned:
        if f.get("source") == "llm":
            f["source"] = "llm+critique"
    _log.info("critique: kept %d / %d", len(pruned), len(findings))
    return pruned


def _extract(text: str) -> dict | None:
    """Best-effort JSON extraction (mirrors analyser._extract_json)."""
    depth = 0
    start = -1
    for i, ch in enumerate(text):
        if ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0 and start != -1:
                try:
                    return json.loads(text[start : i + 1])
                except Exception:
                    continue
    return None


if __name__ == "__main__":
    # Stub call_model that always keeps index 0.
    def _stub(model, system, user):
        return json.dumps({"keep_indices": [0], "reason": "ok"})
    fs = [
        {"type": "SQLi", "evidence": "syntax error", "source": "llm", "detail": "a"},
        {"type": "XSS",  "evidence": "<script>", "source": "llm", "detail": "b"},
    ]
    kept = review(request="GET / HTTP/1.1", response="HTTP/1.1 500\n\nsyntax error",
                  findings=fs, call_model=_stub)
    assert len(kept) == 1 and kept[0]["source"] == "llm+critique"
    print("critique.py smoke test ok")
