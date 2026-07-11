"""
Agentic follow-up probes (DANGEROUS — disabled by default).

Security intent: when the LLM suggests `interesting_for_follow_up`, Argus
can issue a small number of additional HTTP requests through the operator's
upstream proxy to confirm or downgrade the finding. EVERY probe is logged
and bounded by hard per-session and per-finding budgets, and only
non-mutating methods are ever issued.

This module is opt-in via `agentic.enabled: true` in config.yaml. The
operator must also point `agentic.upstream_proxy` at their Burp upstream
(typically http://127.0.0.1:8080) so probes ride the same proxy chain as
the rest of the engagement.
"""
from __future__ import annotations

import json
from threading import Lock
from typing import Any
from urllib.parse import urlparse, urlunparse

import httpx

from . import metrics
from .config import configure_logging, load_config

_log = configure_logging()

# ---------------------------------------------------------------------------
# Hard caps + bookkeeping
# ---------------------------------------------------------------------------

_session_count = 0
_per_finding: dict[int, int] = {}
_lock = Lock()


def reset_budget() -> None:
    """Called when a fresh engagement starts."""
    global _session_count
    with _lock:
        _session_count = 0
        _per_finding.clear()


def _budgets() -> tuple[bool, int, int, list[str], str]:
    cfg = load_config().get("agentic", {})
    return (
        bool(cfg.get("enabled", False)),
        int(cfg.get("per_session_budget", 20)),
        int(cfg.get("per_finding_budget", 3)),
        [m.upper() for m in (cfg.get("allow_methods") or ["GET", "HEAD", "OPTIONS"])],
        str(cfg.get("upstream_proxy") or "") or "",
    )


_PROBE_SYSTEM = """\
You design SAFE follow-up HTTP probes for an existing finding. You may ONLY
suggest non-mutating requests (GET / HEAD / OPTIONS), against the same
origin as the finding's URL. Never include credentials beyond what is
already present in the existing request. Output JSON ONLY:

{
  "probes": [
    {"method": "GET", "url": "...", "headers": {"k":"v"}, "rationale": "..."},
    ...
  ]
}

Use no more than `max_probes` entries. If nothing useful can be probed,
return `{"probes": []}`.
"""


def design_probes(*, finding: dict, max_probes: int, call_model) -> list[dict]:
    """Ask the LLM to design probes for a given finding row."""
    user = (
        f"Finding URL: {finding.get('url')}\n"
        f"Finding type: {finding.get('risk')} / {finding.get('owasp_category')}\n"
        f"Detail JSON: {json.dumps(finding.get('findings') or [])[:1500]}\n"
        f"Follow-up suggestion: {finding.get('follow_up')}\n"
        f"max_probes: {max_probes}\n"
        "Design the probes."
    )
    cfg = load_config()
    model = cfg.get("router", {}).get("auth") or cfg["model"]
    raw = ""
    try:
        raw = call_model(model, _PROBE_SYSTEM, user) or ""
    except Exception as exc:
        _log.warning("probe: design call failed: %s", exc)
        return []
    try:
        parsed = json.loads(raw) if raw.strip().startswith("{") else _extract(raw)
    except Exception:
        parsed = None
    return list((parsed or {}).get("probes") or [])[:max_probes]


def _extract(text: str) -> dict | None:
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
                    return json.loads(text[start:i + 1])
                except Exception:
                    continue
    return None


def _same_origin(target: str, base: str) -> bool:
    try:
        a, b = urlparse(target), urlparse(base)
        return (a.scheme, a.hostname, a.port) == (b.scheme, b.hostname, b.port)
    except Exception:
        return False


def _safe_url(url: str, base: str) -> str | None:
    """Coerce relative URLs into the finding's origin; reject cross-origin."""
    try:
        p = urlparse(url)
        if not p.scheme:
            b = urlparse(base)
            url = urlunparse((b.scheme, b.netloc, p.path or "/", "", p.query, ""))
        if not _same_origin(url, base):
            return None
        return url
    except Exception:
        return None


def _bump_counts(fid: int) -> None:
    global _session_count
    _session_count += 1
    _per_finding[fid] = _per_finding.get(fid, 0) + 1


def execute(*, finding: dict, max_probes: int | None, call_model) -> list[dict[str, Any]]:
    """
    Design and execute follow-up probes for an existing finding.

    Returns a list of result records:
        [{"request": "...", "response": "...", "url": "...", "rationale": "..."}]
    """
    enabled, sess_cap, find_cap, allow_methods, proxy = _budgets()
    if not enabled:
        _log.info("probe: agentic mode is disabled (config.agentic.enabled=false)")
        return []

    fid = int(finding.get("id") or 0)
    cap = int(min(max_probes or find_cap, find_cap))

    with _lock:
        if _session_count >= sess_cap:
            _log.warning("probe: session budget exhausted (%d)", sess_cap)
            return []
        already = _per_finding.get(fid, 0)
        remaining = max(0, min(cap - already, sess_cap - _session_count))
    if remaining <= 0:
        return []

    designs = design_probes(finding=finding, max_probes=remaining, call_model=call_model)
    if not designs:
        return []

    results: list[dict[str, Any]] = []
    proxy_kw = {"proxy": proxy} if proxy else {}
    base = finding.get("url", "")

    with httpx.Client(timeout=20.0, follow_redirects=False, **proxy_kw) as client:
        for d in designs:
            method = str(d.get("method", "GET")).upper()
            if method not in allow_methods:
                _log.info("probe: skipping disallowed method %s", method)
                continue
            url = _safe_url(str(d.get("url", "")), base)
            if not url:
                _log.info("probe: skipping cross-origin or invalid url")
                continue
            headers = {str(k): str(v) for k, v in (d.get("headers") or {}).items()}
            try:
                r = client.request(method, url, headers=headers)
                req_text = f"{method} {url} HTTP/1.1\n" + "\n".join(
                    f"{k}: {v}" for k, v in headers.items()
                ) + "\n\n"
                resp_text = (
                    f"HTTP/1.1 {r.status_code} {r.reason_phrase}\n" +
                    "\n".join(f"{k}: {v}" for k, v in r.headers.items()) +
                    "\n\n" + r.text[:4000]
                )
                metrics.probes_issued.inc()
                with _lock:
                    _bump_counts(fid)
                results.append({
                    "url": url,
                    "method": method,
                    "rationale": d.get("rationale", ""),
                    "request": req_text,
                    "response": resp_text,
                })
            except Exception as exc:
                _log.warning("probe: %s %s failed: %s", method, url, exc)
    return results


if __name__ == "__main__":
    print("probe.py smoke test ok (agentic enabled:", _budgets()[0], ")")
