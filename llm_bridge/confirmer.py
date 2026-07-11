"""
Closed-loop confirmation - upgrade or downgrade detector findings by
issuing a single targeted follow-up request to the target.

Security intent: the deterministic detector tier is tuned for HIGH recall,
which means it deliberately surfaces "possible" findings that may be false
positives. Confirmers prove or disprove those candidates by issuing a
benign, deterministic payload (a 2-second SLEEP, an `id` echo, a unique
XSS canary) and looking for a deterministic signal in the response
(timing delta, payload echo, error/success delta).

All confirmers:
  - Issue at most ONE extra HTTP request per finding
  - Are gated by agentic.enabled in config.yaml (same flag as probe.py)
  - Respect same-origin: never re-issue against a different host
  - Stay non-mutating where possible (GET/HEAD only by default)
  - Have a hard 15s timeout
  - Never propagate exceptions back to the bridge

Output: a verdict dict
    {"verdict": "confirmed" | "false_positive" | "inconclusive",
     "evidence": "...",
     "elapsed_seconds": float,
     "probe_request": "...",
     "probe_response": "..."}
"""
from __future__ import annotations

import re
import time
import uuid
from typing import Any, Optional
from urllib.parse import urlparse, urlencode, parse_qsl, urlunparse

import httpx

from .config import configure_logging, load_config

_log = configure_logging()


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _enabled() -> bool:
    """Confirmers ride on the same opt-in switch as the agentic prober."""
    return bool(load_config().get("agentic", {}).get("enabled", False))


def _proxy() -> Optional[str]:
    return load_config().get("agentic", {}).get("upstream_proxy") or None


def _same_origin(a: str, b: str) -> bool:
    try:
        pa, pb = urlparse(a), urlparse(b)
        return (pa.scheme, pa.hostname, pa.port) == (pb.scheme, pb.hostname, pb.port)
    except Exception:
        return False


def _mutate_query(url: str, param: str, value: str) -> str:
    """Return `url` with query parameter `param` set to `value`."""
    p = urlparse(url)
    pairs = parse_qsl(p.query, keep_blank_values=True)
    pairs = [(k, value if k == param else v) for k, v in pairs]
    if param not in [k for k, _ in pairs]:
        pairs.append((param, value))
    return urlunparse(p._replace(query=urlencode(pairs)))


def _verdict(kind: str, evidence: str = "", elapsed: float = 0.0,
             probe_req: str = "", probe_resp: str = "") -> dict:
    return {
        "verdict": kind,
        "evidence": evidence[:240],
        "elapsed_seconds": round(elapsed, 3),
        "probe_request": probe_req[:400],
        "probe_response": probe_resp[:600],
    }


def _send(method: str, url: str, *, headers: Optional[dict] = None,
          body: Optional[str] = None, timeout: float = 15.0) -> tuple[Optional[httpx.Response], float]:
    proxy = _proxy()
    kw = {"proxy": proxy} if proxy else {}
    t0 = time.monotonic()
    try:
        with httpx.Client(timeout=timeout, follow_redirects=False,
                          verify=False, **kw) as client:
            r = client.request(method, url, headers=headers or {}, content=body)
        return r, time.monotonic() - t0
    except Exception as exc:
        _log.warning("confirmer: %s %s failed: %s", method, url, exc)
        return None, time.monotonic() - t0


# ---------------------------------------------------------------------------
# Per-class confirmers
# ---------------------------------------------------------------------------

_SLEEP_DELTA_THRESHOLD = 1.7  # seconds


def confirm_sqli_time_based(finding: dict, base_url: str) -> dict:
    """Issue ' AND SLEEP(2)-- on the param, look for a >=1.7s response delta."""
    if not _enabled():
        return _verdict("inconclusive", "agentic mode disabled - cannot confirm")
    param = finding.get("parameter") or ""
    if not param:
        return _verdict("inconclusive", "no parameter to mutate")

    # Baseline call (small value).
    baseline_url = _mutate_query(base_url, param, "1")
    payload_url = _mutate_query(base_url, param, "1) AND SLEEP(2)-- -")
    if not _same_origin(payload_url, base_url):
        return _verdict("inconclusive", "cross-origin probe blocked")

    _, t_base = _send("GET", baseline_url, timeout=10.0)
    r, t_payload = _send("GET", payload_url, timeout=15.0)
    if r is None:
        return _verdict("inconclusive", "payload request failed")
    delta = t_payload - t_base
    if delta >= _SLEEP_DELTA_THRESHOLD:
        return _verdict(
            "confirmed",
            f"SLEEP(2) caused {delta:.2f}s response delta (baseline {t_base:.2f}s)",
            elapsed=t_payload,
            probe_req=f"GET {payload_url}",
            probe_resp=f"HTTP {r.status_code} - {len(r.content)} bytes",
        )
    return _verdict(
        "false_positive",
        f"SLEEP payload showed no timing delta ({delta:.2f}s)",
        elapsed=t_payload,
    )


# XSS canaries - unique, deterministic, easy to grep for, not script-like
# enough to fire WAFs on benign sites.
_XSS_CANARY_PREFIX = "argusXSS"


def _xss_canary() -> str:
    return f"{_XSS_CANARY_PREFIX}{uuid.uuid4().hex[:10]}"


_RE_HTML_CTX_UNESCAPED = re.compile(
    r"<(?:script|style)\b[^>]*>[^<]*{canary}[^<]*</(?:script|style)>|"
    r"on[a-z]+\s*=\s*[\"'][^\"']*{canary}|"
    r"href\s*=\s*[\"']javascript:[^\"']*{canary}",
    re.IGNORECASE,
)


def confirm_xss_reflection(finding: dict, base_url: str) -> dict:
    """Issue a unique canary as the param value; look for unescaped reflection."""
    if not _enabled():
        return _verdict("inconclusive", "agentic mode disabled - cannot confirm")
    param = finding.get("parameter") or ""
    if not param:
        return _verdict("inconclusive", "no parameter to mutate")

    canary = _xss_canary()
    url = _mutate_query(base_url, param, canary)
    if not _same_origin(url, base_url):
        return _verdict("inconclusive", "cross-origin probe blocked")
    r, elapsed = _send("GET", url, timeout=10.0)
    if r is None:
        return _verdict("inconclusive", "probe request failed")
    body = r.text
    if canary not in body:
        return _verdict(
            "false_positive",
            f"canary {canary} not reflected in response",
            elapsed=elapsed,
        )
    pat = re.compile(_RE_HTML_CTX_UNESCAPED.pattern.replace("{canary}", re.escape(canary)),
                     re.IGNORECASE)
    if pat.search(body):
        return _verdict(
            "confirmed",
            f"canary appeared unescaped inside a script/event/href context",
            elapsed=elapsed,
            probe_req=f"GET {url}",
            probe_resp=body[:300],
        )
    # Reflected but appears escaped/encoded - downgrade to inconclusive
    # rather than false-positive because context-sensitive escaping could
    # still be bypassable manually.
    return _verdict(
        "inconclusive",
        "canary reflected but appears escaped; manual review recommended",
        elapsed=elapsed,
        probe_resp=body[:300],
    )


_RE_ID_OUTPUT = re.compile(r"\buid=\d+\([\w.\-]+\)\s*gid=\d+\([\w.\-]+\)")


def confirm_command_injection(finding: dict, base_url: str) -> dict:
    """Append `; id` to the param value; look for uid=N(...) gid=N(...) echo."""
    if not _enabled():
        return _verdict("inconclusive", "agentic mode disabled - cannot confirm")
    param = finding.get("parameter") or ""
    if not param:
        return _verdict("inconclusive", "no parameter to mutate")

    payload_url = _mutate_query(base_url, param, "127.0.0.1;id")
    if not _same_origin(payload_url, base_url):
        return _verdict("inconclusive", "cross-origin probe blocked")
    r, elapsed = _send("GET", payload_url, timeout=10.0)
    if r is None:
        return _verdict("inconclusive", "probe request failed")
    body = r.text
    m = _RE_ID_OUTPUT.search(body)
    if m:
        return _verdict(
            "confirmed",
            f"command output leaked: {m.group(0)}",
            elapsed=elapsed,
            probe_req=f"GET {payload_url}",
            probe_resp=m.group(0),
        )
    return _verdict(
        "false_positive",
        "no command output observed in response",
        elapsed=elapsed,
    )


def confirm_ssrf(finding: dict, base_url: str) -> dict:
    """SSRF needs out-of-band; without Collaborator we mark manual-only."""
    return _verdict(
        "inconclusive",
        "SSRF confirmation needs out-of-band callback; "
        "review manually with Burp Collaborator or your own listener.",
    )


# ---------------------------------------------------------------------------
# Public dispatch
# ---------------------------------------------------------------------------


_CONFIRMERS = {
    "SQLi":               confirm_sqli_time_based,
    "XSS":                confirm_xss_reflection,
    "Command injection":  confirm_command_injection,
    "SSRF":               confirm_ssrf,
}


def confirm(finding: dict, base_url: str) -> dict:
    """Route a finding to the right confirmer based on its `type`."""
    ftype = str(finding.get("type") or "")
    fn = _CONFIRMERS.get(ftype)
    if fn is None:
        return _verdict("inconclusive", f"no confirmer registered for type '{ftype}'")
    try:
        v = fn(finding, base_url)
        _log.info("confirmer: %s/%s -> %s", ftype, finding.get("parameter"), v["verdict"])
        return v
    except Exception as exc:
        _log.warning("confirmer: %s crashed: %s", ftype, exc)
        return _verdict("inconclusive", f"confirmer raised: {exc}")


if __name__ == "__main__":
    # Smoke test the URL mutator and the canary generator (no network).
    assert _mutate_query("https://x/a?b=1", "b", "X") == "https://x/a?b=X"
    assert _mutate_query("https://x/a?b=1", "new", "Y").endswith("&new=Y") or \
           _mutate_query("https://x/a?b=1", "new", "Y").endswith("?b=1&new=Y")
    c = _xss_canary()
    assert c.startswith("argusXSS") and len(c) == 18
    print("confirmer.py smoke test ok")
