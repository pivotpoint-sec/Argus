"""
LLM analyser - talks to a local Ollama server and returns a validated
AnalysisResult.

Security intent: this module is the ONLY place outbound HTTP happens, and
it is hard-scoped to the configured Ollama URL (localhost by default). It
truncates inputs, strips binary bodies, retries with backoff on transient
failures, and throttles calls with a token bucket so a burst from Burp
cannot overload the local model.

Pipeline (per request):
    deterministic detectors -> LLM cache lookup -> router picks model ->
    Ollama call (retry + keep-alive) -> JSON extraction -> schema validate ->
    self-critique pass -> merge detector findings back in -> cache write.
"""
from __future__ import annotations

import atexit
import json
import re
import time
from threading import Lock
from typing import Any

import httpx

from burp_extension.prompts import SYSTEM_PROMPT, build_user_prompt
from . import cache as llm_cache
from . import critique as critique_mod
from . import detectors
from . import metrics
from . import router
from .config import configure_logging, load_config
from .models import AnalysisResult

_log = configure_logging()


class TokenBucket:
    """Thread-safe token bucket (capacity == rate per minute)."""

    def __init__(self, rate_per_minute):
        self.capacity = float(rate_per_minute)
        self.tokens = float(rate_per_minute)
        self.refill_rate = float(rate_per_minute) / 60.0
        self.updated = time.monotonic()
        self._lock = Lock()

    def acquire(self, timeout=30.0):
        deadline = time.monotonic() + timeout
        while True:
            with self._lock:
                now = time.monotonic()
                elapsed = now - self.updated
                self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_rate)
                self.updated = now
                if self.tokens >= 1.0:
                    self.tokens -= 1.0
                    return True
                wait = (1.0 - self.tokens) / self.refill_rate
            if time.monotonic() + wait > deadline:
                return False
            time.sleep(min(wait, 0.25))


_bucket = None
_bucket_lock = Lock()


def _get_bucket():
    global _bucket
    with _bucket_lock:
        if _bucket is None:
            cfg = load_config()
            _bucket = TokenBucket(int(cfg.get("rate_limit_per_minute", 10)))
    return _bucket


_client = None
_client_lock = Lock()


def _get_client():
    global _client
    with _client_lock:
        if _client is None:
            cfg = load_config()
            _client = httpx.Client(
                base_url=cfg["ollama_url"].rstrip("/"),
                timeout=float(cfg.get("ollama_timeout_seconds", 120)),
                headers={"User-Agent": "argus-bridge/1.1"},
            )
    return _client


@atexit.register
def _close_client():  # pragma: no cover
    global _client
    if _client is not None:
        try:
            _client.close()
        except Exception:
            pass


_BINARY_CONTENT_TYPES = (
    "image/", "video/", "audio/", "application/octet-stream",
    "application/pdf", "application/zip", "application/gzip",
    "font/", "application/x-font", "application/wasm",
)

_RE_CONTENT_TYPE = re.compile(
    r"^content-type\s*:\s*([^\r\n]+)$", re.IGNORECASE | re.MULTILINE
)


def _is_binary(blob):
    m = _RE_CONTENT_TYPE.search(blob)
    if not m:
        return False
    ct = m.group(1).strip().lower()
    return any(ct.startswith(prefix) for prefix in _BINARY_CONTENT_TYPES)


def _strip_binary_body(blob):
    if not _is_binary(blob):
        return blob
    parts = re.split(r"(\r?\n\r?\n)", blob, maxsplit=1)
    if len(parts) == 3:
        return parts[0] + parts[1] + "[binary body omitted]"
    return blob + "\n\n[binary body omitted]"


def _truncate(text, limit):
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n...[truncated at {limit} chars]"


def sanitise(request, response):
    cfg = load_config()
    req_limit = int(cfg.get("max_request_chars", 3000))
    resp_limit = int(cfg.get("max_response_chars", 3000))
    return (
        _truncate(_strip_binary_body(request), req_limit),
        _truncate(_strip_binary_body(response), resp_limit),
    )


def _extract_json(text):
    if not text:
        return None
    stripped = text.strip()
    if stripped.startswith("```"):
        stripped = re.sub(r"^```[a-zA-Z]*", "", stripped).strip()
        if stripped.endswith("```"):
            stripped = stripped[:-3].strip()
    try:
        return json.loads(stripped)
    except Exception:
        pass
    depth = 0
    start = -1
    for i, ch in enumerate(stripped):
        if ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0 and start != -1:
                try:
                    return json.loads(stripped[start : i + 1])
                except Exception:
                    continue
    return None


_ollama_status = {"up": True, "last_check": 0.0}
_ollama_status_lock = Lock()


def ollama_status():
    """Cached health snapshot for callers that don't want to ping every time."""
    with _ollama_status_lock:
        return dict(_ollama_status)


def ping_ollama():
    try:
        r = _get_client().get("/api/tags", timeout=3.0)
        ok = r.status_code == 200
    except Exception as exc:
        _log.warning("Ollama ping failed: %s", exc)
        ok = False
    with _ollama_status_lock:
        was_up = _ollama_status["up"]
        _ollama_status["up"] = ok
        _ollama_status["last_check"] = time.time()
    if ok and not was_up:
        _log.info("Ollama is back online - resuming LLM analysis")
    elif not ok and was_up:
        _log.warning("Ollama appears OFFLINE - bridge will keep pre-filtering "
                     "and re-poll every 30s")
    return ok


_reconnect_thread = None
_reconnect_lock = Lock()


def start_ollama_reconnect_poller(interval_seconds: float = 30.0):
    """Background thread that pings Ollama on a cadence; idempotent."""
    global _reconnect_thread
    with _reconnect_lock:
        if _reconnect_thread is not None and _reconnect_thread.is_alive():
            return
        import threading

        def _loop():
            while True:
                try:
                    ping_ollama()
                except Exception:
                    pass
                time.sleep(interval_seconds)

        t = threading.Thread(target=_loop, name="argus-ollama-poll", daemon=True)
        t.start()
        _reconnect_thread = t
        _log.info("Ollama reconnect poller started (every %.0fs)", interval_seconds)


def _call_ollama(model, system, user):
    """POST to /api/generate. Raises on non-2xx. Uses long-lived client."""
    cfg = load_config()
    payload = {
        "model": model,
        "prompt": user,
        "system": system,
        "stream": False,
        "format": "json",
        "keep_alive": cfg.get("ollama_keep_alive", "30m"),
        "options": {"temperature": 0.1},
    }
    r = _get_client().post("/api/generate", json=payload)
    r.raise_for_status()
    return str(r.json().get("response", ""))


def _call_with_retries(model, system, user):
    cfg = load_config()
    attempts = int(cfg.get("ollama_retry_attempts", 3))
    backoff = 1.0
    t0 = time.monotonic()
    for attempt in range(1, attempts + 1):
        try:
            metrics.llm_calls.inc()
            raw = _call_ollama(model, system, user)
            metrics.llm_latency.observe(time.monotonic() - t0)
            return raw
        except httpx.HTTPError as exc:
            metrics.llm_failures.inc()
            _log.warning("Ollama attempt %s/%s failed (%s): %s",
                         attempt, attempts, model, exc)
            if attempt == attempts:
                return None
            time.sleep(backoff)
            backoff *= 2
    return None


def analyse(*, request, response, url, tool="burp",
            memory_context="", correlation_id=None):
    cfg = load_config()
    req_limit = int(cfg.get("max_request_chars", 3000))
    resp_limit = int(cfg.get("max_response_chars", 3000))
    request, response = sanitise(request, response)

    det_findings = detectors.run_detectors(request, response, url)
    metrics.detector_findings.inc(len(det_findings))
    det_summary = detectors.summary_for_prompt(det_findings)

    memory_block = memory_context
    if det_summary:
        preamble = "Detector tier already found:\n" + det_summary
        memory_block = (preamble + "\n\n" + memory_context).strip()

    user_prompt = build_user_prompt(
        url=url, tool=tool, request=request, response=response,
        memory_context=memory_block,
        req_limit=req_limit, resp_limit=resp_limit,
    )

    model = router.pick_model(url, request, response)
    key = llm_cache.make_key(
        model=model, system_prompt=SYSTEM_PROMPT,
        user_prompt=user_prompt, url=url,
    )
    cached = llm_cache.get(key)
    if cached is not None:
        metrics.cache_hits.inc()
        return _merge_detector(cached, det_findings, from_cache=True,
                               correlation_id=correlation_id)
    metrics.cache_misses.inc()

    if not _get_bucket().acquire(timeout=30.0):
        _log.warning("analyse: rate-limited out for %s", url)
        return _empty_or_detectors(det_findings, correlation_id)

    raw = _call_with_retries(model, SYSTEM_PROMPT, user_prompt)
    if raw is None:
        return _empty_or_detectors(det_findings, correlation_id)

    parsed = _extract_json(raw)
    if not parsed:
        _log.warning("analyse: could not parse JSON from model for %s", url)
        return _empty_or_detectors(det_findings, correlation_id)

    if parsed.get("risk") == "none":
        return _empty_or_detectors(det_findings, correlation_id)

    parsed = _normalise_llm_output(parsed)
    t_c = time.monotonic()
    kept = critique_mod.review(
        request=request,
        response=response,
        findings=list(parsed.get("findings") or []),
        call_model=_call_ollama,
    )
    metrics.llm_critique_latency.observe(time.monotonic() - t_c)
    before = len(parsed.get("findings") or [])
    if len(kept) < before:
        metrics.critique_pruned.inc(before - len(kept))
    parsed["findings"] = kept

    result_dict = _merge_detector_dicts(parsed, det_findings)
    result_dict["from_cache"] = False
    result_dict["correlation_id"] = correlation_id

    try:
        llm_cache.put(key=key, model=model, url=url, result=result_dict)
    except Exception as exc:  # pragma: no cover
        _log.debug("cache put failed: %s", exc)

    try:
        return AnalysisResult.model_validate(result_dict)
    except Exception as exc:
        _log.warning("analyse: schema validation failed for %s: %s", url, exc)
        return _empty_or_detectors(det_findings, correlation_id)


def _normalise_llm_output(parsed):
    parsed.setdefault("findings", [])
    parsed.setdefault("recommend", [])
    parsed.setdefault("owasp_category", None)
    parsed.setdefault("interesting_for_follow_up", None)

    if isinstance(parsed.get("owasp_category"), str) and \
            parsed["owasp_category"].lower() in {"none", "null", ""}:
        parsed["owasp_category"] = None
    if isinstance(parsed.get("interesting_for_follow_up"), str) and \
            parsed["interesting_for_follow_up"].lower() in {"none", "null", ""}:
        parsed["interesting_for_follow_up"] = None

    clean_findings = []
    for item in parsed.get("findings") or []:
        if not isinstance(item, dict):
            continue
        item.setdefault("parameter", None)
        item.setdefault("evidence", "")
        item.setdefault("detail", "")
        item.setdefault("confidence", "possible")
        item.setdefault("source", "llm")
        item.setdefault("cwe", None)
        item.setdefault("cvss", None)
        if item.get("confidence") not in {"confirmed", "likely", "possible"}:
            item["confidence"] = "possible"
        if not item.get("type") or not item.get("evidence"):
            continue
        clean_findings.append(item)
    parsed["findings"] = clean_findings
    return parsed


_RISK_ORDER = ["none", "low", "medium", "high", "critical"]


def _escalate(a, b):
    return a if _RISK_ORDER.index(a) >= _RISK_ORDER.index(b) else b


def _merge_detector_dicts(llm, det):
    out = dict(llm)
    out.setdefault("risk", "none")
    out.setdefault("findings", [])
    out.setdefault("recommend", [])
    out["findings"] = list(out["findings"]) + list(det)
    out["risk"] = _escalate(str(out.get("risk") or "none"), detectors.worst_risk(det))
    if det and not out.get("owasp_category"):
        out["owasp_category"] = "A05:2021-Security Misconfiguration"
    return out


def _merge_detector(cached, det, *, from_cache, correlation_id):
    merged = _merge_detector_dicts(cached, det)
    merged["from_cache"] = from_cache
    merged["correlation_id"] = correlation_id
    try:
        return AnalysisResult.model_validate(merged)
    except Exception:
        return AnalysisResult(risk=merged.get("risk", "none"),
                              correlation_id=correlation_id, from_cache=from_cache)


def _empty_or_detectors(det, correlation_id):
    if not det:
        return AnalysisResult(risk="none", correlation_id=correlation_id)
    merged = _merge_detector_dicts(
        {"risk": "none", "findings": [], "recommend": []}, det,
    )
    merged["correlation_id"] = correlation_id
    try:
        return AnalysisResult.model_validate(merged)
    except Exception:
        return AnalysisResult(risk="low", correlation_id=correlation_id)


_POC_SYSTEM = (
    "You produce a minimal proof-of-concept for a given web-app finding. "
    "Respond with a single fenced code block and a one-line caption. Never "
    "include explanations outside the code block. Never attempt to "
    "exfiltrate data; only demonstrate the vulnerability against the URL "
    "provided."
)


def generate_poc(*, finding, style="curl"):
    cfg = load_config()
    model = cfg.get("report", {}).get("model") or cfg["model"]
    user = (
        f"Finding: {finding.get('type')} - {finding.get('detail')}\n"
        f"URL: {finding.get('url')}\n"
        f"Parameter: {finding.get('parameter')}\n"
        f"Evidence: {finding.get('evidence')}\n"
        f"Style: {style}\n"
        "Write the minimal PoC."
    )
    raw = _call_with_retries(model, _POC_SYSTEM, user) or ""
    return raw.strip()


# ---------------------------------------------------------------------------
# Business-logic correlation across multiple findings
# ---------------------------------------------------------------------------


_CORRELATE_SYSTEM = (
    "You are reviewing several findings already produced by an automated "
    "pentest pipeline against the SAME web application. Look for BUSINESS "
    "LOGIC bugs that ONLY become visible across multiple findings: "
    "state-machine violations, token / nonce reuse, race conditions, "
    "privilege drift, multi-step IDOR, coupon / rate-limit bypasses. "
        "Do NOT re-raise findings that are already present individually. "
    "Respond with ONLY a JSON object of shape "
    '{"findings": [{"title": "...", "detail": "one sentence", "cwe": "CWE-840 or null", "cvss": 0-10, "related_finding_ids": [int, ...]}]} or {"findings": []}.'
)


def correlate_findings(*, findings, call_model=None):
    if len(findings) < 2:
        return []
    cfg = load_config()
    model = cfg.get("report", {}).get("model") or cfg["model"]
    caller = call_model or _call_ollama
    rows = []
    for f in findings[:30]:
        first = (f.get("findings") or [{}])[0]
        rows.append({
            "id": f.get("id"),
            "url": f.get("url"),
            "type": first.get("type"),
            "parameter": first.get("parameter"),
            "detail": first.get("detail"),
            "risk": f.get("risk"),
        })
    user = "Findings (JSON list):\n" + json.dumps(rows, ensure_ascii=False)[:6000] + "\n\nReturn correlation findings as instructed."
    try:
        raw = caller(model, _CORRELATE_SYSTEM, user) or ""
    except Exception as exc:
        _log.warning("correlate: model call failed: %s", exc)
        return []
    parsed = _extract_json(raw)
    if not isinstance(parsed, dict):
        return []
    out = parsed.get("findings") or []
    return [f for f in out if isinstance(f, dict) and f.get("title")]
