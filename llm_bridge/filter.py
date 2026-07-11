"""
Pre-filter: decide whether a request/response pair is even worth sending to
the local LLM.

Security intent: the LLM is the slow, expensive component. By dropping
obvious noise (static assets, health checks, oversized blobs) and keeping
anything that smells like an attack surface (auth endpoints, parameterised
APIs, error responses) we get useful triage at workable speeds without
sacrificing recall on the things that matter.
"""
from __future__ import annotations

import re
from urllib.parse import urlparse

from .config import configure_logging, load_config

_log = configure_logging()

# ---------------------------------------------------------------------------
# Heuristic tables (kept module-level so they're auditable at a glance)
# ---------------------------------------------------------------------------

INTERESTING_URL_FRAGMENTS: tuple[str, ...] = (
    "/api/", "/admin", "/login", "/auth", "/upload", "/graphql",
    "/v1/", "/v2/", "/user", "/account", "/password", "/token",
    "/oauth", "/callback", "/reset", "/export", "/import",
)

INTERESTING_PARAM_NAMES: tuple[str, ...] = (
    "id", "user", "uid", "account", "token", "key", "secret", "file",
    "path", "redirect", "url", "next", "callback", "ref", "session",
    "auth", "admin", "role", "type", "action",
)

INTERESTING_RESPONSE_HEADERS: tuple[str, ...] = (
    "set-cookie", "authorization", "x-auth", "token", "session",
)

INTERESTING_STATUS: frozenset[int] = frozenset({401, 403, 500, 502})

STATIC_ASSET_EXTENSIONS: tuple[str, ...] = (
    ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".ico",
    ".woff", ".woff2", ".ttf", ".svg", ".map", ".webp",
)

NOISE_PATHS: tuple[str, ...] = ("/health", "/ping", "/metrics", "/healthz", "/readyz")

_RE_CONTENT_LENGTH = re.compile(r"^content-length\s*:\s*(\d+)\s*$", re.IGNORECASE | re.MULTILINE)
_RE_CONTENT_TYPE = re.compile(r"^content-type\s*:\s*([^\r\n]+)$", re.IGNORECASE | re.MULTILINE)
_RE_STATUS = re.compile(r"^HTTP/\d(?:\.\d)?\s+(\d{3})", re.MULTILINE)
_RE_REQ_LINE = re.compile(r"^([A-Z]+)\s+(\S+)\s+HTTP/", re.MULTILINE)


def _header_value(blob: str, name: str) -> str | None:
    """Return the first value of header `name` from a raw HTTP blob."""
    pattern = re.compile(rf"^{re.escape(name)}\s*:\s*([^\r\n]+)$", re.IGNORECASE | re.MULTILINE)
    m = pattern.search(blob)
    return m.group(1).strip() if m else None


def _response_status(response: str) -> int | None:
    m = _RE_STATUS.search(response)
    return int(m.group(1)) if m else None


def _request_method(request: str) -> str | None:
    m = _RE_REQ_LINE.search(request)
    return m.group(1).upper() if m else None


def _request_has_body(request: str) -> bool:
    """True if the request looks like a real POST/PUT/PATCH with a body."""
    method = _request_method(request) or ""
    if method not in {"POST", "PUT", "PATCH", "DELETE"}:
        return False
    cl = _RE_CONTENT_LENGTH.search(request)
    if cl:
        try:
            return int(cl.group(1)) > 0
        except ValueError:
            return False
    # Fall back: inspect for a blank line followed by non-whitespace body.
    parts = re.split(r"\r?\n\r?\n", request, maxsplit=1)
    return len(parts) == 2 and bool(parts[1].strip())


def _is_static_asset(url: str) -> bool:
    path = urlparse(url).path.lower()
    return any(path.endswith(ext) for ext in STATIC_ASSET_EXTENSIONS)


def _is_noise_path(url: str) -> bool:
    path = urlparse(url).path.lower().rstrip("/")
    return any(path == n or path.endswith(n) for n in NOISE_PATHS)


def _has_interesting_query_param(url: str) -> bool:
    query = urlparse(url).query.lower()
    if not query:
        return False
    # Match `name=` to avoid substring false-positives (e.g. "redirect" inside a value).
    pairs = [p.split("=", 1)[0] for p in query.split("&") if "=" in p]
    return any(name in pairs for name in INTERESTING_PARAM_NAMES)


def _response_size_ok(response: str, min_size: int, max_size: int) -> bool:
    # Prefer the declared Content-Length, fall back to the body length.
    cl = _RE_CONTENT_LENGTH.search(response)
    if cl:
        try:
            size = int(cl.group(1))
        except ValueError:
            size = len(response)
    else:
        parts = re.split(r"\r?\n\r?\n", response, maxsplit=1)
        size = len(parts[1]) if len(parts) == 2 else len(response)
    return min_size <= size <= max_size


def _response_is_json(response: str) -> bool:
    ct = _header_value(response, "content-type") or ""
    return "application/json" in ct.lower()


def _response_has_interesting_header(response: str) -> bool:
    lowered = response.lower()
    return any(f"\n{h}:" in lowered or lowered.startswith(f"{h}:") for h in INTERESTING_RESPONSE_HEADERS)


def _has_bearer_auth(request: str) -> bool:
    return bool(re.search(r"^authorization\s*:\s*bearer\s+", request, re.IGNORECASE | re.MULTILINE))


# ---------------------------------------------------------------------------
# 60-second duplicate dedup (spec rule: same method+URL+body hash drops)
# ---------------------------------------------------------------------------

import hashlib as _hashlib
import time as _time
from threading import Lock as _Lock

_DEDUP_LOCK = _Lock()
_DEDUP_SEEN: dict[str, float] = {}


def _dedup_key(request: str, url: str) -> str:
    method = _request_method(request) or ""
    body = ""
    parts = re.split(r"\r?\n\r?\n", request, maxsplit=1)
    if len(parts) == 2:
        body = parts[1]
    h = _hashlib.sha1()
    h.update(method.encode("utf-8", "ignore"))
    h.update(b"\x00")
    h.update(url.encode("utf-8", "ignore"))
    h.update(b"\x00")
    h.update(body.encode("utf-8", "ignore"))
    return h.hexdigest()


def _is_recent_duplicate(request: str, url: str, window_seconds: float = 60.0) -> bool:
    key = _dedup_key(request, url)
    now = _time.time()
    with _DEDUP_LOCK:
        last = _DEDUP_SEEN.get(key)
        if last is not None and (now - last) < window_seconds:
            _DEDUP_SEEN[key] = now
            return True
        _DEDUP_SEEN[key] = now
        # Opportunistic GC so the dict doesn't grow forever.
        if len(_DEDUP_SEEN) > 5000:
            cutoff = now - window_seconds * 4
            for k, t in list(_DEDUP_SEEN.items()):
                if t < cutoff:
                    _DEDUP_SEEN.pop(k, None)
    return False


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def is_interesting(request: str, response: str, url: str) -> bool:
    """
    Return True if the request/response pair is worth sending to the LLM.

    The function is conservative: it only drops things we are confident are
    noise. Anything ambiguous is sent for triage so we don't miss findings.
    """
    cfg = load_config()
    fcfg = cfg.get("filter", {})
    if not fcfg.get("enabled", True):
        return True

    min_size = int(fcfg.get("min_response_size", 0))
    max_size = int(fcfg.get("max_response_size", 102400))

    # ---- Hard rejects -----------------------------------------------------
    if _is_static_asset(url):
        _log.debug("filter: drop static asset %s", url)
        return False
    if _is_noise_path(url):
        _log.debug("filter: drop noise path %s", url)
        return False
    if not _response_size_ok(response, min_size, max_size):
        _log.debug("filter: drop oversized/undersized response %s", url)
        return False
    if fcfg.get("dedup_window_seconds", 60) > 0 and _is_recent_duplicate(
        request, url, float(fcfg.get("dedup_window_seconds", 60))
    ):
        _log.debug("filter: drop duplicate within window %s", url)
        return False

    # ---- Soft keeps -------------------------------------------------------
    url_l = url.lower()
    if any(frag in url_l for frag in INTERESTING_URL_FRAGMENTS):
        _log.debug("filter: keep interesting URL fragment %s", url)
        return True
    if _has_interesting_query_param(url):
        _log.debug("filter: keep interesting query param %s", url)
        return True
    if _request_has_body(request):
        _log.debug("filter: keep request-with-body %s", url)
        return True
    if _has_bearer_auth(request):
        _log.debug("filter: keep request with Authorization Bearer %s", url)
        return True
    if _response_has_interesting_header(response):
        _log.debug("filter: keep auth/session header %s", url)
        return True

    status = _response_status(response)
    if status in INTERESTING_STATUS:
        _log.debug("filter: keep interesting status %s on %s", status, url)
        return True

    if _response_is_json(response):
        _log.debug("filter: keep JSON response %s", url)
        return True

    _log.debug("filter: drop uninteresting %s", url)
    return False


def request_method(request: str):
    """Public helper so the bridge can record the method without re-parsing."""
    return _request_method(request)


def response_status(response: str):
    """Public helper so the bridge can record the status without re-parsing."""
    return _response_status(response)
