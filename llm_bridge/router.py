"""
Multi-model router.

Security intent: different local models have different strengths. CodeLlama
is stronger on SSTI/deserialisation gadgets and JS source inspection;
LLaMA-3 reasons better about access control and OAuth flows; Mistral is a
solid fast default. Picking the right specialist per request improves
precision without slowing the common path.

If a specialist model is not pulled locally, the router transparently falls
back to the default model — the feature is opportunistic, not required.
"""
from __future__ import annotations

import re
from functools import lru_cache
from typing import Optional
from urllib.parse import urlparse

import httpx

from .config import configure_logging, load_config

_log = configure_logging()


# ---------------------------------------------------------------------------
# Route classifiers
# ---------------------------------------------------------------------------

_AUTH_URL_HINTS = (
    "/login", "/logout", "/auth", "/oauth", "/token", "/session",
    "/account", "/password", "/reset", "/2fa", "/mfa", "/sso",
    "/callback", "/refresh",
)

_CODE_URL_HINTS = (
    "/upload", "/import", "/export", "/render", "/template",
    "/exec", "/evaluate", "/admin/shell", "/api/graphql",
)

_CODE_CT_HINTS = (
    "application/javascript", "text/javascript", "application/x-javascript",
    "text/x-python", "application/x-yaml", "text/yaml", "application/xml",
)

_RE_CT = re.compile(r"^content-type\s*:\s*([^\r\n]+)$", re.IGNORECASE | re.MULTILINE)


def _looks_like_code_response(response: str) -> bool:
    m = _RE_CT.search(response)
    if not m:
        return False
    ct = m.group(1).lower()
    if any(hint in ct for hint in _CODE_CT_HINTS):
        return True
    return False


def _looks_like_code_request(request: str) -> bool:
    if "multipart/form-data" in request.lower():
        return True
    if "application/xml" in request.lower():
        return True
    return False


def classify(url: str, request: str, response: str) -> str:
    """Return one of `auth`, `code`, or `general`."""
    path = urlparse(url).path.lower()
    if any(h in path for h in _AUTH_URL_HINTS):
        return "auth"
    if any(h in path for h in _CODE_URL_HINTS):
        return "code"
    if _looks_like_code_request(request) or _looks_like_code_response(response):
        return "code"
    if path.endswith(".js"):
        return "code"
    return "general"


# ---------------------------------------------------------------------------
# Availability probe — cached so we don't round-trip to Ollama every call.
# ---------------------------------------------------------------------------


@lru_cache(maxsize=1)
def _available_models() -> frozenset[str]:
    """Return the set of model names present on the local Ollama, or empty."""
    try:
        cfg = load_config()
        r = httpx.get(cfg["ollama_url"].rstrip("/") + "/api/tags", timeout=3.0)
        r.raise_for_status()
        data = r.json()
        names: set[str] = set()
        for m in data.get("models", []):
            name = m.get("name", "")
            # Ollama returns e.g. "mistral:latest" — record both the full tag
            # and the base name so config can use either.
            names.add(name)
            if ":" in name:
                names.add(name.split(":", 1)[0])
        return frozenset(names)
    except Exception as exc:
        _log.warning("router: could not list local models: %s", exc)
        return frozenset()


def _resolve(preferred: str, default: str) -> str:
    if not preferred:
        return default
    avail = _available_models()
    if not avail:
        return preferred  # can't tell — trust the config
    if preferred in avail:
        return preferred
    _log.info("router: '%s' not pulled locally, falling back to '%s'", preferred, default)
    return default


def pick_model(url: str, request: str, response: str) -> str:
    """
    Return the best-fit model for this request, respecting config.router.
    """
    cfg = load_config()
    default = cfg["model"]
    rcfg = cfg.get("router", {})
    if not rcfg.get("enabled", True):
        return default
    route = classify(url, request, response)
    preferred: Optional[str] = rcfg.get(route, default)
    return _resolve(preferred or default, default)


def invalidate_cache() -> None:
    """Drop the cached model list (e.g. after `ollama pull`)."""
    _available_models.cache_clear()


if __name__ == "__main__":
    assert classify("https://x/api/login", "", "") == "auth"
    assert classify("https://x/static/app.js", "", "") == "code"
    assert classify("https://x/api/users", "", "HTTP/1.1 200 OK\nContent-Type: application/json\n\n{}") == "general"
    print("router.py smoke test ok — classify OK, cached models:", len(_available_models()))
