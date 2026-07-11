"""
Content-addressed cache for LLM analysis results.

Security intent: a real engagement issues thousands of similar requests
(`/users/1`, `/users/2`, …). Answering the LLM for every one of them is
wasteful and slow. The cache key normalises the *shape* of the request —
numeric IDs, UUIDs, and hex blobs are replaced with placeholders — and
hashes the (model, system_prompt, normalised_user_prompt) triple. Two
requests with the same shape collide; the cached `AnalysisResult` is
returned in microseconds.

The cache lives in its own SQLite file so a `/session/clear` does NOT
wipe it — operators often clear the engagement but want cached triage
across targets to persist.
"""
from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import time
from pathlib import Path
from threading import Lock
from typing import Optional

from .config import configure_logging, load_config, resolve_path

_log = configure_logging()

# ---------------------------------------------------------------------------
# Connection management
# ---------------------------------------------------------------------------

_conn: sqlite3.Connection | None = None
_conn_lock = Lock()


def _get_conn() -> sqlite3.Connection | None:
    cfg = load_config().get("cache", {})
    if not cfg.get("enabled", True):
        return None
    global _conn
    with _conn_lock:
        if _conn is None:
            path: Path = resolve_path(cfg.get("path", "storage/llm_cache.db"))
            _conn = sqlite3.connect(str(path), check_same_thread=False, isolation_level=None)
            _conn.execute("PRAGMA journal_mode=WAL")
            _conn.execute("""
                CREATE TABLE IF NOT EXISTS llm_cache (
                    key         TEXT PRIMARY KEY,
                    model       TEXT NOT NULL,
                    url_shape   TEXT NOT NULL,
                    result_json TEXT NOT NULL,
                    created     REAL NOT NULL
                )
            """)
            _conn.execute("CREATE INDEX IF NOT EXISTS idx_cache_created ON llm_cache(created)")
            _log.info("LLM cache ready at %s", path)
    return _conn


# ---------------------------------------------------------------------------
# URL / prompt normalisation
# ---------------------------------------------------------------------------

_RE_UUID = re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
                      re.IGNORECASE)
_RE_LONG_HEX = re.compile(r"\b[0-9a-f]{24,}\b", re.IGNORECASE)
_RE_LONG_NUM = re.compile(r"\b\d{3,}\b")
_RE_SHORT_NUM_PATH = re.compile(r"/\d{1,2}(?=/|\?|$)")
_RE_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


def normalise_url(url: str) -> str:
    """Collapse volatile identifiers so sibling requests share a cache key."""
    u = _RE_UUID.sub("{UUID}", url)
    u = _RE_LONG_HEX.sub("{HEX}", u)
    u = _RE_EMAIL.sub("{EMAIL}", u)
    u = _RE_LONG_NUM.sub("{N}", u)
    u = _RE_SHORT_NUM_PATH.sub("/{N}", u)
    return u


def normalise_prompt(prompt: str) -> str:
    """Remove the most obvious volatile tokens from the user prompt."""
    p = _RE_UUID.sub("{UUID}", prompt)
    p = _RE_LONG_HEX.sub("{HEX}", p)
    p = _RE_EMAIL.sub("{EMAIL}", p)
    p = _RE_LONG_NUM.sub("{N}", p)
    # Collapse short numeric path segments too so sibling requests like
    # "GET /users/1" and "GET /users/9999" produce the same key.
    p = _RE_SHORT_NUM_PATH.sub("/{N}", p)
    return p


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def make_key(*, model: str, system_prompt: str, user_prompt: str, url: str) -> str:
    """Hash the normalised (model, prompts, url_shape) into a stable key."""
    cfg = load_config().get("cache", {})
    if cfg.get("normalise_urls", True):
        user_prompt = normalise_prompt(user_prompt)
        url_shape = normalise_url(url)
    else:
        url_shape = url
    h = hashlib.sha256()
    h.update(model.encode("utf-8"))
    h.update(b"\x00")
    h.update(hashlib.sha256(system_prompt.encode("utf-8")).digest())
    h.update(b"\x00")
    h.update(hashlib.sha256(user_prompt.encode("utf-8")).digest())
    h.update(b"\x00")
    h.update(url_shape.encode("utf-8"))
    return h.hexdigest()


def get(key: str) -> Optional[dict]:
    """Return cached analysis dict, or None if miss / expired / disabled."""
    conn = _get_conn()
    if conn is None:
        return None
    cfg = load_config().get("cache", {})
    ttl = float(cfg.get("ttl_seconds", 86400))
    row = conn.execute(
        "SELECT result_json, created FROM llm_cache WHERE key = ?", (key,)
    ).fetchone()
    if not row:
        return None
    result_json, created = row
    if time.time() - float(created) > ttl:
        conn.execute("DELETE FROM llm_cache WHERE key = ?", (key,))
        return None
    try:
        return json.loads(result_json)
    except Exception:
        return None


def put(*, key: str, model: str, url: str, result: dict) -> None:
    """Persist an analysis result under `key`."""
    conn = _get_conn()
    if conn is None:
        return
    try:
        conn.execute(
            "INSERT OR REPLACE INTO llm_cache (key, model, url_shape, result_json, created) "
            "VALUES (?, ?, ?, ?, ?)",
            (key, model, normalise_url(url), json.dumps(result, ensure_ascii=False), time.time()),
        )
    except Exception as exc:  # pragma: no cover
        _log.warning("cache: put failed: %s", exc)


def size() -> int:
    """Number of rows currently held in the cache (for /metrics)."""
    conn = _get_conn()
    if conn is None:
        return 0
    try:
        return int(conn.execute("SELECT COUNT(*) FROM llm_cache").fetchone()[0])
    except Exception:
        return 0


def purge_expired() -> int:
    conn = _get_conn()
    if conn is None:
        return 0
    cfg = load_config().get("cache", {})
    ttl = float(cfg.get("ttl_seconds", 86400))
    cutoff = time.time() - ttl
    cur = conn.execute("DELETE FROM llm_cache WHERE created < ?", (cutoff,))
    return cur.rowcount or 0


def ping() -> bool:
    try:
        conn = _get_conn()
        if conn is None:
            return True  # disabled == healthy
        conn.execute("SELECT 1").fetchone()
        return True
    except Exception:
        return False


if __name__ == "__main__":
    # Smoke test the URL and prompt normaliser.
    assert normalise_url("https://x/api/users/12345/posts") == "https://x/api/users/{N}/posts"
    assert normalise_url("https://x/api/o/123e4567-e89b-12d3-a456-426614174000") == \
        "https://x/api/o/{UUID}"
    k1 = make_key(model="m", system_prompt="s", user_prompt="GET /users/1", url="https://x/users/1")
    k2 = make_key(model="m", system_prompt="s",
                  user_prompt="GET /users/9999", url="https://x/users/9999")
    assert k1 == k2, "sibling requests must collide"
    print("cache.py smoke test ok")
