"""
Centralised config loader + structured logging.

Security intent: ALL tuneables (model name, endpoints, rate limits, truncation
thresholds, filter rules, auth token) must come from config.yaml. Nothing is
hard-coded so operators can audit the settings of their local engagement
from a single file. Structured JSON logs make offline forensics trivial.

Environment overlay: after loading YAML, a small set of env vars can override
individual keys (see _ENV_OVERLAY). This is what makes the Docker compose
story work (bridge inside a container needs ollama_url pointing at the sibling
container, not localhost) and lets operators keep secrets out of the tracked
config.yaml by exporting ARGUS_TOKEN instead of editing the file.

Startup guard: validate_startup_config() refuses to run when auth is enforced
but the token is empty, still on the installer placeholder, or under 16 chars.
Called from bridge.py's lifespan before anything else.
"""
from __future__ import annotations

import json
import logging
import logging.handlers
import os
import time
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from . import PROJECT_ROOT

CONFIG_PATH: Path = PROJECT_ROOT / "config.yaml"


# ---------------------------------------------------------------------------
# Environment overlay
# ---------------------------------------------------------------------------

# Mapping: env var name -> dotted path into the config dict.
# Any env var present here (and set to a non-empty string) overrides the
# corresponding YAML value. Keys ending in "_port" are coerced to int.
_ENV_OVERLAY: dict[str, tuple[str, ...]] = {
    "OLLAMA_URL":        ("ollama_url",),
    "OLLAMA_KEEP_ALIVE": ("ollama_keep_alive",),
    "ARGUS_MODEL":       ("model",),
    "ARGUS_TOKEN":       ("auth", "token"),
    "BRIDGE_HOST":       ("bridge_host",),
    "BRIDGE_PORT":       ("bridge_port",),
    "LOG_LEVEL":         ("log_level",),
}


def _apply_env_overlay(cfg: dict[str, Any]) -> None:
    """Overlay env vars from _ENV_OVERLAY onto cfg (mutates in place)."""
    for env_var, path in _ENV_OVERLAY.items():
        raw = os.environ.get(env_var)
        if raw is None or raw == "":
            # Treat unset AND empty as "no override" so an accidentally-empty
            # env var can't clear a real config value.
            continue

        value: Any = raw
        # Coerce known integer keys.
        if path[-1].endswith("_port"):
            try:
                value = int(raw)
            except ValueError as exc:
                raise ValueError(
                    f"env var {env_var}={raw!r} must be an integer"
                ) from exc

        # Walk into nested dicts, creating them as needed.
        d: Any = cfg
        for key in path[:-1]:
            existing = d.get(key)
            if existing is None:
                d[key] = {}
            elif not isinstance(existing, dict):
                raise ValueError(
                    f"env overlay path {'.'.join(path)} collides with "
                    f"non-dict value in config.yaml"
                )
            d = d[key]
        d[path[-1]] = value


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------


@lru_cache(maxsize=1)
def load_config() -> dict[str, Any]:
    """Load config.yaml and overlay env vars. Cached for the process lifetime."""
    if not CONFIG_PATH.exists():
        raise FileNotFoundError(
            f"config.yaml not found at {CONFIG_PATH}. "
            "Argus refuses to run without an explicit config."
        )
    with CONFIG_PATH.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    if not isinstance(data, dict):
        raise ValueError("config.yaml must contain a mapping at the top level")
    _apply_env_overlay(data)
    return data


def resolve_path(relative: str) -> Path:
    """Resolve a path from config.yaml relative to the project root."""
    p = Path(relative)
    if not p.is_absolute():
        p = PROJECT_ROOT / p
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


# ---------------------------------------------------------------------------
# Startup validation
# ---------------------------------------------------------------------------


PLACEHOLDER_TOKEN = "change-me-before-first-run"
MIN_TOKEN_LEN = 16


def validate_startup_config(cfg: dict[str, Any]) -> None:
    """
    Refuse to start if auth is enforced but the token is missing / default / weak.
    Raises SystemExit with a helpful message on failure. Safe to call multiple
    times; called from bridge.py's lifespan before the banner.
    """
    auth = cfg.get("auth", {}) or {}
    if not auth.get("enabled", True):
        return
    token = str(auth.get("token") or "")
    if not token:
        raise SystemExit(
            "Argus refuses to start: auth.enabled=true but no token is set. "
            "Set ARGUS_TOKEN in the environment, or auth.token in config.yaml. "
            "To disable auth entirely, set auth.enabled=false."
        )
    if token == PLACEHOLDER_TOKEN:
        raise SystemExit(
            "Argus refuses to start: auth.token still holds the installer "
            f"placeholder '{PLACEHOLDER_TOKEN}'. Run installer/install.sh to "
            "generate a fresh token, or set ARGUS_TOKEN in the environment."
        )
    if len(token) < MIN_TOKEN_LEN:
        raise SystemExit(
            f"Argus refuses to start: auth.token is only {len(token)} chars; "
            f"at least {MIN_TOKEN_LEN} required. Generate with: "
            "python -c 'import secrets; print(secrets.token_urlsafe(24))'"
        )


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------


class _JsonFormatter(logging.Formatter):
    """Minimal structured formatter - one JSON object per line."""

    def format(self, record: logging.LogRecord) -> str:  # noqa: D401
        payload = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created)) + "Z",
            "lvl": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        # Attach correlation_id / url / etc. when a caller passes them via extra=...
        for k, v in getattr(record, "__dict__", {}).items():
            if k in payload or k.startswith("_") or k in _LOG_RECORD_RESERVED:
                continue
            try:
                json.dumps(v)
                payload[k] = v
            except Exception:
                payload[k] = repr(v)
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)


_LOG_RECORD_RESERVED = {
    "name", "msg", "args", "levelname", "levelno", "pathname", "filename",
    "module", "exc_info", "exc_text", "stack_info", "lineno", "funcName",
    "created", "msecs", "relativeCreated", "thread", "threadName",
    "processName", "process", "getMessage", "message",
}


_logging_configured = False


def configure_logging() -> logging.Logger:
    """Install a JSON stream+rotating-file handler on the root logger once."""
    global _logging_configured
    cfg = load_config()
    level_name = str(cfg.get("log_level", "INFO")).upper()
    level = getattr(logging, level_name, logging.INFO)
    root = logging.getLogger()
    if not _logging_configured:
        for h in list(root.handlers):
            root.removeHandler(h)
        stream = logging.StreamHandler()
        stream.setFormatter(_JsonFormatter())
        root.addHandler(stream)
        log_path = resolve_path(cfg.get("log_file", "logs/argus.log"))
        try:
            fileh = logging.handlers.RotatingFileHandler(
                str(log_path),
                maxBytes=int(cfg.get("log_max_bytes", 5 * 1024 * 1024)),
                backupCount=int(cfg.get("log_backups", 3)),
                encoding="utf-8",
            )
            fileh.setFormatter(_JsonFormatter())
            root.addHandler(fileh)
        except Exception:
            # Never let logging init take down the bridge.
            pass
        _logging_configured = True
    root.setLevel(level)
    return logging.getLogger("argus")


if __name__ == "__main__":
    cfg = load_config()
    log = configure_logging()
    log.info("config.py smoke test ok", extra={"model": cfg.get("model")})
    print("config keys:", sorted(cfg.keys()))
