"""
Centralised config loader + structured logging.

Security intent: ALL tuneables (model name, endpoints, rate limits, truncation
thresholds, filter rules, auth token) must come from config.yaml. Nothing is
hard-coded so operators can audit the settings of their local engagement
from a single file. Structured JSON logs make offline forensics trivial.
"""
from __future__ import annotations

import json
import logging
import logging.handlers
import time
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from . import PROJECT_ROOT

CONFIG_PATH: Path = PROJECT_ROOT / "config.yaml"


@lru_cache(maxsize=1)
def load_config() -> dict[str, Any]:
    """Load and cache config.yaml. Fails loudly if the file is missing."""
    if not CONFIG_PATH.exists():
        raise FileNotFoundError(
            f"config.yaml not found at {CONFIG_PATH}. "
            "Argus refuses to run without an explicit config."
        )
    with CONFIG_PATH.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    if not isinstance(data, dict):
        raise ValueError("config.yaml must contain a mapping at the top level")
    return data


def resolve_path(relative: str) -> Path:
    """Resolve a path from config.yaml relative to the project root."""
    p = Path(relative)
    if not p.is_absolute():
        p = PROJECT_ROOT / p
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------


class _JsonFormatter(logging.Formatter):
    """Minimal structured formatter — one JSON object per line."""

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
