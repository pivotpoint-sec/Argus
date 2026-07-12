"""
Tests for env-overlay behaviour and startup config validation.

The env overlay is what makes the docker-compose story work (bridge container
needs ollama_url pointing at the sibling container) and lets operators keep
secrets out of the tracked config.yaml.

validate_startup_config refuses to run when auth is on but the token is
missing, still on the installer placeholder, or under MIN_TOKEN_LEN.
"""
from __future__ import annotations

import pytest


# ---------------------------------------------------------------------------
# Environment overlay
# ---------------------------------------------------------------------------


def test_env_overlays_top_level(_isolate, monkeypatch):
    """OLLAMA_URL in env overrides ollama_url in config.yaml."""
    from llm_bridge.config import load_config

    monkeypatch.setenv("OLLAMA_URL", "http://ollama-container:11434")
    load_config.cache_clear()
    cfg = load_config()
    assert cfg["ollama_url"] == "http://ollama-container:11434"


def test_env_overlays_nested_auth_token(_isolate, monkeypatch):
    """ARGUS_TOKEN in env overrides auth.token."""
    from llm_bridge.config import load_config

    monkeypatch.setenv("ARGUS_TOKEN", "test-token-longer-than-16-chars")
    load_config.cache_clear()
    cfg = load_config()
    assert cfg["auth"]["token"] == "test-token-longer-than-16-chars"


def test_env_bridge_port_coerced_to_int(_isolate, monkeypatch):
    """BRIDGE_PORT string is coerced to int, since callers do int() on it."""
    from llm_bridge.config import load_config

    monkeypatch.setenv("BRIDGE_PORT", "9999")
    load_config.cache_clear()
    cfg = load_config()
    assert cfg["bridge_port"] == 9999
    assert isinstance(cfg["bridge_port"], int)


def test_env_bridge_port_bad_int_raises(_isolate, monkeypatch):
    """Non-integer BRIDGE_PORT is a hard error, not a silent string."""
    from llm_bridge.config import load_config

    monkeypatch.setenv("BRIDGE_PORT", "not-a-number")
    load_config.cache_clear()
    with pytest.raises(ValueError, match="must be an integer"):
        load_config()


def test_env_empty_string_does_not_clobber(_isolate, monkeypatch):
    """Empty env var is treated as unset; must not blank the config value."""
    from llm_bridge.config import load_config

    monkeypatch.setenv("ARGUS_TOKEN", "")
    load_config.cache_clear()
    cfg = load_config()
    # The default config.yaml still ships the placeholder; overlay must leave
    # it alone rather than substitute empty string.
    assert cfg["auth"]["token"]  # non-empty


def test_env_argus_model(_isolate, monkeypatch):
    """ARGUS_MODEL overrides model — used by installer and docs."""
    from llm_bridge.config import load_config

    monkeypatch.setenv("ARGUS_MODEL", "llama3")
    load_config.cache_clear()
    cfg = load_config()
    assert cfg["model"] == "llama3"


def test_env_multiple_overrides(_isolate, monkeypatch):
    """Multiple env vars can override simultaneously."""
    from llm_bridge.config import load_config

    monkeypatch.setenv("OLLAMA_URL", "http://ollama:11434")
    monkeypatch.setenv("ARGUS_TOKEN", "x" * 32)
    monkeypatch.setenv("BRIDGE_PORT", "8000")
    load_config.cache_clear()
    cfg = load_config()
    assert cfg["ollama_url"] == "http://ollama:11434"
    assert cfg["auth"]["token"] == "x" * 32
    assert cfg["bridge_port"] == 8000


# ---------------------------------------------------------------------------
# Startup validation
# ---------------------------------------------------------------------------


def test_startup_guard_rejects_placeholder(_isolate):
    from llm_bridge.config import PLACEHOLDER_TOKEN, validate_startup_config

    with pytest.raises(SystemExit, match="placeholder"):
        validate_startup_config({
            "auth": {"enabled": True, "token": PLACEHOLDER_TOKEN},
        })


def test_startup_guard_rejects_empty_token(_isolate):
    from llm_bridge.config import validate_startup_config

    with pytest.raises(SystemExit, match="no token"):
        validate_startup_config({"auth": {"enabled": True, "token": ""}})


def test_startup_guard_rejects_missing_token(_isolate):
    """auth.token key absent altogether is treated as empty."""
    from llm_bridge.config import validate_startup_config

    with pytest.raises(SystemExit, match="no token"):
        validate_startup_config({"auth": {"enabled": True}})


def test_startup_guard_rejects_short_token(_isolate):
    from llm_bridge.config import MIN_TOKEN_LEN, validate_startup_config

    with pytest.raises(SystemExit, match=f"at least {MIN_TOKEN_LEN}"):
        validate_startup_config({
            "auth": {"enabled": True, "token": "short"},
        })


def test_startup_guard_allows_valid_token(_isolate):
    """A proper token passes without raising."""
    from llm_bridge.config import validate_startup_config

    validate_startup_config({
        "auth": {"enabled": True, "token": "a-perfectly-good-token-value"},
    })


def test_startup_guard_skips_when_auth_disabled(_isolate):
    """auth.enabled=false disables the guard entirely."""
    from llm_bridge.config import PLACEHOLDER_TOKEN, validate_startup_config

    # Even the placeholder is allowed if auth is off.
    validate_startup_config({
        "auth": {"enabled": False, "token": PLACEHOLDER_TOKEN},
    })


def test_startup_guard_default_auth_treated_as_enabled(_isolate):
    """If auth is missing entirely, we default to 'enabled' (safe default)."""
    from llm_bridge.config import validate_startup_config

    # No 'auth' key at all -> should still enforce (safer default).
    with pytest.raises(SystemExit):
        validate_startup_config({})
