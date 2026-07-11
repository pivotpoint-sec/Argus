"""
Shared-secret bearer auth for the bridge.

Security intent: even on 127.0.0.1, other local processes can reach the
bridge and either poison findings or read engagement data. A shared token
(configured in config.yaml) keeps the blast radius scoped to the Burp
extension and the dashboard, both of which are under operator control.
"""
from __future__ import annotations

import hmac

from fastapi import Header, HTTPException, status

from .config import load_config

_HEADER = "x-argus-token"


def verify_token(x_argus_token: str | None = Header(default=None)) -> None:
    """
    FastAPI dependency — reject requests whose X-Argus-Token doesn't match.

    When `auth.enabled` is False (default for dev) this is a no-op.
    """
    cfg = load_config().get("auth", {})
    if not cfg.get("enabled", False):
        return
    expected = str(cfg.get("token") or "")
    if not expected:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="auth.enabled is true but auth.token is empty",
        )
    if not x_argus_token or not hmac.compare_digest(x_argus_token, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="missing or invalid X-Argus-Token",
        )


def token_header_name() -> str:
    return _HEADER
