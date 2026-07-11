"""
Sensitive-data redaction.

Security intent: raw Burp traffic contains passwords, bearer tokens, cookies,
JWTs, and PII. Argus writes traffic to disk (logs, SQLite findings, ChromaDB
evidence). Redacting obvious secrets at two boundaries — before logging
and before persistence — limits the blast radius if the engagement data is
later exfiltrated, shared for a report, or inherited by another operator.

Detector findings are preserved UNREDACTED because they deliberately
surface the leak; it is the *surrounding* request/response text that is
scrubbed.
"""
from __future__ import annotations

import re
from typing import Iterable

from .config import configure_logging

_log = configure_logging()

# ---------------------------------------------------------------------------
# Scrub patterns. Order matters — more specific first.
# ---------------------------------------------------------------------------

_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    # JWT
    (re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
     "[redacted-jwt]"),
    # Authorization / Cookie / Set-Cookie header values
    (re.compile(r"(?im)^(authorization|proxy-authorization)\s*:\s*[^\r\n]+"),
     r"\1: [redacted-auth]"),
    (re.compile(r"(?im)^(cookie|set-cookie)\s*:\s*[^\r\n]+"),
     r"\1: [redacted-cookie]"),
    # Common password-like form fields.
    # Negative lookahead skips content already redacted by a more-specific
    # pattern (e.g. JWT, AWS key) that ran earlier in this tuple.
    (re.compile(r"(?i)([\"']?(?:password|passwd|pwd|secret|api[_-]?key|token)[\"']?\s*[:=]\s*[\"']?)(?!\[redacted)([^\"'&\s,}]{3,})"),
     r"\1[redacted]"),
    # AWS keys
    (re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"), "[redacted-aws-key]"),
    # Google API keys
    (re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), "[redacted-google-key]"),
    # Stripe
    (re.compile(r"\bsk_(?:live|test)_[0-9a-zA-Z]{24,}\b"), "[redacted-stripe-key]"),
    # GitHub
    (re.compile(r"\bghp_[0-9A-Za-z]{36}\b"), "[redacted-github-token]"),
    (re.compile(r"\bgithub_pat_[0-9A-Za-z_]{70,}\b"), "[redacted-github-token]"),
    # Bearer tokens inline
    (re.compile(r"\bBearer\s+[A-Za-z0-9\-._~+/]{16,}=*\b"), "Bearer [redacted]"),
    # Private keys
    (re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |)PRIVATE KEY-----[\s\S]*?-----END [^-]+-----"),
     "[redacted-private-key]"),
    # Credit card numbers (loose Luhn-ish)
    (re.compile(r"\b(?:\d[ -]*?){13,19}\b"), "[redacted-cc]"),
    # Email addresses — we only redact obvious ones, keeping domains helps
    # with triage so we replace the local-part only.
    (re.compile(r"([A-Za-z0-9._%+-]+)@([A-Za-z0-9.-]+\.[A-Za-z]{2,})"),
     r"[redacted]@\2"),
)


def redact(text: str) -> str:
    """Apply every redaction pattern to `text`. Idempotent."""
    if not text:
        return text
    out = text
    for pat, repl in _PATTERNS:
        try:
            out = pat.sub(repl, out)
        except Exception as exc:  # pragma: no cover
            _log.debug("redact: pattern failed: %s", exc)
    return out


def redact_all(*texts: str) -> list[str]:
    return [redact(t) for t in texts]


def redact_fields(d: dict, keys: Iterable[str]) -> dict:
    """Return a shallow copy of `d` with `keys` redacted."""
    out = dict(d)
    for k in keys:
        if k in out and isinstance(out[k], str):
            out[k] = redact(out[k])
    return out


if __name__ == "__main__":
    sample = (
        "POST /login HTTP/1.1\nCookie: sid=abc123\n\n"
        "{\"password\":\"hunter2\",\"token\":\"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.YWJj-def_123\"}"
    )
    out = redact(sample)
    assert "hunter2" not in out
    assert "eyJ" not in out
    assert "[redacted-cookie]" in out
    print("redact.py smoke test ok")
