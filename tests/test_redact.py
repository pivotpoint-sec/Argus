"""Sensitive-data redaction."""
from __future__ import annotations


def _redact():
    import llm_bridge.redact as r
    return r


def test_jwt_redacted(disable_auth):
    r = _redact()
    s = "token: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4eXoifQ.YWJjZGVm-ABC_123"
    out = r.redact(s)
    assert "eyJ" not in out
    assert "[redacted-jwt]" in out


def test_cookie_header_redacted(disable_auth):
    r = _redact()
    s = "Cookie: session=abc123; csrf=def456"
    assert "[redacted-cookie]" in r.redact(s)


def test_password_field_redacted(disable_auth):
    r = _redact()
    s = '{"password":"hunter2"}'
    out = r.redact(s)
    assert "hunter2" not in out


def test_aws_key_redacted(disable_auth):
    r = _redact()
    out = r.redact("leak: AKIAIOSFODNN7EXAMPLE")
    assert "[redacted-aws-key]" in out
    assert "AKIA" not in out


def test_idempotent(disable_auth):
    r = _redact()
    s = '{"password":"hunter2"}'
    assert r.redact(r.redact(s)) == r.redact(s)
