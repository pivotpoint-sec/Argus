"""Deterministic detector regression tests."""
from __future__ import annotations


def _detectors():
    import llm_bridge.detectors as d
    return d


def test_detects_jwt(disable_auth):
    d = _detectors()
    resp = (
        "HTTP/1.1 200 OK\nContent-Type: application/json\n\n"
        "{\"token\": \"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4eXoifQ.YWJjZGVm-ABC_123\"}"
    )
    fs = d.run_detectors("GET / HTTP/1.1\n\n", resp, "https://x/api/me")
    assert any(f["type"] == "Sensitive data" and "JWT" in f["detail"] for f in fs)


def test_detects_aws_key(disable_auth):
    d = _detectors()
    resp = "HTTP/1.1 200 OK\nContent-Type: text/plain\n\nleak: AKIAIOSFODNN7EXAMPLE"
    fs = d.run_detectors("GET / HTTP/1.1\n\n", resp, "https://x/")
    assert any("aws" in f["detail"].lower() or "AWS" in f["detail"] for f in fs)


def test_detects_stack_trace(disable_auth):
    d = _detectors()
    resp = "HTTP/1.1 500 ISE\nContent-Type: text/html\n\nERROR: psycopg2.errors.UndefinedTable"
    fs = d.run_detectors("GET / HTTP/1.1\n\n", resp, "https://x/")
    assert any(f["type"] == "Sensitive data" for f in fs)


def test_detects_missing_security_headers(disable_auth):
    d = _detectors()
    resp = "HTTP/1.1 200 OK\nContent-Type: text/html\n\nhello"
    fs = d.run_detectors("GET / HTTP/1.1\n\n", resp, "https://x/")
    assert any(f["type"] == "Header misconfiguration" for f in fs)


def test_no_findings_on_clean_binary(disable_auth):
    d = _detectors()
    resp = "HTTP/1.1 200 OK\nContent-Type: image/png\n\n\x89PNG..."
    fs = d.run_detectors("GET / HTTP/1.1\n\n", resp, "https://x/logo.png")
    assert fs == []


def test_csp_weakness(disable_auth):
    d = _detectors()
    resp = (
        "HTTP/1.1 200 OK\n"
        "Content-Type: text/html\n"
        "Strict-Transport-Security: max-age=1\n"
        "X-Content-Type-Options: nosniff\n"
        "X-Frame-Options: DENY\n"
        "Referrer-Policy: no-referrer\n"
        "Content-Security-Policy: default-src * 'unsafe-inline' 'unsafe-eval'\n"
        "\n<html>"
    )
    fs = d.run_detectors("GET / HTTP/1.1\n\n", resp, "https://x/")
    assert any("CSP" in f["detail"] or "unsafe" in f["detail"] for f in fs)
