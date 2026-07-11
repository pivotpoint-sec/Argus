"""JSON extraction + sanitation in the analyser."""
from __future__ import annotations


def _an():
    import llm_bridge.analyser as a
    return a


def test_extract_pure_json(disable_auth):
    a = _an()
    assert a._extract_json('{"risk":"none"}') == {"risk": "none"}


def test_extract_with_prose(disable_auth):
    a = _an()
    s = 'Here is your verdict:\n{"risk":"low","findings":[]}\nThanks.'
    out = a._extract_json(s)
    assert out and out["risk"] == "low"


def test_extract_with_code_fence(disable_auth):
    a = _an()
    s = "```json\n{\"risk\":\"medium\"}\n```"
    out = a._extract_json(s)
    assert out and out["risk"] == "medium"


def test_sanitise_strips_binary(disable_auth):
    a = _an()
    req = "POST /a HTTP/1.1\nHost: x\n\nhello"
    resp = "HTTP/1.1 200 OK\nContent-Type: image/png\n\n\x89PNG..."
    _, s_resp = a.sanitise(req, resp)
    assert "[binary body omitted]" in s_resp


def test_sanitise_truncates(disable_auth):
    a = _an()
    long_body = "X" * 10_000
    resp = f"HTTP/1.1 200 OK\nContent-Type: text/html\n\n{long_body}"
    _, s = a.sanitise("GET / HTTP/1.1\n\n", resp)
    assert "truncated" in s
