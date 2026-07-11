"""Pre-filter heuristics."""
from __future__ import annotations

import pytest


def _filter():
    import llm_bridge.filter as f
    return f


@pytest.mark.parametrize("url, expect", [
    ("https://x/assets/app.js", False),
    ("https://x/img/logo.png", False),
    ("https://x/fonts/regular.woff2", False),
    ("https://x/health", False),
    ("https://x/api/v1/users", True),
    ("https://x/login", True),
    ("https://x/admin/dashboard", True),
])
def test_url_shape(disable_auth, url, expect):
    f = _filter()
    resp = "HTTP/1.1 200 OK\nContent-Type: text/html\n\n<html></html>"
    assert f.is_interesting("GET / HTTP/1.1\nHost: x\n\n", resp, url) is expect


def test_interesting_query_param_kept(disable_auth):
    f = _filter()
    resp = "HTTP/1.1 200 OK\nContent-Type: text/html\n\n"
    assert f.is_interesting(
        "GET /search?token=abc HTTP/1.1\nHost: x\n\n", resp,
        "https://x/search?token=abc",
    ) is True


def test_oversized_response_dropped(disable_auth):
    f = _filter()
    big_body = "A" * 200_000
    resp = f"HTTP/1.1 200 OK\nContent-Type: text/html\nContent-Length: {len(big_body)}\n\n{big_body}"
    assert f.is_interesting("GET /api/x HTTP/1.1\nHost: x\n\n", resp,
                            "https://x/api/x") is False


def test_error_status_kept(disable_auth):
    f = _filter()
    assert f.is_interesting(
        "GET /random HTTP/1.1\nHost: x\n\n",
        "HTTP/1.1 500 ISE\nContent-Type: text/html\n\nboom",
        "https://x/random",
    ) is True


def test_set_cookie_kept(disable_auth):
    f = _filter()
    assert f.is_interesting(
        "GET /random HTTP/1.1\nHost: x\n\n",
        "HTTP/1.1 200 OK\nSet-Cookie: sid=abc\n\n",
        "https://x/random",
    ) is True
