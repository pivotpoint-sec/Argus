"""LLM response cache + URL normalisation."""
from __future__ import annotations


def _cache():
    import llm_bridge.cache as c
    return c


def test_url_normalisation_collapses_ids(disable_auth):
    c = _cache()
    assert c.normalise_url("https://x/api/users/12345") == "https://x/api/users/{N}"
    assert c.normalise_url("https://x/api/o/123e4567-e89b-12d3-a456-426614174000") \
        == "https://x/api/o/{UUID}"
    assert c.normalise_url("https://x/api/u/2") == "https://x/api/u/{N}"


def test_keys_collide_for_sibling_requests(disable_auth):
    c = _cache()
    k1 = c.make_key(model="m", system_prompt="s",
                    user_prompt="GET /users/1", url="https://x/users/1")
    k2 = c.make_key(model="m", system_prompt="s",
                    user_prompt="GET /users/9999", url="https://x/users/9999")
    assert k1 == k2


def test_cache_roundtrip(disable_auth):
    c = _cache()
    k = c.make_key(model="m", system_prompt="sys",
                   user_prompt="hello", url="https://x/")
    assert c.get(k) is None
    c.put(key=k, model="m", url="https://x/", result={"risk": "low", "findings": []})
    cached = c.get(k)
    assert cached and cached["risk"] == "low"
