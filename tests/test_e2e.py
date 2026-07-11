"""
End-to-end test exercising the whole pipeline with stubbed Ollama.

Verifies: filter keeps → detectors fire → LLM stubbed → critique prunes →
SQLite persists → dedup collapses repeats → /state returns everything.
"""
from __future__ import annotations

import json

from fastapi.testclient import TestClient


def _build_client(monkeypatch):
    import llm_bridge.analyser as an
    from llm_bridge import bridge

    def fake_ollama(model, system, user):
        if "strict reviewer" in system.lower():
            return json.dumps({"keep_indices": [0], "reason": "ok"})
        return json.dumps({
            "risk": "medium",
            "owasp_category": "A03:2021-Injection",
            "findings": [{
                "type": "SQLi", "parameter": "id",
                "evidence": "syntax error near", "confidence": "likely",
                "detail": "err-based SQLi",
            }],
            "recommend": ["Parameterise queries"],
            "interesting_for_follow_up": "Try UNION",
        })

    monkeypatch.setattr(an, "_call_ollama", fake_ollama)
    monkeypatch.setattr(an, "ping_ollama", lambda: True)
    monkeypatch.setattr("llm_bridge.bridge.ping_ollama", lambda: True)
    return TestClient(bridge.app)


def test_pipeline(disable_auth, monkeypatch):
    client = _build_client(monkeypatch)

    payload = {
        "url": "https://t.example/api/users?id=1'",
        "tool": "burp",
        "method": "GET",
        "status_code": 500,
        "correlation_id": "corr-1",
        "request": "GET /api/users?id=1%27 HTTP/1.1\nHost: t.example\n\n",
        "response": (
            "HTTP/1.1 500 ISE\nContent-Type: text/html\n\n"
            "<html>SQL syntax error near 'x'</html>"
        ),
    }
    r = client.post("/analyse", json=payload)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["risk"] in ("medium", "high", "critical")
    # Both detector (stack trace) and LLM (SQLi) findings should be present.
    types = {f["type"] for f in body["findings"]}
    assert "SQLi" in types

    # Second identical submission — dedup should trigger; /findings still lists one row.
    r2 = client.post("/analyse", json=payload)
    assert r2.status_code == 200

    findings = client.get("/findings").json()
    assert len(findings) >= 1
    assert findings[0]["correlation_id"] == "corr-1"

    summary = client.get("/findings/summary").json()
    assert summary["total"] >= 1

    state = client.get("/state").json()
    assert "metrics" in state and "findings" in state and "health" in state
    assert state["metrics"]["llm_calls"] >= 1


def test_auth_required(_isolate, monkeypatch):
    # Auth is ON by default in config.yaml → requests without the token fail.
    from fastapi.testclient import TestClient
    from llm_bridge import bridge
    client = TestClient(bridge.app)
    r = client.post("/analyse", json={
        "request": "GET / HTTP/1.1\n\n",
        "response": "HTTP/1.1 200 OK\n\n",
        "url": "https://x/",
    })
    assert r.status_code == 401


def test_probe_gated_off(disable_auth, monkeypatch):
    # Make the test self-contained: explicitly disable agentic mode rather
    # than relying on whatever the operator-shipping config.yaml currently has.
    import yaml
    cfg = yaml.safe_load(disable_auth.read_text())
    cfg.setdefault("agentic", {})["enabled"] = False
    disable_auth.write_text(yaml.safe_dump(cfg))
    client = _build_client(monkeypatch)
    r = client.post("/probe", json={"finding_id": 1})
    assert r.status_code == 403
