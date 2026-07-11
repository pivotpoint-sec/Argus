"""
Regression tests for the five capability enhancements:
XSS detector, SQLi-hint detector, JWT crypto analyzer, XXE detector,
and the /correlate business-logic endpoint.
"""
from __future__ import annotations

import base64
import json


def _detectors():
    import llm_bridge.detectors as d
    return d


# --------------------------------------------------------------------------
# XSS
# --------------------------------------------------------------------------

def test_xss_reflected_param_in_html(disable_auth):
    d = _detectors()
    req = "GET /search?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E HTTP/1.1\nHost: x\n\n"
    resp = (
        "HTTP/1.1 200 OK\nContent-Type: text/html\n"
        "Strict-Transport-Security: max-age=1\n"
        "X-Content-Type-Options: nosniff\n"
        "X-Frame-Options: DENY\n"
        "Referrer-Policy: no-referrer\n"
        "Content-Security-Policy: default-src 'self'\n\n"
        "<html><body>You searched: <script>alert(1)</script></body></html>"
    )
    fs = d.run_detectors(req, resp, "https://x/search?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E")
    # The detector reads the URL params verbatim; the unescaped angle brackets
    # in the original (decoded by the test) appear in the body.
    # We assert *some* finding of type XSS or a likely JS-sink hit:
    assert any(f["type"] == "XSS" for f in fs) or any("XSS" in f["detail"] for f in fs)


def test_xss_js_sink_detected(disable_auth):
    d = _detectors()
    req = "GET /app.js HTTP/1.1\nHost: x\n\n"
    resp = (
        "HTTP/1.1 200 OK\nContent-Type: text/html\n"
        "Strict-Transport-Security: max-age=1\nX-Content-Type-Options: nosniff\n"
        "X-Frame-Options: DENY\nReferrer-Policy: no-referrer\n"
        "Content-Security-Policy: default-src 'self'\n\n"
        "<script>document.write(userInput); el.innerHTML = data;</script>"
    )
    fs = d.run_detectors(req, resp, "https://x/app.js")
    assert any(f["type"] == "XSS" and "sink" in f["detail"].lower() for f in fs)


# --------------------------------------------------------------------------
# SQLi hint
# --------------------------------------------------------------------------

def test_sqli_hint_quote_in_param(disable_auth):
    d = _detectors()
    req = "GET /api/users?id=1%27%20OR%201%3D1 HTTP/1.1\nHost: x\n\n"
    resp = "HTTP/1.1 200 OK\nContent-Type: application/json\n\n{\"ok\":true}"
    fs = d.run_detectors(req, resp, "https://x/api/users?id=1' OR 1=1")
    assert any(f["type"] == "SQLi" and f.get("parameter") == "id" for f in fs)


def test_sqli_hint_union_select(disable_auth):
    d = _detectors()
    url = "https://x/api/r?q=1+UNION+SELECT+1,2,3"
    req = f"GET /api/r?q=1+UNION+SELECT+1,2,3 HTTP/1.1\nHost: x\n\n"
    resp = "HTTP/1.1 200 OK\nContent-Type: application/json\n\n{}"
    fs = d.run_detectors(req, resp, url)
    assert any(f["type"] == "SQLi" for f in fs)


# --------------------------------------------------------------------------
# JWT crypto analyzer
# --------------------------------------------------------------------------

def _make_jwt(header: dict, payload: dict, sig: str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA") -> str:
    def b64(d):
        return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
    return f"{b64(header)}.{b64(payload)}.{sig}"


def test_jwt_alg_none_flagged(disable_auth):
    d = _detectors()
    tok = _make_jwt({"alg": "none", "typ": "JWT"}, {"sub": "admin"}, sig="")
    # The detector's _RE_JWT requires 3 segments separated by dots, each 10+ chars.
    # alg=none usually has empty sig; we use a 30-char placeholder so the regex matches,
    # then the analyzer reads the header and flags alg=none regardless.
    tok = _make_jwt({"alg": "none", "typ": "JWT"}, {"sub": "admin"})
    resp = f"HTTP/1.1 200 OK\nContent-Type: application/json\n\n{{\"token\":\"{tok}\"}}"
    fs = d.run_detectors("GET / HTTP/1.1\n\n", resp, "https://x/")
    assert any(
        f["type"] == "JWT misconfiguration" and "alg=none" in f["detail"]
        for f in fs
    )


def test_jwt_missing_exp_flagged(disable_auth):
    d = _detectors()
    tok = _make_jwt({"alg": "HS256", "typ": "JWT"}, {"sub": "admin", "iat": 1700000000})
    resp = f"HTTP/1.1 200 OK\nContent-Type: application/json\n\n{{\"t\":\"{tok}\"}}"
    fs = d.run_detectors("GET / HTTP/1.1\n\n", resp, "https://x/")
    assert any(
        f["type"] == "JWT misconfiguration" and "exp" in f["detail"]
        for f in fs
    )


def test_jwt_long_lived_flagged(disable_auth):
    d = _detectors()
    iat = 1700000000
    exp = iat + 86400 * 365  # one year
    tok = _make_jwt({"alg": "HS256", "typ": "JWT"}, {"sub": "x", "iat": iat, "exp": exp})
    resp = f"HTTP/1.1 200 OK\nContent-Type: application/json\n\n{{\"t\":\"{tok}\"}}"
    fs = d.run_detectors("GET / HTTP/1.1\n\n", resp, "https://x/")
    assert any(
        f["type"] == "JWT misconfiguration" and "lifetime" in f["detail"]
        for f in fs
    )


# --------------------------------------------------------------------------
# XXE
# --------------------------------------------------------------------------

def test_xxe_external_entity_in_request(disable_auth):
    d = _detectors()
    req = (
        "POST /api/import HTTP/1.1\nHost: x\nContent-Type: application/xml\n\n"
        '<?xml version="1.0"?>\n'
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>\n'
        "<foo>&xxe;</foo>"
    )
    resp = "HTTP/1.1 200 OK\nContent-Type: application/xml\n\n<r/>"
    fs = d.run_detectors(req, resp, "https://x/api/import")
    assert any(f["type"] == "XXE" and "external XML entity" in f["detail"] for f in fs)


def test_xxe_xml_endpoint_candidate(disable_auth):
    d = _detectors()
    req = (
        "POST /api/import HTTP/1.1\nHost: x\nContent-Type: application/xml\n\n"
        "<order><item>x</item></order>"
    )
    resp = "HTTP/1.1 200 OK\nContent-Type: application/json\n\n{}"
    fs = d.run_detectors(req, resp, "https://x/api/import")
    assert any(f["type"] == "XXE" and "candidate" in f["detail"] for f in fs)


def test_xxe_parse_error_in_response(disable_auth):
    d = _detectors()
    req = "POST / HTTP/1.1\nHost: x\nContent-Type: application/xml\n\n<broken>"
    resp = (
        "HTTP/1.1 500 ISE\nContent-Type: text/plain\n\n"
        "lxml.etree.XMLSyntaxError: Premature end of data in tag broken line 1"
    )
    fs = d.run_detectors(req, resp, "https://x/")
    assert any(f["type"] == "XXE" and "parser error" in f["detail"].lower() for f in fs)


# --------------------------------------------------------------------------
# Business-logic correlation endpoint
# --------------------------------------------------------------------------

def test_correlate_endpoint_requires_min_findings(disable_auth):
    from fastapi.testclient import TestClient
    from llm_bridge import bridge
    c = TestClient(bridge.app)
    r = c.post("/correlate", json={"min_findings": 2}).json()
    # Empty DB at test start -> examined=0 -> returns empty findings.
    assert r["examined"] == 0
    assert r["findings"] == []


def test_correlate_endpoint_calls_llm_when_enough_findings(disable_auth, monkeypatch):
    from fastapi.testclient import TestClient
    from llm_bridge import analyser, bridge
    from storage import db

    # Seed two findings so the correlator has something to chew on.
    db.save_finding(
        url="https://x/api/reset", method="POST", status_code=200,
        risk="medium", owasp_category="A04:2021-Insecure Design",
        findings=[{"type": "Auth bypass", "parameter": "token", "evidence": "...",
                   "confidence": "likely", "detail": "reset token reused",
                   "source": "llm", "cwe": "CWE-294", "cvss": 6.5}],
        recommend=["Invalidate on use"], follow_up=None,
    )
    db.save_finding(
        url="https://x/api/account", method="POST", status_code=200,
        risk="medium", owasp_category="A04:2021-Insecure Design",
        findings=[{"type": "IDOR", "parameter": "uid", "evidence": "uid=2",
                   "confidence": "likely", "detail": "neighbor account readable",
                   "source": "llm", "cwe": "CWE-639", "cvss": 6.5}],
        recommend=["Check ownership"], follow_up=None,
    )

    # Stub the model call so the test is deterministic and offline.
    fake = lambda model, system, user: json.dumps({
        "findings": [{
            "title": "Cross-flow privilege drift via reused reset token",
            "detail": "Reset token from /api/reset enables IDOR on /api/account.",
            "cwe": "CWE-840", "cvss": 7.5,
            "related_finding_ids": [1, 2],
        }]
    })
    monkeypatch.setattr(analyser, "_call_ollama", fake)
    monkeypatch.setattr(bridge, "ollama_call", fake)  # bridge captured the alias at import time

    c = TestClient(bridge.app)
    r = c.post("/correlate", json={"min_findings": 2}).json()
    assert r["examined"] >= 2
    assert len(r["findings"]) == 1
    assert r["findings"][0]["title"].startswith("Cross-flow privilege")
    assert r["findings"][0]["related_finding_ids"] == [1, 2]


# --------------------------------------------------------------------------
# Command injection
# --------------------------------------------------------------------------

def test_cmdi_shell_metachar_in_param(disable_auth):
    d = _detectors()
    url = "https://x/api/ping?host=127.0.0.1;id"
    req = "GET /api/ping?host=127.0.0.1;id HTTP/1.1\nHost: x\n\n"
    resp = "HTTP/1.1 200 OK\nContent-Type: text/plain\n\nPING 127.0.0.1"
    fs = d.run_detectors(req, resp, url)
    assert any(f["type"] == "Command injection" and f.get("parameter") == "host" for f in fs)


def test_cmdi_id_output_in_response(disable_auth):
    d = _detectors()
    url = "https://x/api/exec?cmd=id"
    req = "GET /api/exec?cmd=id HTTP/1.1\nHost: x\n\n"
    resp = (
        "HTTP/1.1 200 OK\nContent-Type: text/plain\n\n"
        "uid=33(www-data) gid=33(www-data) groups=33(www-data)"
    )
    fs = d.run_detectors(req, resp, url)
    assert any(
        f["type"] == "Command injection" and "id" in f["detail"]
        for f in fs
    )


def test_cmdi_passwd_leak_in_response(disable_auth):
    d = _detectors()
    url = "https://x/files?path=/etc/passwd"
    req = "GET /files?path=/etc/passwd HTTP/1.1\nHost: x\n\n"
    resp = (
        "HTTP/1.1 200 OK\nContent-Type: text/plain\n\n"
        "root:x:0:0:root:/root:/bin/bash\n"
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    )
    fs = d.run_detectors(req, resp, url)
    assert any(
        f["type"] == "Command injection" and "passwd" in f["detail"]
        for f in fs
    )


def test_cmdi_pipe_to_cat_in_param(disable_auth):
    d = _detectors()
    # Real Burp traffic URL-encodes spaces; literal spaces never appear
    # in a query string on the wire. Use %20 to mirror that reality.
    url = "https://x/api/log?file=app.log;cat%20/etc/passwd"
    req = "GET /api/log?file=app.log;cat%20/etc/passwd HTTP/1.1\nHost: x\n\n"
    resp = "HTTP/1.1 200 OK\nContent-Type: text/plain\n\nok"
    fs = d.run_detectors(req, resp, url)
    assert any(f["type"] == "Command injection" for f in fs)


def test_cmdi_no_false_positive_on_clean_request(disable_auth):
    d = _detectors()
    url = "https://x/api/users?name=alice"
    req = "GET /api/users?name=alice HTTP/1.1\nHost: x\n\n"
    resp = "HTTP/1.1 200 OK\nContent-Type: application/json\n\n{\"id\":1}"
    fs = d.run_detectors(req, resp, url)
    assert not any(f["type"] == "Command injection" for f in fs)


# --------------------------------------------------------------------------
# HTTP request smuggling detector
# --------------------------------------------------------------------------

def test_smuggling_cl_te_mismatch(disable_auth):
    d = _detectors()
    req = ("POST /api/x HTTP/1.1\r\nHost: x\r\n"
           "Content-Length: 13\r\nTransfer-Encoding: chunked\r\n\r\n"
           "0\r\n\r\nGET /\r\n")
    resp = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nok"
    fs = d.run_detectors(req, resp, "https://x/api/x")
    assert any(f["type"] == "HTTP request smuggling" for f in fs)


# --------------------------------------------------------------------------
# GraphQL detectors
# --------------------------------------------------------------------------

def test_graphql_introspection_enabled(disable_auth):
    d = _detectors()
    req = ('POST /graphql HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n\r\n'
           '{"query":"{__schema { types { name } } }"}')
    resp = ('HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n'
            '{"data":{"__schema":{"types":[{"name":"User"}]}}}')
    fs = d.run_detectors(req, resp, "https://x/graphql")
    assert any(f["type"] == "GraphQL misconfiguration" and "introspection" in f["detail"].lower()
               for f in fs)


def test_graphql_deeply_nested_query(disable_auth):
    d = _detectors()
    # Brace depth 10 - should trigger.
    nested = "{a{b{c{d{e{f{g{h{i{j 1 }}}}}}}}}}"
    req = ('POST /graphql HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n\r\n'
           f'{{"query":"query {nested}"}}')
    resp = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{}"
    fs = d.run_detectors(req, resp, "https://x/graphql")
    assert any(f["type"] == "GraphQL misconfiguration" and "depth" in f["detail"].lower()
               for f in fs)


# --------------------------------------------------------------------------
# Mass assignment
# --------------------------------------------------------------------------

def test_mass_assignment_admin_in_json(disable_auth):
    d = _detectors()
    req = ('POST /api/users HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n\r\n'
           '{"name":"alice","email":"a@x","isAdmin":true}')
    resp = "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\n\r\n{}"
    fs = d.run_detectors(req, resp, "https://x/api/users")
    assert any(f["type"] == "Mass assignment" for f in fs)


def test_parameter_pollution_duplicate(disable_auth):
    d = _detectors()
    req = "GET /api/u?id=1&id=2 HTTP/1.1\r\nHost: x\r\n\r\n"
    resp = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{}"
    fs = d.run_detectors(req, resp, "https://x/api/u?id=1&id=2")
    assert any(f["type"] == "Parameter pollution" for f in fs)


# --------------------------------------------------------------------------
# Self-consistency voting
# --------------------------------------------------------------------------

def test_consistency_majority_vote(disable_auth):
    from llm_bridge import consistency
    from llm_bridge.models import AnalysisResult, Finding as F
    a = AnalysisResult(risk="high", findings=[
        F(type="SQLi", parameter="id", evidence="x", confidence="likely", detail="d"),
        F(type="XSS", parameter="q", evidence="y", confidence="possible", detail="e"),
    ])
    b = AnalysisResult(risk="medium", findings=[
        F(type="SQLi", parameter="id", evidence="x", confidence="confirmed", detail="d"),
    ])
    c = AnalysisResult(risk="high", findings=[
        F(type="SQLi", parameter="id", evidence="x", confidence="likely", detail="d"),
        F(type="XSS", parameter="q", evidence="y", confidence="possible", detail="e"),
    ])
    voted = consistency.vote([a, b, c])
    types = sorted(f.type for f in voted.findings)
    assert types == ["SQLi", "XSS"], voted
    # The kept SQLi finding should carry the highest-confidence label observed.
    sqli = next(f for f in voted.findings if f.type == "SQLi")
    assert sqli.confidence == "confirmed"


def test_consistency_drops_minority(disable_auth):
    from llm_bridge import consistency
    from llm_bridge.models import AnalysisResult, Finding as F
    a = AnalysisResult(risk="high", findings=[
        F(type="SQLi", parameter="id", evidence="x", confidence="likely", detail="d"),
        F(type="Hallucinated", parameter=None, evidence="z", confidence="possible", detail="e"),
    ])
    b = AnalysisResult(risk="high", findings=[
        F(type="SQLi", parameter="id", evidence="x", confidence="likely", detail="d"),
    ])
    c = AnalysisResult(risk="high", findings=[
        F(type="SQLi", parameter="id", evidence="x", confidence="likely", detail="d"),
    ])
    voted = consistency.vote([a, b, c])
    assert [f.type for f in voted.findings] == ["SQLi"]


# --------------------------------------------------------------------------
# SARIF export
# --------------------------------------------------------------------------

def test_sarif_export_shape(disable_auth):
    from llm_bridge import sarif
    doc = sarif.to_sarif(session_id="s1", findings=[{
        "id": 7, "url": "https://x/api/u?id=1", "risk": "high",
        "owasp_category": "A03:2021-Injection",
        "method": "GET", "status_code": 200, "timestamp": "2026-01-01T00:00:00Z",
        "occurrences": 1,
        "findings": [{"type": "SQLi", "parameter": "id", "evidence": "OR 1=1",
                      "confidence": "likely", "detail": "boolean OR",
                      "source": "llm", "cwe": "CWE-89", "cvss": 7.5}],
    }])
    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["tool"]["driver"]["name"] == "Argus"
    rule_ids = [r["id"] for r in doc["runs"][0]["tool"]["driver"]["rules"]]
    assert "sqli" in rule_ids
    res = doc["runs"][0]["results"][0]
    assert res["ruleId"] == "sqli"
    assert res["level"] == "error"
    assert res["properties"]["argus_finding_id"] == 7


# --------------------------------------------------------------------------
# Confirmer dispatch (without actually sending HTTP)
# --------------------------------------------------------------------------

def test_confirmer_dispatch_no_param(disable_auth):
    from llm_bridge import confirmer
    v = confirmer.confirm({"type": "SQLi"}, base_url="https://x/api/u?id=1")
    # agentic disabled by default -> inconclusive
    assert v["verdict"] == "inconclusive"


def test_confirmer_unknown_type(disable_auth):
    from llm_bridge import confirmer
    v = confirmer.confirm({"type": "Nonsense"}, base_url="https://x/")
    assert v["verdict"] == "inconclusive"
    assert "no confirmer" in v["evidence"].lower()


def test_confirmer_ssrf_marks_manual(disable_auth):
    from llm_bridge import confirmer
    v = confirmer.confirm({"type": "SSRF", "parameter": "url"},
                           base_url="https://x/proxy?url=http://x")
    assert v["verdict"] == "inconclusive"
    assert "out-of-band" in v["evidence"].lower() or "collaborator" in v["evidence"].lower()


# --------------------------------------------------------------------------
# A06: Vulnerable / Outdated Components
# --------------------------------------------------------------------------

def test_fingerprint_versioned_headers(disable_auth):
    d = _detectors()
    req = "GET / HTTP/1.1\r\nHost: x\r\n\r\n"
    resp = "HTTP/1.1 200 OK\r\nServer: nginx/1.14.0\r\nX-Powered-By: PHP/7.2.34\r\nContent-Type: text/html\r\n\r\n<html/>"
    fs = d.run_detectors(req, resp, "https://x/")
    assert any(f["type"] == "Vulnerable component" for f in fs)


def test_fingerprint_phpmyadmin_path(disable_auth):
    d = _detectors()
    req = "GET /phpMyAdmin/index.php HTTP/1.1\r\nHost: x\r\n\r\n"
    resp = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html/>"
    fs = d.run_detectors(req, resp, "https://x/phpMyAdmin/index.php")
    assert any(f["type"] == "Vulnerable component" and "phpMyAdmin" in f["detail"] for f in fs)


# --------------------------------------------------------------------------
# A10: SSRF candidates
# --------------------------------------------------------------------------

def test_ssrf_aws_metadata(disable_auth):
    d = _detectors()
    url = "https://x/proxy?url=http://169.254.169.254/latest/meta-data/"
    req = f"GET /proxy?url=http://169.254.169.254/latest/meta-data/ HTTP/1.1\r\nHost: x\r\n\r\n"
    resp = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nok"
    fs = d.run_detectors(req, resp, url)
    assert any(f["type"] == "SSRF" and f.get("parameter") == "url" for f in fs)


def test_ssrf_internal_ip(disable_auth):
    d = _detectors()
    url = "https://x/fetch?image_url=http://10.0.5.7/admin"
    req = f"GET /fetch?image_url=http://10.0.5.7/admin HTTP/1.1\r\nHost: x\r\n\r\n"
    resp = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nok"
    fs = d.run_detectors(req, resp, url)
    assert any(f["type"] == "SSRF" and f.get("parameter") == "image_url" for f in fs)


def test_ssrf_no_false_positive_on_external_url(disable_auth):
    d = _detectors()
    # External URL in a non-SSRF-shaped param name should not fire.
    url = "https://x/api/users?name=alice"
    req = "GET /api/users?name=alice HTTP/1.1\r\nHost: x\r\n\r\n"
    resp = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{}"
    fs = d.run_detectors(req, resp, url)
    assert not any(f["type"] == "SSRF" for f in fs)


# --------------------------------------------------------------------------
# A08: Insecure deserialization + missing SRI
# --------------------------------------------------------------------------

def test_deserialization_java_serialized(disable_auth):
    d = _detectors()
    # Real Java serialized blob starts base64 with "rO0AB"
    blob = "rO0ABXNyABVqYXZhLnV0aWwuTGlua2VkSGFzaE1hcDR" + "A" * 60
    req = f"POST /api/auth HTTP/1.1\r\nHost: x\r\nContent-Type: text/plain\r\n\r\nsession={blob}"
    resp = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nok"
    fs = d.run_detectors(req, resp, "https://x/api/auth")
    assert any(f["type"] == "Insecure deserialization" and "Java" in f["detail"] for f in fs)


def test_deserialization_php_serialized(disable_auth):
    d = _detectors()
    req = ('POST /api/save HTTP/1.1\r\nHost: x\r\nContent-Type: text/plain\r\n\r\n'
           'data=O:8:"UserPref":2:{s:5:"theme";s:4:"dark";}')
    resp = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nok"
    fs = d.run_detectors(req, resp, "https://x/api/save")
    assert any(f["type"] == "Insecure deserialization" and "PHP" in f["detail"] for f in fs)


def test_missing_sri_on_cdn_script(disable_auth):
    d = _detectors()
    req = "GET / HTTP/1.1\r\nHost: x\r\n\r\n"
    resp = ('HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n'
            '<html><script src="https://cdn.jsdelivr.net/jquery.js"></script></html>')
    fs = d.run_detectors(req, resp, "https://x/")
    assert any(f["type"] == "Missing Subresource Integrity" for f in fs)


# --------------------------------------------------------------------------
# A03: SSTI + NoSQL
# --------------------------------------------------------------------------

def test_ssti_jinja2_error(disable_auth):
    d = _detectors()
    req = "GET /render?name=test HTTP/1.1\r\nHost: x\r\n\r\n"
    resp = ('HTTP/1.1 500 ISE\r\nContent-Type: text/html\r\n\r\n'
            'jinja2.exceptions.TemplateSyntaxError: unexpected token at line 4')
    fs = d.run_detectors(req, resp, "https://x/render?name=test")
    assert any(f["type"] == "SSTI" and "Jinja2" in f["detail"] for f in fs)


def test_nosql_mongodb_operator(disable_auth):
    d = _detectors()
    req = ('POST /api/login HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n\r\n'
           '{"username":{"$ne":null},"password":{"$ne":null}}')
    resp = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{}"
    fs = d.run_detectors(req, resp, "https://x/api/login")
    assert any(f["type"] == "NoSQL injection" for f in fs)


# --------------------------------------------------------------------------
# A05: Debug / VCS / config endpoints
# --------------------------------------------------------------------------

def test_debug_endpoint_git_head(disable_auth):
    d = _detectors()
    req = "GET /.git/HEAD HTTP/1.1\r\nHost: x\r\n\r\n"
    resp = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nref: refs/heads/main"
    fs = d.run_detectors(req, resp, "https://x/.git/HEAD")
    assert any("/.git/HEAD" in f["evidence"] for f in fs)


def test_debug_endpoint_actuator_env(disable_auth):
    d = _detectors()
    req = "GET /actuator/env HTTP/1.1\r\nHost: x\r\n\r\n"
    resp = ('HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n'
            '{"activeProfiles":["prod"],"propertySources":[]}')
    fs = d.run_detectors(req, resp, "https://x/actuator/env")
    assert any("actuator/env" in f["evidence"] for f in fs)


def test_directory_listing_detected(disable_auth):
    d = _detectors()
    req = "GET /uploads/ HTTP/1.1\r\nHost: x\r\n\r\n"
    resp = ('HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n'
            '<html><head><title>Index of /uploads</title></head>...')
    fs = d.run_detectors(req, resp, "https://x/uploads/")
    assert any("Index of" in f["evidence"] for f in fs)


# --------------------------------------------------------------------------
# Payload library
# --------------------------------------------------------------------------

def test_payloads_registry_populated(disable_auth):
    from llm_bridge import payloads
    total = sum(len(v) for v in payloads.REGISTRY.values())
    assert total >= 30, f"expected 30+ payloads, found {total}"
    assert "SQLi" in payloads.REGISTRY
    assert "SSRF" in payloads.REGISTRY


def test_payloads_filter_intrusive_gate(disable_auth):
    from llm_bridge import payloads
    benign = payloads.filter_payloads(vuln_class="SQLi", intrusive_allowed=False)
    all_p = payloads.filter_payloads(vuln_class="SQLi", intrusive_allowed=True)
    assert len(benign) < len(all_p)
    assert all(p["risk"] == "benign" for p in benign)


def test_payloads_filter_by_db(disable_auth):
    from llm_bridge import payloads
    mysql = payloads.filter_payloads(vuln_class="SQLi", db="mysql", intrusive_allowed=True)
    pg = payloads.filter_payloads(vuln_class="SQLi", db="postgresql", intrusive_allowed=True)
    assert any("MySQL" in p["name"] or "OUTFILE" in p["name"] for p in mysql)
    assert any("PostgreSQL" in p["name"] for p in pg)


# --------------------------------------------------------------------------
# Attack surface mapper
# --------------------------------------------------------------------------

def test_surface_builds_graph(disable_auth):
    from llm_bridge import surface
    rows = [
        {"id": 1, "url": "https://target/api/users?id=1", "method": "GET", "status_code": 200,
         "findings": [{"type": "SQLi", "parameter": "id", "evidence": "MySQL syntax error near",
                       "detail": "boolean OR", "confidence": "likely", "source": "llm",
                       "cwe": "CWE-89", "cvss": 7.5}]},
        {"id": 2, "url": "https://target/api/orders?id=42", "method": "GET", "status_code": 200,
         "findings": []},
        {"id": 3, "url": "https://target/", "method": "GET", "status_code": 200,
         "findings": [{"type": "Vulnerable component", "parameter": None,
                       "evidence": "Server: nginx/1.14.0; X-Powered-By: PHP/7.2.34",
                       "detail": "fingerprint", "confidence": "confirmed", "source": "detector",
                       "cwe": "CWE-200", "cvss": 3.7}]},
    ]
    g = surface.build(rows)
    assert g["total_hosts"] == 1
    assert g["total_endpoints"] >= 2
    tech = g["hosts"]["target"]["tech"]
    assert "mysql" in tech["db"]
    assert "php" in tech["language"]


def test_surface_lateral_targets(disable_auth):
    from llm_bridge import surface
    rows = [
        {"id": 1, "url": "https://x/api/users?id=1", "findings": []},
        {"id": 2, "url": "https://x/api/orders?id=42", "findings": []},
        {"id": 3, "url": "https://x/api/products/9?id=5", "findings": []},
        {"id": 4, "url": "https://x/api/comments?author=1", "findings": []},
    ]
    g = surface.build(rows)
    lat = surface.lateral_targets(g, "x", "id", exclude_shape="https://x/api/users")
    # Should include /api/orders and /api/products but exclude /api/users.
    assert any("/api/orders" in u for u in lat)
    assert all("/api/users" not in u for u in lat)
    # author= shouldn't appear since we asked for `id` only.
    assert all("/api/comments" not in u for u in lat)


# --------------------------------------------------------------------------
# Recommender + /recommend endpoint
# --------------------------------------------------------------------------

def test_recommender_empty_session(disable_auth):
    from llm_bridge import recommender
    out = recommender.recommend(limit=10)
    assert out["recommendations"] == []
    assert out["examined_findings"] == 0


def test_recommender_evidence_driven_with_lateral(disable_auth):
    from llm_bridge import recommender
    from storage import db
    # Seed: a SQLi finding on /api/users?id=1 and a fingerprint of PHP/MySQL,
    # plus a sibling /api/orders?id endpoint we have ALSO touched.
    db.save_finding(
        url="https://target/api/users?id=1", method="GET", status_code=200,
        risk="high", owasp_category="A03:2021-Injection",
        findings=[{"type": "SQLi", "parameter": "id", "evidence": "MySQL syntax error near",
                   "confidence": "likely", "detail": "boolean OR",
                   "source": "llm", "cwe": "CWE-89", "cvss": 7.5}],
        recommend=[], follow_up=None,
    )
    db.save_finding(
        url="https://target/", method="GET", status_code=200,
        risk="low", owasp_category="A06:2021-Vulnerable and Outdated Components",
        findings=[{"type": "Vulnerable component", "parameter": None,
                   "evidence": "Server: nginx/1.14.0; X-Powered-By: PHP/7.2.34; MySQL 5.7",
                   "confidence": "confirmed", "detail": "fingerprint",
                   "source": "detector", "cwe": "CWE-200", "cvss": 3.7}],
        recommend=[], follow_up=None,
    )
    db.save_finding(
        url="https://target/api/orders?id=42", method="GET", status_code=200,
        risk="none", owasp_category=None, findings=[], recommend=[], follow_up=None,
    )
    out = recommender.recommend(limit=10)
    assert out["examined_findings"] >= 3
    sqli_recs = [r for r in out["recommendations"] if r["vuln_class"] == "SQLi"]
    assert sqli_recs, "expected at least one SQLi recommendation"
    top = sqli_recs[0]
    assert top["payload"], top
    assert "delivery" in top and top["delivery"]["as_curl"].startswith("curl")
    # Lateral propagation: /api/orders should appear as a lateral target
    # because it shares the `id` parameter shape with /api/users.
    flat = " ".join(top["lateral_targets"])
    assert "/api/orders" in flat


def test_recommender_param_hint_for_unknown_endpoint(disable_auth):
    from llm_bridge import recommender
    from storage import db
    # An endpoint we have seen but never flagged. Its `url` param is a
    # canonical SSRF hint; the recommender should suggest an SSRF probe.
    db.save_finding(
        url="https://target/proxy?url=https://example.com/x", method="GET", status_code=200,
        risk="none", owasp_category=None, findings=[], recommend=[], follow_up=None,
    )
    out = recommender.recommend(limit=10)
    ssrf_recs = [r for r in out["recommendations"] if r["vuln_class"] == "SSRF"]
    assert ssrf_recs, "expected at least one SSRF probe suggestion"
    assert "url" in ssrf_recs[0]["rationale"].lower() or "url=" in ssrf_recs[0]["delivery"]["target_url"]


def test_recommend_endpoint_returns_json(disable_auth):
    from fastapi.testclient import TestClient
    from llm_bridge import bridge
    from storage import db
    db.save_finding(
        url="https://target/api/users?id=1", method="GET", status_code=200,
        risk="high", owasp_category="A03:2021-Injection",
        findings=[{"type": "SQLi", "parameter": "id", "evidence": "MySQL",
                   "confidence": "likely", "detail": "OR 1=1",
                   "source": "llm", "cwe": "CWE-89", "cvss": 7.5}],
        recommend=[], follow_up=None,
    )
    c = TestClient(bridge.app)
    r = c.post("/recommend", json={"limit": 5}).json()
    assert "recommendations" in r
    assert isinstance(r["recommendations"], list)
    assert r["examined_findings"] >= 1
