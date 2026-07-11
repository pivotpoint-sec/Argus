"""
Deterministic detector tier — fast regex/heuristic checks that run BEFORE
the LLM and persist regardless of what the LLM says.

Security intent: catches the boring-but-important findings (missing security
headers, leaked cloud keys, JWTs in responses, stack-trace info leaks) at
microsecond cost. Cutting the false-negative rate on these patterns also
frees the LLM to spend its budget on reasoning-heavy findings.

Every detector returns plain dicts matching the `Finding` schema with
`source = "detector"` so the downstream pipeline treats them identically to
LLM findings.
"""
from __future__ import annotations

import re
from typing import Optional
from urllib.parse import urlparse

from .config import configure_logging, load_config
from . import owasp_extras as _extras

_log = configure_logging()


# ---------------------------------------------------------------------------
# Regex tables — module-level so they compile once.
# ---------------------------------------------------------------------------

_RE_STATUS = re.compile(r"^HTTP/\d(?:\.\d)?\s+(\d{3})", re.MULTILINE)
_RE_HEADER = lambda name: re.compile(
    rf"^{re.escape(name)}\s*:\s*([^\r\n]+)$", re.IGNORECASE | re.MULTILINE
)

# JWT: three base64url segments separated by dots. We keep the pattern
# conservative to avoid matching arbitrary dotted strings.
_RE_JWT = re.compile(
    r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"
)

_CLOUD_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str], str], ...] = (
    ("AWS access key id",      re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),          "CWE-798"),
    ("AWS secret access key",  re.compile(r"\baws_secret_access_key\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{40}['\"]?", re.IGNORECASE), "CWE-798"),
    ("Google API key",         re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),           "CWE-798"),
    ("Stripe live key",        re.compile(r"\bsk_live_[0-9a-zA-Z]{24,}\b"),          "CWE-798"),
    ("Stripe test key",        re.compile(r"\bsk_test_[0-9a-zA-Z]{24,}\b"),          "CWE-798"),
    ("Slack token",            re.compile(r"\bxox[abpr]-[0-9A-Za-z\-]{10,}\b"),      "CWE-798"),
    ("GitHub token",           re.compile(r"\bghp_[0-9A-Za-z]{36}\b"),               "CWE-798"),
    ("GitHub fine-grained",    re.compile(r"\bgithub_pat_[0-9A-Za-z_]{70,}\b"),      "CWE-798"),
    ("Twilio SID",             re.compile(r"\bAC[a-f0-9]{32}\b"),                    "CWE-798"),
    ("SendGrid key",           re.compile(r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b"), "CWE-798"),
    ("Private key block",      re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |)PRIVATE KEY-----"), "CWE-321"),
)

_STACK_TRACE_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("SQL error (generic)",    re.compile(r"(SQL syntax|unterminated quoted string|ORA-\d{5}|PG::|psycopg2\.errors|SQLSTATE\[)", re.IGNORECASE)),
    ("MySQL error",            re.compile(r"(You have an error in your SQL syntax|Warning: mysql_)", re.IGNORECASE)),
    ("ORM leak (Django)",      re.compile(r"Traceback \(most recent call last\):[\s\S]{0,400}django\.", re.IGNORECASE)),
    ("ORM leak (SQLAlchemy)",  re.compile(r"sqlalchemy\.exc\.[A-Za-z]+", re.IGNORECASE)),
    ("Java stack trace",       re.compile(r"at\s+[a-zA-Z_][\w.$]+\.[a-zA-Z_]\w*\([A-Za-z0-9_.$]+:\d+\)")),
    ("PHP error",              re.compile(r"(Fatal error|Warning|Parse error):[\s\S]{0,80}on line \d+", re.IGNORECASE)),
    ("Rails error",            re.compile(r"ActionController::[A-Za-z]+|ActiveRecord::[A-Za-z]+")),
    ("Node stack",             re.compile(r"at\s+\S+\s+\(?[^\s]+\.js:\d+:\d+")),
)

_SECURITY_HEADERS = (
    ("Strict-Transport-Security", "high",   "CWE-319", "A05:2021-Security Misconfiguration"),
    ("Content-Security-Policy",   "medium", "CWE-1021", "A05:2021-Security Misconfiguration"),
    ("X-Content-Type-Options",    "low",    "CWE-16",  "A05:2021-Security Misconfiguration"),
    ("X-Frame-Options",           "low",    "CWE-1021", "A05:2021-Security Misconfiguration"),
    ("Referrer-Policy",           "low",    "CWE-200",  "A05:2021-Security Misconfiguration"),
)

_CSP_WEAK_PATTERNS = (
    ("unsafe-inline in script-src", re.compile(r"script-src[^;]*'unsafe-inline'", re.IGNORECASE), "medium"),
    ("unsafe-eval",                 re.compile(r"'unsafe-eval'", re.IGNORECASE), "medium"),
    ("wildcard default-src",        re.compile(r"default-src[^;]*\*", re.IGNORECASE), "medium"),
    ("wildcard script-src",         re.compile(r"script-src[^;]*\*", re.IGNORECASE), "high"),
)

_RE_PRIVATE_IP = re.compile(
    r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
    r"192\.168\.\d{1,3}\.\d{1,3}|"
    r"172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|"
    r"127\.0\.0\.\d{1,3})\b"
)

_BINARY_CT_PREFIXES = ("image/", "video/", "audio/", "font/", "application/octet-stream",
                       "application/pdf", "application/zip", "application/gzip")


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------


def _status_code(response: str) -> int | None:
    m = _RE_STATUS.search(response)
    return int(m.group(1)) if m else None


def _header(blob: str, name: str) -> str | None:
    m = _RE_HEADER(name).search(blob)
    return m.group(1).strip() if m else None


def _split_body(blob: str) -> str:
    parts = re.split(r"\r?\n\r?\n", blob, maxsplit=1)
    return parts[1] if len(parts) == 2 else ""


def _is_binary(blob: str) -> bool:
    ct = (_header(blob, "Content-Type") or "").lower()
    return any(ct.startswith(p) for p in _BINARY_CT_PREFIXES)


def _mk(
    *,
    type_: str,
    detail: str,
    evidence: str,
    parameter: Optional[str] = None,
    confidence: str = "confirmed",
    cwe: Optional[str] = None,
    cvss: Optional[float] = None,
) -> dict:
    return {
        "type": type_,
        "parameter": parameter,
        "evidence": evidence[:300],
        "confidence": confidence,
        "detail": detail,
        "source": "detector",
        "cwe": cwe,
        "cvss": cvss,
    }


# ---------------------------------------------------------------------------
# Individual detectors
# ---------------------------------------------------------------------------


def _detect_jwt(response: str) -> list[dict]:
    out: list[dict] = []
    for m in _RE_JWT.finditer(response):
        tok = m.group(0)
        out.append(_mk(
            type_="Sensitive data",
            detail="JWT found in response body — verify it is not a long-lived privileged token.",
            evidence=tok[:80] + "…",
            confidence="likely",
            cwe="CWE-522",
            cvss=4.3,
        ))
        break  # one finding per response is enough
    return out


def _detect_cloud_secrets(blob: str) -> list[dict]:
    out: list[dict] = []
    for label, pat, cwe in _CLOUD_SECRET_PATTERNS:
        m = pat.search(blob)
        if m:
            out.append(_mk(
                type_="Secret leak",
                detail=f"{label} pattern detected — rotate immediately if real.",
                evidence=m.group(0)[:60] + ("…" if len(m.group(0)) > 60 else ""),
                confidence="likely",
                cwe=cwe,
                cvss=9.1,
            ))
    return out


def _detect_stack_traces(response: str) -> list[dict]:
    out: list[dict] = []
    for label, pat in _STACK_TRACE_PATTERNS:
        m = pat.search(response)
        if m:
            out.append(_mk(
                type_="Sensitive data",
                detail=f"Server-side {label} leaked into response — verbose error handling.",
                evidence=m.group(0)[:200],
                confidence="confirmed",
                cwe="CWE-209",
                cvss=5.3,
            ))
    return out


def _detect_missing_security_headers(response: str, url: str) -> list[dict]:
    if not urlparse(url).scheme.startswith("http"):
        return []
    status = _status_code(response)
    if status is None or not (200 <= status < 400):
        return []
    out: list[dict] = []
    missing = []
    for name, _risk_level, cwe, _owasp in _SECURITY_HEADERS:
        if _header(response, name) is None:
            missing.append((name, cwe))
    if not missing:
        return out
    detail = "Missing security headers: " + ", ".join(n for n, _ in missing)
    out.append(_mk(
        type_="Header misconfiguration",
        detail=detail,
        evidence=detail,
        confidence="confirmed",
        cwe=missing[0][1],
        cvss=3.7,
    ))
    return out


def _detect_csp_weakness(response: str) -> list[dict]:
    csp = _header(response, "Content-Security-Policy")
    if not csp:
        return []
    out: list[dict] = []
    for label, pat, _level in _CSP_WEAK_PATTERNS:
        if pat.search(csp):
            out.append(_mk(
                type_="Header misconfiguration",
                detail=f"CSP weakness: {label}.",
                evidence=csp[:240],
                confidence="confirmed",
                cwe="CWE-1021",
                cvss=4.3,
            ))
    return out


def _detect_private_ip_leak(response: str) -> list[dict]:
    body = _split_body(response)
    m = _RE_PRIVATE_IP.search(body)
    if not m:
        return []
    return [_mk(
        type_="Sensitive data",
        detail="Internal/private IP address leaked in response body.",
        evidence=m.group(0),
        confidence="likely",
        cwe="CWE-200",
        cvss=3.1,
    )]


# ---------------------------------------------------------------------------
# XSS - reflected query/body params unescaped in HTML responses + JS sinks
# ---------------------------------------------------------------------------

_RE_QUERY_PAIR = re.compile(r"[?&]([A-Za-z_][\w\-]{0,40})=([^&#\s]{1,200})")
_RE_FORM_PAIR  = re.compile(r"(?:^|[&\r\n])([A-Za-z_][\w\-]{0,40})=([^&\r\n]{1,200})")
_RE_JS_SINKS   = re.compile(
    r"\.innerHTML\s*=|document\.write\s*\(|eval\s*\(|setTimeout\s*\(\s*['\"]|"
    r"new\s+Function\s*\(",
    re.IGNORECASE,
)
_HTML_DANGEROUS_CHARS = ("<", ">", "\"", "'")


def _request_params(request: str, url: str) -> list[tuple[str, str]]:
    """Extract (name, value) pairs from URL query + form body, URL-decoded."""
    from urllib.parse import unquote_plus
    pairs: list[tuple[str, str]] = []
    for name, val in _RE_QUERY_PAIR.findall(url):
        pairs.append((name, unquote_plus(val)))
    body = _split_body(request)
    if body and "=" in body and "{" not in body[:10]:
        for name, val in _RE_FORM_PAIR.findall(body):
            pairs.append((name, unquote_plus(val)))
    return pairs


def _detect_xss(request: str, response: str, url: str) -> list[dict]:
    out: list[dict] = []
    ct = (_header(response, "Content-Type") or "").lower()
    body = _split_body(response)
    if not body:
        return out

    # 1) Reflected unescaped parameter values in an HTML response.
    if "text/html" in ct or "<html" in body[:200].lower():
        for name, value in _request_params(request, url):
            if len(value) < 4:
                continue
            if not any(c in value for c in _HTML_DANGEROUS_CHARS):
                continue
            if value in body:
                out.append(_mk(
                    type_="XSS",
                    parameter=name,
                    detail=(
                        f"Parameter '{name}' value containing HTML metacharacters "
                        "was reflected unescaped in the response body."
                    ),
                    evidence=value[:120],
                    confidence="likely",
                    cwe="CWE-79",
                    cvss=6.1,
                ))
                break

    # 2) Dangerous JS sinks in served script.
    if "javascript" in ct or "text/html" in ct:
        m = _RE_JS_SINKS.search(body)
        if m:
            out.append(_mk(
                type_="XSS",
                parameter=None,
                detail=(
                    "Response includes a dangerous JS sink (innerHTML / document.write "
                    "/ eval / Function) — sink-source flow should be reviewed."
                ),
                evidence=m.group(0),
                confidence="possible",
                cwe="CWE-79",
                cvss=4.3,
            ))

    return out


# ---------------------------------------------------------------------------
# Command injection - shell metacharacters in params + OS-output leaks in body
# ---------------------------------------------------------------------------

# Shell metacharacters / classic payloads in a request param value.
_RE_CMDI_HINT = re.compile(
    r"(?:;|\|\||&&|`|\$\(|\$\{IFS\}|"
    r"\b(?:id|whoami|uname|hostname|cat\s+/etc|ls\s+-l|ping\s+-[cn]\s+\d+|sleep\s+\d+|"
    r"nslookup|curl\s+http|wget\s+http|nc\s+-[el])\b)",
    re.IGNORECASE,
)

# Classic command-output signatures inside the response body.
_RE_CMDI_OUTPUT = (
    ("`id` output",       re.compile(r"\buid=\d+\([\w.\-]+\)\s*gid=\d+\([\w.\-]+\)")),
    ("/etc/passwd leak",  re.compile(r"^root:[x*!]:0:0:", re.MULTILINE)),
    ("`uname -a` output", re.compile(r"\bLinux\s+[\w.\-]+\s+\d+\.\d+\.\d+[-\w]*\s+#\d+", re.IGNORECASE)),
    ("`ls -l` output",    re.compile(r"^total\s+\d+\s*$[\s\S]{0,30}^[-dlrwxs]{10}\s+\d+\s+\w+\s+\w+", re.MULTILINE)),
    ("`ping` output",     re.compile(r"\b\d+\s+bytes\s+from\s+\S+:\s+icmp_seq=\d+", re.IGNORECASE)),
    ("Windows ipconfig",  re.compile(r"\bIPv4 Address[. ]*:\s*\d{1,3}(?:\.\d{1,3}){3}", re.IGNORECASE)),
    ("Windows whoami",    re.compile(r"\b[A-Z][A-Z0-9_\-]+\\[a-z][\w.\-]+\b")),
)


def _detect_command_injection(request: str, response: str, url: str) -> list[dict]:
    out: list[dict] = []
    # 1) Suspicious payload in a request parameter.
    for name, value in _request_params(request, url):
        if _RE_CMDI_HINT.search(value):
            out.append(_mk(
                type_="Command injection",
                parameter=name,
                detail=(
                    f"Parameter '{name}' contains shell metacharacters or classic "
                    "command-injection tokens (;, |, $(), backticks, id/whoami/cat). "
                    "Diff the response against a benign baseline to confirm."
                ),
                evidence=value[:120],
                confidence="possible",
                cwe="CWE-78",
                cvss=7.5,
            ))
            break
    # 2) Command output leaked in the response body.
    body = _split_body(response) or response
    for label, pat in _RE_CMDI_OUTPUT:
        m = pat.search(body)
        if m:
            out.append(_mk(
                type_="Command injection",
                detail=f"Response body contains {label} - probable command-execution leak.",
                evidence=m.group(0)[:200],
                confidence="likely",
                cwe="CWE-78",
                cvss=9.1,
            ))
            break  # one output-leak finding per response is enough
    return out


# ---------------------------------------------------------------------------
# SQLi - boolean / quote injection hints (in addition to stack-trace tier)
# ---------------------------------------------------------------------------

_RE_SQLI_HINT = re.compile(
    r"(?:'|%27|--|\bOR\b\s+\d+\s*=\s*\d+|\bUNION\b\s+SELECT|\bSLEEP\(|\bBENCHMARK\()",
    re.IGNORECASE,
)


def _detect_sqli_hint(request: str, url: str) -> list[dict]:
    out: list[dict] = []
    for name, value in _request_params(request, url):
        if _RE_SQLI_HINT.search(value):
            out.append(_mk(
                type_="SQLi",
                parameter=name,
                detail=(
                    f"Parameter '{name}' contains SQL-injection-shaped tokens "
                    "(quote / boolean / UNION / time delay). Send to /diff with "
                    "a benign baseline to confirm exploitability."
                ),
                evidence=value[:120],
                confidence="possible",
                cwe="CWE-89",
                cvss=5.0,
            ))
            break
    return out


# ---------------------------------------------------------------------------
# JWT crypto - decode header + payload, flag alg=none, missing exp, long-lived
# ---------------------------------------------------------------------------

import base64 as _b64
import json as _json


def _b64url_decode(seg: str) -> bytes:
    pad = "=" * (-len(seg) % 4)
    try:
        return _b64.urlsafe_b64decode(seg + pad)
    except Exception:
        return b""


def _decode_jwt(token: str):
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        hdr = _json.loads(_b64url_decode(parts[0]) or b"{}")
        pld = _json.loads(_b64url_decode(parts[1]) or b"{}")
        if isinstance(hdr, dict) and isinstance(pld, dict):
            return hdr, pld
    except Exception:
        return None
    return None


def _detect_jwt_crypto(blob: str) -> list[dict]:
    """Inspect every JWT in `blob` for cryptographic / lifetime weaknesses."""
    out: list[dict] = []
    seen: set[str] = set()
    for m in _RE_JWT.finditer(blob):
        tok = m.group(0)
        if tok in seen:
            continue
        seen.add(tok)
        decoded = _decode_jwt(tok)
        if not decoded:
            continue
        hdr, pld = decoded
        alg = str(hdr.get("alg", "")).lower()

        if alg in {"none", ""}:
            out.append(_mk(
                type_="JWT misconfiguration",
                detail="JWT uses alg=none - signature verification can be trivially bypassed.",
                evidence=tok[:80] + ("..." if len(tok) > 80 else ""),
                confidence="confirmed",
                cwe="CWE-347",
                cvss=9.1,
            ))
            continue

        if alg.startswith("hs"):
            sig = tok.split(".")[-1]
            if len(sig) < 22:
                out.append(_mk(
                    type_="JWT misconfiguration",
                    detail=f"JWT uses {alg.upper()} but signature is suspiciously short - likely weak secret.",
                    evidence=tok[:80] + "...",
                    confidence="possible",
                    cwe="CWE-326",
                    cvss=5.9,
                ))

        exp = pld.get("exp")
        iat = pld.get("iat")
        if exp is None:
            out.append(_mk(
                type_="JWT misconfiguration",
                detail="JWT payload has no 'exp' claim - token never expires.",
                evidence=_json.dumps({k: pld.get(k) for k in ("iss", "sub", "iat") if k in pld})[:120],
                confidence="confirmed",
                cwe="CWE-613",
                cvss=5.3,
            ))
        elif isinstance(exp, (int, float)) and isinstance(iat, (int, float)):
            lifetime_days = (exp - iat) / 86400.0
            if lifetime_days > 30:
                out.append(_mk(
                    type_="JWT misconfiguration",
                    detail=f"JWT lifetime is ~{lifetime_days:.0f} days - exceeds 30-day guideline.",
                    evidence=f"iat={iat} exp={exp}",
                    confidence="likely",
                    cwe="CWE-613",
                    cvss=4.3,
                ))
    return out


# ---------------------------------------------------------------------------
# XXE - XML request bodies + XML parser error signatures in responses
# ---------------------------------------------------------------------------

_RE_XML_REQ_CT = re.compile(r"content-type\s*:[^\r\n]*\b(?:application|text)/xml\b", re.IGNORECASE)
_RE_XML_DECL   = re.compile(r"<\?xml\b[^?>]*\?>")
_RE_XML_ENTITY = re.compile(r"<!ENTITY\b[^>]+SYSTEM", re.IGNORECASE)
_RE_XML_PARSE_ERR = re.compile(
    r"(SAXParseException|XMLParseError|lxml\.etree\.XMLSyntaxError|"
    r"DOMException.*XML|Premature end of data|EntityRef.*expected)",
    re.IGNORECASE,
)


def _detect_xxe(request: str, response: str) -> list[dict]:
    out: list[dict] = []
    req_is_xml = bool(_RE_XML_REQ_CT.search(request) or _RE_XML_DECL.search(request[:300]))
    if req_is_xml:
        m_entity = _RE_XML_ENTITY.search(request)
        if m_entity:
            out.append(_mk(
                type_="XXE",
                detail="Request body declares an external XML entity (SYSTEM) - direct XXE exposure.",
                evidence=m_entity.group(0)[:200],
                confidence="confirmed",
                cwe="CWE-611",
                cvss=8.6,
            ))
        else:
            out.append(_mk(
                type_="XXE",
                detail=(
                    "Endpoint accepts XML - candidate for XXE probe (entity expansion, "
                    "billion laughs, SYSTEM file://). Enable agentic.enabled to test."
                ),
                evidence="Content-Type: application/xml",
                confidence="possible",
                cwe="CWE-611",
                cvss=5.0,
            ))
    m_err = _RE_XML_PARSE_ERR.search(response)
    if m_err:
        out.append(_mk(
            type_="XXE",
            detail="Server XML parser error leaked - confirms XML processing path is reachable.",
            evidence=m_err.group(0)[:200],
            confidence="likely",
            cwe="CWE-611",
            cvss=5.3,
        ))
    return out



# ---------------------------------------------------------------------------
# HTTP request smuggling - CL.TE / TE.CL header mismatch + chunked confusion
# ---------------------------------------------------------------------------

_RE_TRANSFER_ENCODING = re.compile(r"^transfer-encoding\s*:\s*([^\r\n]+)", re.IGNORECASE | re.MULTILINE)
_RE_CONTENT_LENGTH = re.compile(r"^content-length\s*:\s*(\d+)", re.IGNORECASE | re.MULTILINE)
_RE_DUPLICATE_TE = re.compile(r"transfer-encoding\s*:[^\r\n]*\r?\n[\s\S]*?transfer-encoding\s*:", re.IGNORECASE)


def _detect_request_smuggling(request: str, response: str) -> list[dict]:
    out: list[dict] = []
    te = _RE_TRANSFER_ENCODING.search(request)
    cl = _RE_CONTENT_LENGTH.search(request)
    if te and cl:
        out.append(_mk(
            type_="HTTP request smuggling",
            detail=(
                "Request carries BOTH Content-Length and Transfer-Encoding headers. "
                "Front/back-end proxies that disagree on which header wins are "
                "smuggling-vulnerable (CL.TE or TE.CL)."
            ),
            evidence=f"TE={te.group(1).strip()[:40]} | CL={cl.group(1)}",
            confidence="likely",
            cwe="CWE-444",
            cvss=8.1,
        ))
    if _RE_DUPLICATE_TE.search(request):
        out.append(_mk(
            type_="HTTP request smuggling",
            detail="Request contains TWO Transfer-Encoding headers - exploitable confusion vector.",
            evidence="duplicate Transfer-Encoding header",
            confidence="likely",
            cwe="CWE-444",
            cvss=8.1,
        ))
    # Response-side hint: 400 with a body that looks like a partial second response.
    status = _status_code(response) or 0
    body = _split_body(response)
    if status == 400 and re.search(r"\bHTTP/\d\.\d\s+\d{3}", body):
        out.append(_mk(
            type_="HTTP request smuggling",
            detail="400 response body contains an embedded HTTP status line - server may be desynchronised.",
            evidence=body[:200],
            confidence="possible",
            cwe="CWE-444",
            cvss=6.5,
        ))
    return out


# ---------------------------------------------------------------------------
# GraphQL - introspection, deeply-nested queries, mutations without auth
# ---------------------------------------------------------------------------

_RE_GRAPHQL_PATH = re.compile(r"/(?:graphql|gql|api/graphql|v\d+/graphql)\b", re.IGNORECASE)
_RE_GRAPHQL_INTROSPECTION = re.compile(r'\b(?:__schema|__type|__typename)\b')
_RE_GRAPHQL_MUTATION = re.compile(r'"\s*query\s*"\s*:\s*"\s*mutation\b|^\s*mutation\b', re.IGNORECASE)


def _detect_graphql(request: str, response: str, url: str) -> list[dict]:
    if not _RE_GRAPHQL_PATH.search(url) and "graphql" not in (_header(response, "Content-Type") or "").lower():
        return []
    out: list[dict] = []
    body = _split_body(request) or request

    # 1) Introspection allowed in production (any non-empty introspection response is bad).
    if _RE_GRAPHQL_INTROSPECTION.search(body):
        resp_body = _split_body(response)
        if resp_body and ('"__schema"' in resp_body or '"types"' in resp_body):
            out.append(_mk(
                type_="GraphQL misconfiguration",
                detail="GraphQL introspection is enabled - exposes the full schema to anyone.",
                evidence="__schema query returned populated response",
                confidence="confirmed",
                cwe="CWE-200",
                cvss=5.3,
            ))

    # 2) Deeply nested query - DoS / batching risk. Count `{` depth in the body.
    depth, peak = 0, 0
    for ch in body:
        if ch == "{":
            depth += 1
            peak = max(peak, depth)
        elif ch == "}":
            depth -= 1
    if peak >= 8:
        out.append(_mk(
            type_="GraphQL misconfiguration",
            detail=f"Query brace depth is {peak} - depth-limit / cost-analysis appears absent (DoS risk).",
            evidence=f"max brace depth = {peak}",
            confidence="likely",
            cwe="CWE-674",
            cvss=5.3,
        ))

    # 3) Mutation called without an Authorization header.
    if _RE_GRAPHQL_MUTATION.search(body) and not re.search(r"^authorization\s*:", request, re.IGNORECASE | re.MULTILINE):
        out.append(_mk(
            type_="GraphQL misconfiguration",
            detail="GraphQL mutation issued WITHOUT an Authorization header - investigate access control.",
            evidence="mutation { ... } without Authorization",
            confidence="possible",
            cwe="CWE-862",
            cvss=6.5,
        ))
    return out


# ---------------------------------------------------------------------------
# Mass assignment / parameter pollution
# ---------------------------------------------------------------------------

_RE_DUPLICATE_PARAM = re.compile(r"[?&]([A-Za-z_][\w\-]{0,40})=[^&#]*&[^&#]*\1=")
_PRIVILEGE_KEYS = frozenset({
    "isadmin", "is_admin", "admin", "role", "roles", "is_superuser",
    "is_staff", "permissions", "scope", "scopes", "tier", "plan",
    "verified", "approved", "balance", "credit",
})


_RE_MA_REQ_LINE = re.compile(r"^([A-Z]+)\s+\S+\s+HTTP/", re.MULTILINE)


def _detect_mass_assignment(request: str, url: str) -> list[dict]:
    out: list[dict] = []
    m_method = _RE_MA_REQ_LINE.search(request)
    method = m_method.group(1).upper() if m_method else ""

    # 1) Duplicate parameter name in URL query string.
    m = _RE_DUPLICATE_PARAM.search(url)
    if m:
        out.append(_mk(
            type_="Parameter pollution",
            parameter=m.group(1),
            detail=(
                f"Query parameter '{m.group(1)}' appears more than once - "
                "back-end and proxy may parse different values (HPP)."
            ),
            evidence=m.group(0)[:120],
            confidence="likely",
            cwe="CWE-235",
            cvss=5.0,
        ))

    # 2) Privilege-key smuggled into POST/PUT/PATCH body.
    if method in {"POST", "PUT", "PATCH"}:
        body = _split_body(request) or ""
        for key in _PRIVILEGE_KEYS:
            # JSON body: "isAdmin":true or "role":"admin"
            jm = re.search(rf'"{key}"\s*:\s*("[^"]*"|true|\d+)', body, re.IGNORECASE)
            if jm:
                out.append(_mk(
                    type_="Mass assignment",
                    parameter=key,
                    detail=(
                        f"Request body sets the privileged field '{key}' - "
                        "verify the server ignores client-supplied authorisation fields."
                    ),
                    evidence=jm.group(0)[:120],
                    confidence="possible",
                    cwe="CWE-915",
                    cvss=7.5,
                ))
                break
            # Form body: isAdmin=true
            fm = re.search(rf'(?:^|[&\r\n]){key}=[^&\r\n]+', body, re.IGNORECASE)
            if fm:
                out.append(_mk(
                    type_="Mass assignment",
                    parameter=key,
                    detail=(
                        f"Form body sets the privileged field '{key}' - "
                        "verify the server ignores client-supplied authorisation fields."
                    ),
                    evidence=fm.group(0)[:120],
                    confidence="possible",
                    cwe="CWE-915",
                    cvss=7.5,
                ))
                break
    return out


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def run_detectors(request: str, response: str, url: str) -> list[dict]:
    """
    Run every enabled detector and return the merged finding list.

    The caller is responsible for feeding these findings both to the store
    AND to the LLM prompt (as pre-seen evidence) so the model does not
    re-raise them as hallucinated duplicates.
    """
    cfg = load_config().get("detectors", {})
    if not cfg.get("enabled", True):
        return []

    if _is_binary(response):
        return []

    findings: list[dict] = []
    try:
        if cfg.get("jwt", True):
            findings.extend(_detect_jwt(response))
        if cfg.get("jwt_crypto", True):
            findings.extend(_detect_jwt_crypto(response))
            findings.extend(_detect_jwt_crypto(request))
        if cfg.get("cloud_secrets", True):
            findings.extend(_detect_cloud_secrets(response))
            findings.extend(_detect_cloud_secrets(request))
        if cfg.get("stack_traces", True):
            findings.extend(_detect_stack_traces(response))
        if cfg.get("security_headers", True):
            findings.extend(_detect_missing_security_headers(response, url))
        if cfg.get("csp_weakness", True):
            findings.extend(_detect_csp_weakness(response))
        if cfg.get("private_ip_leak", True):
            findings.extend(_detect_private_ip_leak(response))
        if cfg.get("xss", True):
            findings.extend(_detect_xss(request, response, url))
        if cfg.get("sqli_hint", True):
            findings.extend(_detect_sqli_hint(request, url))
        if cfg.get("command_injection", True):
            findings.extend(_detect_command_injection(request, response, url))
        if cfg.get("xxe", True):
            findings.extend(_detect_xxe(request, response))
        if cfg.get("request_smuggling", True):
            findings.extend(_detect_request_smuggling(request, response))
        if cfg.get("graphql", True):
            findings.extend(_detect_graphql(request, response, url))
        if cfg.get("mass_assignment", True):
            findings.extend(_detect_mass_assignment(request, url))
        # Extended OWASP Top 10 coverage (A06/A08/A10 + SSTI/NoSQL/debug).
        findings.extend(_extras.run_extras(request, response, url))
    except Exception as exc:
        _log.warning("detectors crashed on %s: %s", url, exc)
        return []

    if findings:
        _log.debug("detectors: %d finding(s) on %s", len(findings), url)
    return findings


def summary_for_prompt(findings):
    if not findings:
        return ""
    lines = []
    for f in findings:
        lines.append(f"- [{f['type']}] {f.get('detail', '')} (evidence: {f.get('evidence', '')[:100]})")
    return "\n".join(lines)


def worst_risk(findings):
    score = {"critical": 5, "high": 4, "medium": 3, "low": 2, "none": 1}
    if not findings:
        return "none"
    best = "none"
    for f in findings:
        c = f.get("cvss") or 0.0
        if c >= 9.0: label = "critical"
        elif c >= 7.0: label = "high"
        elif c >= 4.0: label = "medium"
        elif c > 0: label = "low"
        else: label = "low"
        if score[label] > score[best]:
            best = label
    return best


if __name__ == "__main__":
    resp = (
        "HTTP/1.1 200 OK\nContent-Type: text/plain\n\n"
        "uid=33(www-data) gid=33(www-data) groups=33(www-data)\n"
    )
    f = run_detectors("GET /api/exec?cmd=id HTTP/1.1\nHost: x\n\n", resp, "https://x/api/exec?cmd=id")
    for it in f:
        print(it["type"], "-", it["detail"][:80])
    print("detectors.py smoke test ok -", len(f), "findings")
