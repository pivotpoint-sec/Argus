"""
Additional OWASP Top 10 (2021) detectors that close the coverage gap.

Covers:
  - A06: Vulnerable and Outdated Components - fingerprinting
  - A10: SSRF candidate detection (deterministic; confirmation still
         requires Burp Collaborator or an OOB listener)
  - A08: Insecure deserialization (Java, PHP, Python, .NET) + missing SRI
  - A03: SSTI via template-engine error signatures, NoSQL operators in JSON
  - A05: Debug / management / VCS / config endpoints exposed

Same shape as llm_bridge/detectors.py: each function returns a list of
plain dicts matching the Finding schema with source="detector". A single
public run_extras() dispatches them all and is called from detectors.py.
"""
from __future__ import annotations

import re
from typing import Optional
from urllib.parse import urlparse, parse_qsl, unquote_plus

from .config import configure_logging, load_config

_log = configure_logging()


# ---------------------------------------------------------------------------
# Shared helpers (intentionally duplicated so this module is independent)
# ---------------------------------------------------------------------------

_RE_STATUS = re.compile(r"^HTTP/\d(?:\.\d)?\s+(\d{3})", re.MULTILINE)


def _status(response: str) -> Optional[int]:
    m = _RE_STATUS.search(response)
    return int(m.group(1)) if m else None


def _header(blob: str, name: str) -> Optional[str]:
    # No `$` anchor: `[^\r\n]+` already stops at EOL, and `$` in MULTILINE
    # mode matches before `\n` not before `\r`, which breaks on CRLF inputs.
    pat = re.compile(rf"^{re.escape(name)}\s*:\s*([^\r\n]+)", re.IGNORECASE | re.MULTILINE)
    m = pat.search(blob)
    return m.group(1).strip() if m else None


def _split_body(blob: str) -> str:
    parts = re.split(r"\r?\n\r?\n", blob, maxsplit=1)
    return parts[1] if len(parts) == 2 else ""


def _mk(
    *,
    type_: str,
    detail: str,
    evidence: str,
    parameter: Optional[str] = None,
    confidence: str = "likely",
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
# A06: Vulnerable / Outdated Components - fingerprinting
# ---------------------------------------------------------------------------

# Versioned tokens worth surfacing if they leak (vendor / product / version).
_RE_VERSIONED_HEADER = re.compile(r"([A-Za-z][\w./\-]*)/(\d+(?:\.\d+){1,3})")

_FINGERPRINT_HEADERS = (
    "Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version",
    "X-Generator", "X-Runtime", "Liferay-Portal",
)

_FINGERPRINT_COOKIES = (
    ("PHPSESSID",   "PHP application"),
    ("JSESSIONID",  "Java servlet container (Tomcat/Jetty/WildFly)"),
    ("ASP.NET_SessionId", ".NET / ASP.NET application"),
    ("CFID",        "Adobe ColdFusion application"),
    ("CFTOKEN",     "Adobe ColdFusion application"),
    ("_session_id", "Ruby on Rails application"),
    ("connect.sid", "Node.js Express (connect) session"),
    ("laravel_session", "PHP Laravel application"),
    ("wordpress_logged_in", "WordPress installation"),
    ("wp-settings", "WordPress installation"),
)

_FINGERPRINT_PATHS = (
    (re.compile(r"/wp-(?:login\.php|admin/|content/|includes/)", re.IGNORECASE),
     "WordPress installation", "high"),
    (re.compile(r"/phpMyAdmin/?|/phpmyadmin/?", re.IGNORECASE),
     "phpMyAdmin exposed", "high"),
    (re.compile(r"/manager/(?:html|status|text)", re.IGNORECASE),
     "Apache Tomcat manager exposed", "high"),
    (re.compile(r"/jenkins/?|/script\b", re.IGNORECASE),
     "Jenkins / script console", "medium"),
    (re.compile(r"/drupal/?|/sites/default/", re.IGNORECASE),
     "Drupal installation", "medium"),
    (re.compile(r"/typo3/?", re.IGNORECASE),
     "TYPO3 installation", "medium"),
    (re.compile(r"/joomla/?|/administrator/index\.php", re.IGNORECASE),
     "Joomla installation", "medium"),
)


def _detect_fingerprint(request: str, response: str, url: str) -> list[dict]:
    out: list[dict] = []

    # 1) Versioned product banners in well-known headers.
    versioned = []
    for h in _FINGERPRINT_HEADERS:
        v = _header(response, h)
        if not v:
            continue
        m = _RE_VERSIONED_HEADER.search(v)
        if m:
            versioned.append(f"{h}: {v}")
        elif v.strip() and v.strip() != "-":
            # Unversioned but still informative.
            versioned.append(f"{h}: {v}")
    if versioned:
        out.append(_mk(
            type_="Vulnerable component",
            detail=(
                "Server / framework version disclosed in response headers - "
                "cross-check against the relevant CVE database. Hiding these "
                "headers is a defence-in-depth measure."
            ),
            evidence="; ".join(versioned[:3])[:240],
            confidence="confirmed",
            cwe="CWE-200",
            cvss=3.7,
        ))

    # 2) Framework-identifying cookies.
    set_cookie = " ".join(re.findall(r"^Set-Cookie\s*:\s*([^\r\n]+)", response, re.IGNORECASE | re.MULTILINE))
    if set_cookie:
        for name, tech in _FINGERPRINT_COOKIES:
            if re.search(rf"\b{re.escape(name)}=", set_cookie):
                out.append(_mk(
                    type_="Vulnerable component",
                    detail=f"Cookie '{name}' reveals {tech} - inventory the stack version for CVEs.",
                    evidence=f"Set-Cookie: {name}=...",
                    confidence="confirmed",
                    cwe="CWE-200",
                    cvss=3.1,
                ))
                break

    # 3) Path-based fingerprints (URL patterns that uniquely identify a product).
    for pat, tech, sev in _FINGERPRINT_PATHS:
        if pat.search(urlparse(url).path):
            cvss = 5.3 if sev == "high" else 3.7
            out.append(_mk(
                type_="Vulnerable component",
                detail=f"{tech} reachable at this URL - audit the deployed version for outstanding CVEs.",
                evidence=urlparse(url).path[:160],
                confidence="confirmed",
                cwe="CWE-200",
                cvss=cvss,
            ))
            break
    return out


# ---------------------------------------------------------------------------
# A10: SSRF candidate detection
# ---------------------------------------------------------------------------

_SSRF_PARAM_HINTS = frozenset({
    "url", "uri", "src", "source", "dest", "destination", "redirect", "redir",
    "redirect_uri", "redirect_url", "callback", "image", "image_url", "img",
    "imageurl", "avatar", "avatar_url", "fetch", "fetch_url", "host",
    "target", "endpoint", "feed", "data", "domain", "site", "next",
    "return", "return_to", "returnurl", "continue", "u", "link", "ref",
})

_RE_INTERNAL_IP = re.compile(
    r"\b(?:"
    r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
    r"192\.168\.\d{1,3}\.\d{1,3}|"
    r"172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|"
    r"127\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
    r"169\.254\.\d{1,3}\.\d{1,3}|"
    r"::1|fc00::|fe80::"
    r")\b"
)
_RE_AWS_METADATA = re.compile(r"169\.254\.169\.254")
_RE_ABS_URL = re.compile(r"^(?:https?|file|gopher|dict|ftp|ldap|sftp)://", re.IGNORECASE)


def _detect_ssrf_candidate(request: str, url: str) -> list[dict]:
    out: list[dict] = []
    query_pairs = parse_qsl(urlparse(url).query, keep_blank_values=True)
    body = _split_body(request)

    body_pairs: list[tuple[str, str]] = []
    # JSON body: pull "key":"value" pairs roughly.
    if body and body.lstrip().startswith("{"):
        for m in re.finditer(r'"([A-Za-z_][\w\-]{0,40})"\s*:\s*"([^"]{1,400})"', body):
            body_pairs.append((m.group(1), m.group(2)))
    elif body and "=" in body:
        for m in re.finditer(r'(?:^|[&\r\n])([A-Za-z_][\w\-]{0,40})=([^&\r\n]{1,400})', body):
            body_pairs.append((m.group(1), unquote_plus(m.group(2))))

    for name, value in list(query_pairs) + body_pairs:
        nlow = name.lower()
        if nlow not in _SSRF_PARAM_HINTS:
            continue
        decoded = unquote_plus(str(value))
        if not _RE_ABS_URL.search(decoded):
            continue
        is_metadata = bool(_RE_AWS_METADATA.search(decoded))
        is_internal = bool(_RE_INTERNAL_IP.search(decoded))
        scheme = decoded.split(":", 1)[0].lower()
        cvss = 9.8 if is_metadata else (8.6 if is_internal else 6.5)
        confidence = "confirmed" if is_metadata else ("likely" if is_internal else "possible")
        why = []
        if is_metadata:
            why.append("AWS metadata 169.254.169.254 reachable")
        elif is_internal:
            why.append("URL points at an RFC1918 / loopback / link-local address")
        if scheme not in {"http", "https"}:
            why.append(f"non-standard scheme '{scheme}://'")
        if not why:
            why.append("absolute URL in a typical SSRF-vector parameter")
        out.append(_mk(
            type_="SSRF",
            parameter=name,
            detail=(
                f"Parameter '{name}' carries an absolute URL ({', '.join(why)}). "
                "Confirm with an out-of-band callback (Burp Collaborator)."
            ),
            evidence=decoded[:200],
            confidence=confidence,
            cwe="CWE-918",
            cvss=cvss,
        ))
        break  # one finding per request is enough
    return out


# ---------------------------------------------------------------------------
# A08: Insecure deserialization + missing SRI
# ---------------------------------------------------------------------------

# Java serialized objects always start with magic 0xAC ED 00 05 = base64 prefix "rO0"
_RE_JAVA_SERIALIZED_B64 = re.compile(r"\brO0[A-Za-z0-9+/=]{40,}")
_RE_JAVA_SERIALIZED_HEX = re.compile(r"\bac\s?ed\s?0\s?0\s?0\s?5\b", re.IGNORECASE)

# PHP serialized object: O:N:"ClassName": or a:N:{ at start of value
_RE_PHP_SERIALIZED = re.compile(r"\b[Oa]:\d+:\"[A-Za-z_\\][\w\\]*\":\d+:\{", re.IGNORECASE)

# Python pickle: \x80 protocol byte followed by protocol 0-5. Hex/base64 form.
_RE_PICKLE_B64 = re.compile(r"\bgASV[A-Za-z0-9+/=]{20,}")  # gASV = b"\x80\x04\x95" base64
_RE_PICKLE_REDUCE = re.compile(r'"__reduce__"|"__class__"\s*:\s*"', re.IGNORECASE)

# .NET ViewState (legacy unencrypted): base64 starting with /w== or similar headers
_RE_VIEWSTATE = re.compile(r"__VIEWSTATE\s*=\s*([^&\s]{40,})")

# Subresource Integrity check: external <script src="https://cdn..."> without integrity=
_RE_EXTERNAL_SCRIPT_NO_SRI = re.compile(
    r'<script\b[^>]*\bsrc=["\']https?://(?!(?:localhost|127\.|0\.0\.0\.0))[^"\']+["\'][^>]*>',
    re.IGNORECASE,
)


def _detect_deserialization(request: str, response: str) -> list[dict]:
    out: list[dict] = []
    # Scan request body + cookies + headers for serialized blobs.
    blobs = [_split_body(request) or "", request]
    for blob in blobs:
        m = _RE_JAVA_SERIALIZED_B64.search(blob) or _RE_JAVA_SERIALIZED_HEX.search(blob)
        if m:
            out.append(_mk(
                type_="Insecure deserialization",
                detail=(
                    "Request carries a Java serialized object (magic 0xACED0005). "
                    "If the server deserialises it before authentication, this is "
                    "remote code execution territory (CVE-2015-7501 class)."
                ),
                evidence=m.group(0)[:160],
                confidence="likely",
                cwe="CWE-502",
                cvss=9.1,
            ))
            break
        m = _RE_PHP_SERIALIZED.search(blob)
        if m:
            out.append(_mk(
                type_="Insecure deserialization",
                detail=(
                    "Request carries a PHP serialized object. PHP unserialize() "
                    "on attacker-controlled input enables magic-method (POP) "
                    "chains - audit any __wakeup / __destruct in the codebase."
                ),
                evidence=m.group(0)[:160],
                confidence="likely",
                cwe="CWE-502",
                cvss=9.1,
            ))
            break
        m = _RE_PICKLE_B64.search(blob)
        if m:
            out.append(_mk(
                type_="Insecure deserialization",
                detail=(
                    "Request carries what looks like a base64-encoded Python "
                    "pickle blob. pickle.loads() on untrusted input is "
                    "always-RCE; do not deserialise."
                ),
                evidence=m.group(0)[:160],
                confidence="likely",
                cwe="CWE-502",
                cvss=9.8,
            ))
            break
        m = _RE_VIEWSTATE.search(blob)
        if m:
            out.append(_mk(
                type_="Insecure deserialization",
                detail=(
                    ".NET __VIEWSTATE present - confirm validation/encryption is "
                    "enabled (ViewStateMac) or this is a deserialisation RCE "
                    "(BinaryFormatter / ObjectStateFormatter gadget chains)."
                ),
                evidence=m.group(0)[:120],
                confidence="possible",
                cwe="CWE-502",
                cvss=7.5,
            ))
            break

    # Missing SRI on external <script> tags loaded from CDNs.
    body = _split_body(response) or ""
    if "<script" in body.lower():
        for m in _RE_EXTERNAL_SCRIPT_NO_SRI.finditer(body):
            tag = m.group(0)
            if "integrity=" in tag.lower():
                continue
            out.append(_mk(
                type_="Missing Subresource Integrity",
                detail=(
                    "External <script> loaded from a third-party origin without an "
                    "integrity= attribute - a compromised CDN can ship arbitrary JS."
                ),
                evidence=tag[:200],
                confidence="confirmed",
                cwe="CWE-353",
                cvss=4.3,
            ))
            break
    return out


# ---------------------------------------------------------------------------
# A03: SSTI (response-side template error signatures) + NoSQL injection
# ---------------------------------------------------------------------------

_SSTI_ERROR_PATTERNS = (
    ("Jinja2",     re.compile(r"jinja2\.exceptions\.(?:Template|Undefined)\w*", re.IGNORECASE)),
    ("Twig",       re.compile(r"Twig(?:_Error_Syntax|\\Error\\SyntaxError)", re.IGNORECASE)),
    ("Freemarker", re.compile(r"freemarker\.template\.TemplateException", re.IGNORECASE)),
    ("Velocity",   re.compile(r"org\.apache\.velocity\.exception", re.IGNORECASE)),
    ("Liquid",     re.compile(r"Liquid::SyntaxError", re.IGNORECASE)),
    ("ERB / Ruby", re.compile(r"\(erb\):\d+|ActionView::Template::Error", re.IGNORECASE)),
    ("Smarty",     re.compile(r"Smarty(?:CompilerException|Exception)", re.IGNORECASE)),
    ("Handlebars", re.compile(r"Handlebars\.SafeString|Parse error on line \d+", re.IGNORECASE)),
)


def _detect_ssti(response: str) -> list[dict]:
    body = _split_body(response) or response
    for engine, pat in _SSTI_ERROR_PATTERNS:
        m = pat.search(body)
        if m:
            return [_mk(
                type_="SSTI",
                detail=(
                    f"Response contains a {engine} template-engine stack trace - "
                    "user input may be evaluated as a template expression. Try "
                    "engine-specific probes (e.g. {{7*7}}, ${{7*7}}) on input params."
                ),
                evidence=m.group(0)[:200],
                confidence="likely",
                cwe="CWE-1336",
                cvss=8.6,
            )]
    return []


_NOSQL_OPS = (r"\$ne", r"\$gt", r"\$lt", r"\$gte", r"\$lte", r"\$where",
              r"\$regex", r"\$or", r"\$exists", r"\$in", r"\$nin")
_RE_NOSQL_OPS = re.compile(r'"(' + "|".join(_NOSQL_OPS) + r')"\s*:', re.IGNORECASE)


def _detect_nosql_injection(request: str) -> list[dict]:
    body = _split_body(request) or ""
    if not body.lstrip().startswith("{"):
        return []
    m = _RE_NOSQL_OPS.search(body)
    if not m:
        return []
    return [_mk(
        type_="NoSQL injection",
        detail=(
            f"Request JSON body contains a MongoDB-style operator ({m.group(1)}) - "
            "operator injection (always-true / regex match / blind boolean) "
            "is the typical NoSQLi vector."
        ),
        evidence=m.group(0)[:120],
        confidence="likely",
        cwe="CWE-943",
        cvss=7.5,
    )]


# ---------------------------------------------------------------------------
# A05: Debug / management / VCS / config endpoints exposed
# ---------------------------------------------------------------------------

_RE_DEBUG_PATH = re.compile(
    r"/(?:"
    r"\.git/HEAD|\.git/config|\.env|\.envrc|"
    r"actuator/(?:env|heapdump|threaddump|metrics|mappings|trace|configprops)|"
    r"debug/?(?:vars|pprof)?|__debug__/?|"
    r"console/?|jolokia/?|"
    r"swagger\.json|swagger-ui|api-docs|openapi\.json|"
    r"server-status|server-info|"
    r"phpinfo\.php|info\.php|test\.php|"
    r"web\.config|appsettings\.json|"
    r"id_rsa|id_dsa|\.htpasswd|\.htaccess"
    r")(?:$|[?#])",
    re.IGNORECASE,
)

_RE_DIRECTORY_LISTING = re.compile(r"<title>\s*Index of /", re.IGNORECASE)


def _detect_debug_endpoint(response: str, url: str) -> list[dict]:
    out: list[dict] = []
    path = urlparse(url).path
    status = _status(response) or 0
    m = _RE_DEBUG_PATH.search(path)
    if m and 200 <= status < 400:
        out.append(_mk(
            type_="Header misconfiguration",
            detail=(
                f"Debug / management / config endpoint reachable ({m.group(0)}) - "
                "remove from production or restrict by IP / auth."
            ),
            evidence=path[:160],
            confidence="confirmed",
            cwe="CWE-489",
            cvss=7.5,
        ))
    if _RE_DIRECTORY_LISTING.search(_split_body(response) or ""):
        out.append(_mk(
            type_="Header misconfiguration",
            detail="Server returned an Apache/Nginx-style directory listing - disable autoindex.",
            evidence="<title>Index of /",
            confidence="confirmed",
            cwe="CWE-548",
            cvss=5.3,
        ))
    return out


# ---------------------------------------------------------------------------
# Public dispatcher
# ---------------------------------------------------------------------------


def run_extras(request: str, response: str, url: str) -> list[dict]:
    """Run every extra-OWASP detector and return the merged finding list."""
    cfg = load_config().get("detectors", {})
    findings: list[dict] = []
    try:
        if cfg.get("fingerprint", True):
            findings.extend(_detect_fingerprint(request, response, url))
        if cfg.get("ssrf_candidate", True):
            findings.extend(_detect_ssrf_candidate(request, url))
        if cfg.get("deserialization", True):
            findings.extend(_detect_deserialization(request, response))
        if cfg.get("ssti", True):
            findings.extend(_detect_ssti(response))
        if cfg.get("nosql", True):
            findings.extend(_detect_nosql_injection(request))
        if cfg.get("debug_endpoints", True):
            findings.extend(_detect_debug_endpoint(response, url))
    except Exception as exc:
        _log.warning("owasp_extras: crashed on %s: %s", url, exc)
        return []
    if findings:
        _log.debug("owasp_extras: %d extra finding(s) on %s", len(findings), url)
    return findings


if __name__ == "__main__":
    resp = (
        "HTTP/1.1 200 OK\r\nServer: nginx/1.14.0\r\n"
        "X-Powered-By: PHP/7.2.34\r\n"
        "Set-Cookie: PHPSESSID=abc123\r\n"
        "Content-Type: text/html\r\n\r\n"
        "<html><script src='https://cdn.example.com/jquery.js'></script></html>"
    )
    req = (
        "POST /api/users HTTP/1.1\r\nHost: x\r\n"
        "Content-Type: application/json\r\n\r\n"
        '{"username": {"$ne": null}, "password": {"$ne": null}}'
    )
    fs = run_extras(req, resp, "https://x/api/users")
    for f in fs:
        print(f["type"], "-", f["detail"][:80])
    print("owasp_extras.py smoke test ok -", len(fs), "findings")
