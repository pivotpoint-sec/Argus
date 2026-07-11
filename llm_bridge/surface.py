"""
Attack-surface mapper.

Reads SQLite findings for the current session and builds a per-host graph
of endpoints, parameters, response shape hints, and fingerprinted
technology. The recommender uses this graph to (a) decide which payloads
fit the stack, and (b) propose lateral targets where a finding on one
endpoint is likely to apply to another.

Pure-Python, no LLM, no network.
"""
from __future__ import annotations

import re
from collections import defaultdict
from typing import Any
from urllib.parse import urlparse, parse_qsl

from .config import configure_logging

_log = configure_logging()


# ---------------------------------------------------------------------------
# URL shape helpers
# ---------------------------------------------------------------------------

_RE_NUMERIC_SEG = re.compile(r"/(\d+)(?=/|$|\?)")
_RE_UUID_SEG = re.compile(
    r"/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?=/|$|\?)",
    re.IGNORECASE,
)


def shape(url: str) -> str:
    """Collapse numeric / UUID path segments so sibling URLs share a key."""
    p = urlparse(url)
    path = p.path
    path = _RE_UUID_SEG.sub("/{UUID}", path)
    path = _RE_NUMERIC_SEG.sub("/{N}", path)
    return f"{p.scheme}://{p.hostname or '?'}{path or '/'}"


def host_of(url: str) -> str:
    return urlparse(url).hostname or "?"


# ---------------------------------------------------------------------------
# Fingerprint extraction from "Vulnerable component" detector findings.
# ---------------------------------------------------------------------------

_DB_HINTS = {
    "mysql":      ("mysql", "mariadb", "phpmyadmin"),
    "postgresql": ("postgresql", "postgres", "psycopg"),
    "mssql":      ("mssql", "sql server", "sqlsrv"),
    "oracle":     ("oracle", "ora-"),
    "sqlite":     ("sqlite",),
    "mongodb":    ("mongodb", "mongo"),
}

_LANG_HINTS = {
    "php":    ("php/", "phpsessid", "x-powered-by: php", "laravel", "wordpress", "drupal", "joomla"),
    "java":   ("jboss", "jsessionid", "tomcat", "jetty", "wildfly", "spring", "struts", "weblogic"),
    "python": ("python/", "django", "flask", "gunicorn", "werkzeug"),
    "dotnet": ("asp.net", "x-aspnet-version", "x-aspnetmvc-version", "iis/"),
    "node":   ("connect.sid", "express", "x-powered-by: express"),
    "ruby":   ("_session_id", "rails", "phusion passenger"),
    "go":     ("go-http-client",),
}


def _tech_from_evidence(rows: list[dict]) -> dict[str, set[str]]:
    """Walk findings, harvest tech tokens from evidence + detail strings."""
    found_db: set[str] = set()
    found_lang: set[str] = set()
    for r in rows:
        for sub in r.get("findings") or []:
            blob = ((sub.get("evidence") or "") + " " + (sub.get("detail") or "")).lower()
            for db, hints in _DB_HINTS.items():
                if any(h in blob for h in hints):
                    found_db.add(db)
            for lang, hints in _LANG_HINTS.items():
                if any(h in blob for h in hints):
                    found_lang.add(lang)
    return {"db": found_db, "language": found_lang}


# ---------------------------------------------------------------------------
# Per-endpoint inventory
# ---------------------------------------------------------------------------


def _endpoint_record(rows: list[dict], url_shape: str) -> dict[str, Any]:
    """All rows that share `url_shape` -> aggregate metadata."""
    matching = [r for r in rows if shape(r.get("url", "")) == url_shape]
    params: set[str] = set()
    methods: set[str] = set()
    statuses: set[int] = set()
    has_json = False
    has_html = False
    has_xml = False
    for r in matching:
        for k, _v in parse_qsl(urlparse(r.get("url", "")).query, keep_blank_values=True):
            params.add(k)
        if r.get("method"):
            methods.add(str(r["method"]).upper())
        if r.get("status_code"):
            try:
                statuses.add(int(r["status_code"]))
            except Exception:
                pass
        for sub in r.get("findings") or []:
            if sub.get("parameter"):
                params.add(str(sub["parameter"]))
            ev = (sub.get("evidence") or "") + " " + (sub.get("detail") or "")
            evl = ev.lower()
            if "application/json" in evl or "json" in evl:
                has_json = True
            if "<html" in evl or "text/html" in evl:
                has_html = True
            if "<?xml" in evl or "application/xml" in evl:
                has_xml = True

    finding_types: set[str] = set()
    for r in matching:
        for sub in r.get("findings") or []:
            t = sub.get("type")
            if t:
                finding_types.add(str(t))

    return {
        "shape": url_shape,
        "example_url": matching[0].get("url") if matching else url_shape,
        "params": sorted(params),
        "methods": sorted(methods),
        "statuses": sorted(statuses),
        "response_shape": (
            "json" if has_json else "html" if has_html else "xml" if has_xml else "unknown"
        ),
        "finding_types": sorted(finding_types),
        "row_ids": [r["id"] for r in matching if "id" in r],
    }


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def build(rows: list[dict]) -> dict[str, Any]:
    """
    Return the attack surface graph for these findings.

    Output shape:
        {
          "hosts": {
            "target.example.com": {
              "tech": {"db": {"mysql"}, "language": {"php"}},
              "endpoints": [
                {"shape": "...", "params": [...], "methods": [...], ...},
                ...
              ],
            },
          },
          "total_endpoints": N,
          "total_hosts": M,
        }
    """
    by_host: dict[str, list[dict]] = defaultdict(list)
    for r in rows:
        by_host[host_of(r.get("url", ""))].append(r)

    hosts: dict[str, Any] = {}
    total_endpoints = 0
    for host, host_rows in by_host.items():
        if host == "?":
            continue
        shapes = sorted({shape(r.get("url", "")) for r in host_rows if r.get("url")})
        endpoints = [_endpoint_record(host_rows, s) for s in shapes]
        tech = _tech_from_evidence(host_rows)
        hosts[host] = {
            "tech": {k: sorted(v) for k, v in tech.items()},
            "endpoints": endpoints,
        }
        total_endpoints += len(endpoints)

    return {
        "hosts": hosts,
        "total_hosts": len(hosts),
        "total_endpoints": total_endpoints,
    }


def lateral_targets(graph: dict, host: str, param_name: str | None,
                    exclude_shape: str | None = None, limit: int = 8) -> list[str]:
    """
    Find other endpoints on `host` that take the same parameter name.
    Returns example URLs (one per endpoint shape), excluding `exclude_shape`.
    """
    host_info = (graph.get("hosts") or {}).get(host)
    if not host_info:
        return []
    out: list[str] = []
    for ep in host_info["endpoints"]:
        if exclude_shape and ep["shape"] == exclude_shape:
            continue
        if param_name is None or param_name in ep["params"]:
            out.append(ep["example_url"])
            if len(out) >= limit:
                break
    return out


if __name__ == "__main__":
    sample_rows = [
        {"id": 1, "url": "https://x/api/users?id=1", "method": "GET", "status_code": 200,
         "findings": [{"type": "SQLi", "parameter": "id", "evidence": "MySQL syntax error",
                       "detail": "boolean OR", "confidence": "likely", "source": "llm",
                       "cwe": "CWE-89", "cvss": 7.5}]},
        {"id": 2, "url": "https://x/api/users?id=9999", "method": "GET", "status_code": 200,
         "findings": [{"type": "Vulnerable component", "evidence": "Server: nginx/1.14.0; X-Powered-By: PHP/7.2.34",
                       "detail": "fingerprint", "confidence": "confirmed", "source": "detector",
                       "cwe": "CWE-200", "cvss": 3.7}]},
        {"id": 3, "url": "https://x/api/orders?id=42", "method": "GET", "status_code": 200,
         "findings": []},
    ]
    g = build(sample_rows)
    assert g["total_hosts"] == 1
    assert g["total_endpoints"] == 2  # /api/users/{N} and /api/orders/{N}
    assert "mysql" in g["hosts"]["x"]["tech"]["db"]
    assert "php" in g["hosts"]["x"]["tech"]["language"]
    lat = lateral_targets(g, "x", "id", exclude_shape="https://x/api/users")
    print("lateral targets for `id` on host x:", lat)
    print("surface.py smoke test ok")
