"""
Payload recommender.

Combines:
  - llm_bridge.payloads   (stack-aware payload library)
  - llm_bridge.surface    (attack-surface graph built from session findings)
  - storage.db            (the findings themselves)

Produces a ranked list of (payload, target_url, target_param, rationale,
lateral_targets, tech_context, risk, impact, confidence) tuples that the
operator can run next.

Two sources of recommendations:
  1. EVIDENCE-DRIVEN - for every existing finding, suggest stronger
     variants of the same vuln class and lateral targets where the same
     payload would likely work.
  2. SURFACE-DRIVEN - for endpoints we have seen but have no finding on,
     suggest benign confirmation payloads based on parameter-name hints
     (id -> SQLi probe, url -> SSRF probe, etc.).

Intrusive payloads are filtered out unless config.recommender.intrusive=true.
"""
from __future__ import annotations

from typing import Any
from urllib.parse import quote_plus

from .config import configure_logging, load_config
from . import payloads as _payloads
from . import surface as _surface
from storage import db

_log = configure_logging()


_CONF_BOOST = {"confirmed": 1.0, "likely": 0.85, "possible": 0.65}


def _intrusive_allowed() -> bool:
    cfg = load_config().get("recommender", {})
    return bool(cfg.get("intrusive", False))


def _delivery(method: str, base_url: str, param: str | None, payload: str) -> dict[str, str]:
    """Build a copy-pasteable curl + raw-request for the operator."""
    if not param:
        target = base_url
    elif "?" in base_url:
        # Replace value if param already present in the query string.
        from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
        u = urlparse(base_url)
        pairs = parse_qsl(u.query, keep_blank_values=True)
        pairs = [(k, payload if k == param else v) for k, v in pairs]
        if param not in [k for k, _ in pairs]:
            pairs.append((param, payload))
        target = urlunparse(u._replace(query=urlencode(pairs, quote_via=quote_plus)))
    else:
        target = f"{base_url}?{param}={quote_plus(payload)}"
    raw = f"{method} {target} HTTP/1.1\r\nHost: {target.split('/')[2]}\r\n\r\n"
    return {
        "method": method,
        "target_url": target,
        "as_curl": f"curl -i -X {method} {target!r}",
        "as_raw_http": raw,
    }


def _score(*, payload: dict, finding_confidence: str | None, tech_match: bool) -> float:
    """Likelihood × impact scoring. Higher = better candidate."""
    impact = float(payload.get("base_cvss") or 5.0)
    conf = _CONF_BOOST.get(str(finding_confidence or "possible"), 0.7)
    tech_factor = 1.0 if tech_match else 0.7
    # Normalise to roughly 0-100 for human readability.
    return round(impact * conf * tech_factor * 10.0, 1)


# ---------------------------------------------------------------------------
# Evidence-driven (a known finding -> better payloads + lateral targets)
# ---------------------------------------------------------------------------


def _from_findings(*, rows: list[dict], graph: dict, intrusive: bool) -> list[dict]:
    """For each finding, pick payloads that match its vuln class + tech."""
    out: list[dict] = []
    for row in rows:
        host = _surface.host_of(row.get("url") or "")
        host_info = (graph.get("hosts") or {}).get(host, {})
        host_tech = host_info.get("tech") or {"db": [], "language": []}
        for sub in (row.get("findings") or []):
            vclass = sub.get("type")
            param = sub.get("parameter")
            method = (row.get("method") or "GET").upper()
            base_url = row.get("url") or ""
            # Try every DB/language combination derived from fingerprint.
            picked: list[dict] = []
            db_options = host_tech["db"] or [None]
            lang_options = host_tech["language"] or [None]
            for d in db_options:
                for lang in lang_options:
                    picked.extend(_payloads.filter_payloads(
                        vuln_class=str(vclass),
                        db=d,
                        language=lang,
                        context="query_param",
                        intrusive_allowed=intrusive,
                    ))
            # Dedup by payload string.
            seen: set[str] = set()
            unique = []
            for p in picked:
                if p["payload"] in seen:
                    continue
                seen.add(p["payload"])
                unique.append(p)
            # Top 3 per finding to keep the report digestible.
            for p in unique[:3]:
                tech_match = bool(p.get("db") or p.get("language"))
                lateral = _surface.lateral_targets(
                    graph, host, param,
                    exclude_shape=_surface.shape(base_url), limit=5,
                )
                out.append({
                    "vuln_class": str(vclass),
                    "payload_name": p["name"],
                    "payload": p["payload"],
                    "rationale": (
                        f"Existing {vclass} finding on parameter '{param}' "
                        f"(confidence: {sub.get('confidence', '?')}). "
                        + (f"Stack matches: {p['db'] or p['language']}. "
                           if (p["db"] or p["language"]) else "")
                        + f"Expected signal: {p['expected_signal']}."
                    ),
                    "lateral_targets": lateral,
                    "tech_context": {
                        "db": host_tech["db"],
                        "language": host_tech["language"],
                    },
                    "risk_class": p["risk"],
                    "estimated_impact_cvss": p["base_cvss"],
                    "score": _score(payload=p,
                                    finding_confidence=sub.get("confidence"),
                                    tech_match=tech_match),
                    "delivery": _delivery(method, base_url, param, p["payload"]),
                    "source_finding_id": row.get("id"),
                })
    return out


# ---------------------------------------------------------------------------
# Surface-driven (no finding yet -> param-name -> starter probes)
# ---------------------------------------------------------------------------


def _from_surface(*, graph: dict, intrusive: bool, rows: list[dict]) -> list[dict]:
    """For endpoints without findings, use param-name hints for starter probes."""
    out: list[dict] = []
    finding_param_pairs: set[tuple[str, str]] = set()
    for row in rows:
        s = _surface.shape(row.get("url") or "")
        for sub in row.get("findings") or []:
            if sub.get("parameter"):
                finding_param_pairs.add((s, str(sub["parameter"])))

    for host, host_info in (graph.get("hosts") or {}).items():
        host_tech = host_info.get("tech") or {"db": [], "language": []}
        for ep in host_info.get("endpoints", []):
            for param in ep.get("params", []):
                if (ep["shape"], param) in finding_param_pairs:
                    continue  # already has a finding -> evidence-driven handled it
                guesses = _payloads.PARAM_HINTS.get(param.lower(), [])
                for vclass in guesses:
                    candidates = _payloads.filter_payloads(
                        vuln_class=vclass, context="query_param",
                        intrusive_allowed=intrusive,
                    )
                    if not candidates:
                        continue
                    # Use the first benign payload (cheapest confirmation probe).
                    p = candidates[0]
                    out.append({
                        "vuln_class": vclass,
                        "payload_name": p["name"],
                        "payload": p["payload"],
                        "rationale": (
                            f"Parameter name '{param}' is a typical {vclass} vector; "
                            f"no finding here yet. Probe: {p['expected_signal']}."
                        ),
                        "lateral_targets": [],
                        "tech_context": {
                            "db": host_tech["db"],
                            "language": host_tech["language"],
                        },
                        "risk_class": p["risk"],
                        "estimated_impact_cvss": p["base_cvss"],
                        "score": _score(payload=p, finding_confidence="possible",
                                        tech_match=False),
                        "delivery": _delivery("GET", ep["example_url"], param, p["payload"]),
                        "source_finding_id": None,
                    })
                    break  # one suggestion per (endpoint, param)
    return out


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def recommend(*, host: str | None = None, vuln_class: str | None = None,
              limit: int = 25) -> dict:
    """
    Build a ranked list of payload recommendations for the current session.

    Filters:
      host:       limit to one hostname
      vuln_class: limit to one finding type ("SQLi" / "XSS" / ...)
      limit:      cap on results returned (defaults 25)
    """
    rows = db.list_current_findings()
    if host:
        from urllib.parse import urlparse
        rows = [r for r in rows if urlparse(r.get("url") or "").hostname == host]
    graph = _surface.build(rows)

    intrusive = _intrusive_allowed()
    recs = _from_findings(rows=rows, graph=graph, intrusive=intrusive) \
         + _from_surface(graph=graph, intrusive=intrusive, rows=rows)

    if vuln_class:
        recs = [r for r in recs if r["vuln_class"] == vuln_class]

    # Sort by score desc, then by vuln class for stable output.
    recs.sort(key=lambda r: (-r["score"], r["vuln_class"]))
    recs = recs[:max(1, int(limit))]
    return {
        "host": host,
        "vuln_class": vuln_class,
        "intrusive_enabled": intrusive,
        "examined_findings": len(rows),
        "examined_endpoints": graph.get("total_endpoints", 0),
        "recommendations": recs,
    }


if __name__ == "__main__":
    out = recommend(limit=3)
    print(f"recommender.py smoke test ok: {len(out['recommendations'])} recs")
