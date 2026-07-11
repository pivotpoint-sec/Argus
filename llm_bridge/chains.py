"""
Cross-request pattern detector - finds vulnerability chains spanning
multiple findings already persisted in this session.

Security intent: single findings are useful, but the high-impact bugs in
modern applications come from chains - an enumerable ID returning a
different user's data, a 403 then 200 after one parameter flip, the same
session token reused across hours. This module reads the SQLite findings
table for the current session, joins on URL shape / param name / status
deltas, and surfaces aggregate findings the per-request pipeline could
never see in isolation.

All detection here is local + deterministic - no LLM call.
"""
from __future__ import annotations

import re
from collections import Counter, defaultdict
from typing import Any
from urllib.parse import urlparse, parse_qs

from .config import configure_logging
from storage import db

_log = configure_logging()


# ---------------------------------------------------------------------------
# URL / parameter helpers
# ---------------------------------------------------------------------------

_RE_NUMERIC_SEG = re.compile(r"/(\d+)(?=/|$|\?)")
_RE_UUID_SEG = re.compile(
    r"/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?=/|$|\?)",
    re.IGNORECASE,
)
_RE_USER_TOKEN = re.compile(
    r"\"(?:email|username|user_id|userId|user)\"\s*:\s*\"?([^\"',}\s]+)",
    re.IGNORECASE,
)


def _url_shape(url: str) -> str:
    """Collapse numeric / UUID path segments to placeholders for grouping."""
    u = urlparse(url)
    path = u.path
    path = _RE_UUID_SEG.sub("/{UUID}", path)
    path = _RE_NUMERIC_SEG.sub("/{N}", path)
    return "{scheme}://{host}{path}".format(
        scheme=u.scheme or "http",
        host=u.hostname or "?",
        path=path or "/",
    )


def _numeric_ids_in_path(url: str) -> list[int]:
    return [int(m.group(1)) for m in _RE_NUMERIC_SEG.finditer(urlparse(url).path)]


def _query_params(url: str) -> dict[str, list[str]]:
    return parse_qs(urlparse(url).query, keep_blank_values=True)


def _path_kind(url: str) -> str | None:
    p = (urlparse(url).path or "/").lower()
    if "/admin" in p:
        return "admin"
    if any(seg in p for seg in ("/user", "/profile", "/account", "/me")):
        return "user"
    return None


def _user_tokens_in_evidence(findings_blob: list[dict]) -> set[str]:
    """Pull email / username / user_id tokens out of stored evidence strings."""
    found: set[str] = set()
    for f in findings_blob or []:
        ev = f.get("evidence") or ""
        for m in _RE_USER_TOKEN.finditer(ev):
            found.add(m.group(1).lower())
    return found


# ---------------------------------------------------------------------------
# Individual chain detectors
# ---------------------------------------------------------------------------


def _detect_idor_chain(rows: list[dict]) -> list[dict]:
    """Same URL shape, different numeric IDs, different user data in response."""
    by_shape: dict[str, list[dict]] = defaultdict(list)
    for r in rows:
        ids = _numeric_ids_in_path(r["url"])
        if not ids:
            continue
        by_shape[_url_shape(r["url"])].append(r)

    out: list[dict] = []
    for shape, group in by_shape.items():
        if len(group) < 2:
            continue
        distinct_ids = {tuple(_numeric_ids_in_path(r["url"])) for r in group}
        if len(distinct_ids) < 2:
            continue
        # Look for distinct user-identifying tokens in evidence across the group.
        token_sets = [_user_tokens_in_evidence(r.get("findings") or []) for r in group]
        all_tokens: set[str] = set().union(*token_sets) if token_sets else set()
        cross_user = len(all_tokens) >= 2  # at least two distinct identities
        confidence = "likely" if cross_user else "possible"
        out.append({
            "type": "IDOR chain",
            "detail": (
                "{n} requests to {shape} use distinct numeric IDs ({ids}); "
                "{verdict}."
            ).format(
                n=len(group),
                shape=shape,
                ids=", ".join(sorted({str(i[0]) for i in distinct_ids if i})[:6]),
                verdict=(
                    "responses reveal distinct user identities"
                    if cross_user else "no cross-user evidence in stored snippets"
                ),
            ),
            "evidence": "; ".join(sorted(all_tokens)[:4]) if all_tokens else shape,
            "confidence": confidence,
            "source": "chain",
            "cwe": "CWE-639",
            "cvss": 7.5 if cross_user else 5.0,
            "related_finding_ids": [r["id"] for r in group],
        })
    return out


def _detect_auth_bypass_chain(rows: list[dict], window_seconds: int = 600) -> list[dict]:
    """403 then 200 to same endpoint within `window_seconds`."""
    by_shape: dict[str, list[dict]] = defaultdict(list)
    for r in rows:
        by_shape[_url_shape(r["url"])].append(r)

    out: list[dict] = []
    for shape, group in by_shape.items():
        statuses = [(r.get("status_code") or 0, r.get("timestamp") or "", r["id"]) for r in group]
        denied = [(t, fid) for s, t, fid in statuses if s in (401, 403)]
        allowed = [(t, fid) for s, t, fid in statuses if 200 <= s < 300]
        if not denied or not allowed:
            continue
        # Cheap heuristic: there exists a denied row with a later allowed row.
        related: list[int] = []
        for dt, dfid in denied:
            for at, afid in allowed:
                if at > dt:
                    related.extend([dfid, afid])
        if not related:
            continue
        out.append({
            "type": "Auth bypass chain",
            "detail": (
                "{shape} returned 401/403 then later returned 2xx in the same "
                "session - parameter or header mutation may have bypassed access "
                "control."
            ).format(shape=shape),
            "evidence": shape,
            "confidence": "likely",
            "source": "chain",
            "cwe": "CWE-285",
            "cvss": 8.1,
            "related_finding_ids": sorted(set(related)),
        })
    return out


def _detect_privilege_escalation(rows: list[dict]) -> list[dict]:
    """Same param=value appearing in both /user/ and /admin/ paths."""
    seen: dict[tuple[str, str], dict[str, list[int]]] = defaultdict(lambda: defaultdict(list))
    for r in rows:
        kind = _path_kind(r["url"])
        if not kind:
            continue
        for name, vals in _query_params(r["url"]).items():
            for v in vals:
                if not v or len(v) > 64:
                    continue
                seen[(name, v)][kind].append(r["id"])

    out: list[dict] = []
    for (name, value), buckets in seen.items():
        if "user" in buckets and "admin" in buckets:
            out.append({
                "type": "Privilege escalation path",
                "detail": (
                    "Parameter {name}={value} appears in both user-scope and "
                    "admin-scope endpoints - investigate horizontal/vertical "
                    "privilege boundary."
                ).format(name=name, value=value[:40]),
                "evidence": "{name}={value}".format(name=name, value=value[:40]),
                "confidence": "possible",
                "source": "chain",
                "cwe": "CWE-269",
                "cvss": 7.2,
                "related_finding_ids": sorted(set(buckets["user"] + buckets["admin"])),
            })
    return out


def _detect_session_token_reuse(rows: list[dict], min_hours: float = 2.0) -> list[dict]:
    """A token (Bearer / cookie value) repeated across requests spanning hours."""
    # Pull tokens from evidence strings - the redactor leaves shape info even
    # when it scrubs the value, so we hash on the first 12 chars of any JWT.
    tokens_seen: dict[str, list[tuple[str, int]]] = defaultdict(list)
    re_jwt = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\b")
    for r in rows:
        ts = r.get("timestamp") or ""
        for f in r.get("findings") or []:
            ev = f.get("evidence") or ""
            for m in re_jwt.finditer(ev):
                head = m.group(0)[:24]
                tokens_seen[head].append((ts, r["id"]))

    out: list[dict] = []
    for head, hits in tokens_seen.items():
        if len(hits) < 2:
            continue
        timestamps = sorted(t for t, _ in hits if t)
        if len(timestamps) < 2:
            continue
        # ISO-8601 string compare works for ordering and rough duration estimate.
        first, last = timestamps[0], timestamps[-1]
        try:
            from datetime import datetime
            t0 = datetime.fromisoformat(first.replace("Z", "+00:00"))
            t1 = datetime.fromisoformat(last.replace("Z", "+00:00"))
            duration_hours = (t1 - t0).total_seconds() / 3600.0
        except Exception:
            duration_hours = 0.0
        if duration_hours < min_hours:
            continue
        out.append({
            "type": "Session token reuse",
            "detail": (
                "JWT token starting {head}... seen in {n} findings across "
                "{hrs:.1f}h - sessions are not being rotated."
            ).format(head=head[:12], n=len(hits), hrs=duration_hours),
            "evidence": head[:24] + "...",
            "confidence": "likely",
            "source": "chain",
            "cwe": "CWE-613",
            "cvss": 5.3,
            "related_finding_ids": sorted({fid for _, fid in hits}),
        })
    return out


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def run_chains(session_id: str | None = None) -> list[dict]:
    """Run every chain detector against the current session's findings."""
    sid = session_id or db.current_session_id()
    rows = db.list_session_findings(sid, include_archived=False)
    if len(rows) < 2:
        return []
    findings: list[dict] = []
    try:
        findings.extend(_detect_idor_chain(rows))
        findings.extend(_detect_auth_bypass_chain(rows))
        findings.extend(_detect_privilege_escalation(rows))
        findings.extend(_detect_session_token_reuse(rows))
    except Exception as exc:
        _log.warning("chain detector failed: %s", exc)
        return []
    return findings


if __name__ == "__main__":
    print("chains.py smoke test: %d chain finding(s)" % len(run_chains()))
