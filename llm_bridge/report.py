"""
Engagement report generation.

Security intent: take everything Argus has accumulated for a session and
hand the operator a self-contained Markdown report — executive summary
followed by a per-finding write-up. The LLM is used ONLY to write the
narrative; the structured findings table is built deterministically from
the SQLite store so the model cannot drop or invent rows.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Callable

from .config import configure_logging, load_config

_log = configure_logging()

_REPORT_SYSTEM = """\
You are writing the executive summary of a web application pentest. You
will be given a JSON list of validated findings and must produce ONE
short Markdown section titled '## Executive summary'. Stick to the
findings provided — do not invent details. 4-8 sentences. No bullet
points. No tables.
"""


def _exec_summary(findings: list[dict], call_model: Callable[[str, str, str], str]) -> str:
    if not findings:
        return "## Executive summary\n\nNo findings recorded for this session."
    cfg = load_config()
    model = cfg.get("report", {}).get("model") or cfg["model"]
    summary_input = json.dumps(
        [{
            "risk": f.get("risk"),
            "owasp": f.get("owasp_category"),
            "url": f.get("url"),
            "type": (f.get("findings") or [{}])[0].get("type"),
            "detail": (f.get("findings") or [{}])[0].get("detail"),
        } for f in findings[:50]],
        ensure_ascii=False,
    )
    try:
        out = call_model(model, _REPORT_SYSTEM, summary_input) or ""
    except Exception as exc:
        _log.warning("report: exec summary call failed: %s", exc)
        out = ""
    if "## Executive summary" not in out:
        out = "## Executive summary\n\n" + out.strip()
    return out.strip()


def _format_finding(f: dict) -> str:
    """Render one DB row as a Markdown subsection."""
    head = (
        f"### [{f.get('risk', '?').upper()}] {f.get('url', '?')}\n"
        f"- **OWASP:** {f.get('owasp_category') or '-'}\n"
        f"- **CWE:** {f.get('cwe') or '-'}  •  **CVSS:** {f.get('cvss') if f.get('cvss') is not None else '-'}\n"
        f"- **Source:** {f.get('source', 'llm')}  •  **Occurrences:** {f.get('occurrences', 1)}\n"
        f"- **Method/Status:** {f.get('method') or '-'} / {f.get('status_code') or '-'}\n"
        f"- **Time:** {f.get('timestamp')}\n"
    )
    body_parts = []
    for sub in f.get("findings") or []:
        body_parts.append(
            f"- **{sub.get('type', '?')}** "
            f"(confidence: {sub.get('confidence', '?')})  \n"
            f"  parameter: `{sub.get('parameter') or '-'}`  \n"
            f"  detail: {sub.get('detail', '')}  \n"
            f"  evidence:\n  ```\n  {str(sub.get('evidence', ''))[:600]}\n  ```"
        )
    body = "\n".join(body_parts) if body_parts else "_(no sub-findings)_"
    recs = f.get("recommend") or []
    rec_block = "\n".join(f"- {r}" for r in recs) if recs else "_(none provided)_"
    follow = f.get("follow_up") or "_(none)_"
    return (
        head + "\n**Findings:**\n\n" + body
        + "\n\n**Recommendations:**\n" + rec_block
        + "\n\n**Follow-up:** " + str(follow) + "\n"
    )


def render(*, session_id: str, findings: list[dict],
           call_model: Callable[[str, str, str], str]) -> str:
    """Return a complete Markdown report for `session_id`."""
    now = datetime.now(timezone.utc).isoformat()
    by_risk: dict[str, int] = {}
    for f in findings:
        by_risk[f.get("risk", "?")] = by_risk.get(f.get("risk", "?"), 0) + 1
    counts_line = ", ".join(f"{k}: {v}" for k, v in by_risk.items()) or "none"

    stats = _session_stats(findings)
    try:
        from . import metrics
        snap = metrics.snapshot()
    except Exception:
        snap = {}
    analysed = snap.get("requests_total", "-")
    kept = snap.get("filter_kept", "-")
    dropped = snap.get("filter_dropped", "-")

    summary = _exec_summary(findings, call_model)
    parts = [
        f"# Argus engagement report",
        f"_Session `{session_id}` • generated {now}_\n",
        f"**Target:** `{stats['target']}`  ",
        f"**Started:** {stats['started'] or '-'}  ",
        f"**Duration:** {stats['duration']}\n",
        f"**Requests analysed:** {analysed}  ",
        f"**Pre-filter kept:** {kept}  ",
        f"**Pre-filter dropped:** {dropped}\n",
        f"**Total findings:** {len(findings)}  \n**By risk:** {counts_line}\n",
        summary,
        "\n## Findings\n",
    ]
    for f in findings:
        parts.append(_format_finding(f))
    return "\n".join(parts)


def _session_stats(findings: list[dict]) -> dict:
    """Pull target / duration stats from the session's findings."""
    from collections import Counter
    from urllib.parse import urlparse
    hosts = Counter(urlparse(f.get("url") or "").hostname for f in findings if f.get("url"))
    hosts.pop(None, None)
    target = hosts.most_common(1)[0][0] if hosts else "(no host)"
    timestamps = sorted(f.get("timestamp") for f in findings if f.get("timestamp"))
    duration = "-"
    started = ""
    if timestamps:
        try:
            t0 = datetime.fromisoformat(str(timestamps[0]).replace("Z", "+00:00"))
            t1 = datetime.fromisoformat(str(timestamps[-1]).replace("Z", "+00:00"))
            delta = t1 - t0
            total_min = int(delta.total_seconds() // 60)
            duration = "%dh %02dm" % (total_min // 60, total_min % 60)
            started = t0.isoformat()
        except Exception:
            pass
    return {"target": target, "started": started, "duration": duration}


if __name__ == "__main__":
    def stub(model, system, user):
        return "Some prose about the engagement."
    md = render(session_id="abc", findings=[
        {"id": 1, "risk": "high", "url": "https://x/api/users",
         "owasp_category": "A01:2021-Broken Access Control",
         "cwe": "CWE-285", "cvss": 7.5, "source": "llm",
         "method": "GET", "status_code": 200, "timestamp": "2026-04-19T00:00:00Z",
         "findings": [{"type": "IDOR", "confidence": "likely", "parameter": "id", "evidence": "user 2 returned", "detail": "horizontal access"}],
         "recommend": ["Authorise on user_id"], "follow_up": "Try admin id"}],
        call_model=stub)
    assert "Executive summary" in md and "IDOR" in md
    print("report.py smoke test ok")
