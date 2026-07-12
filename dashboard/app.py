"""
Argus live-findings dashboard (Streamlit).

Security intent: give the operator a single, local-only pane of glass onto
the current engagement. Talks exclusively to the local bridge on
127.0.0.1 (or the configured bridge_host when running under docker-compose),
sends the X-Argus-Token shared secret, and uses a single /state endpoint
per refresh to keep network chatter and UI jitter minimal.
"""
from __future__ import annotations

import io
import json
import sys
import time
from pathlib import Path
from typing import Any

import httpx
import pandas as pd
import streamlit as st

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


@st.cache_data(ttl=30)
def _load_config():
    # Delegate to llm_bridge.config.load_config so the env overlay
    # (OLLAMA_URL, ARGUS_TOKEN, BRIDGE_HOST, BRIDGE_PORT, ...) applies here
    # too. Otherwise docker-compose can set env vars for the dashboard
    # container that would be silently ignored.
    from llm_bridge.config import load_config
    return load_config()


def _bridge_base():
    cfg = _load_config()
    return f"http://{cfg.get('bridge_host', '127.0.0.1')}:{cfg.get('bridge_port', 8765)}"


def _headers():
    cfg = _load_config().get("auth", {})
    if cfg.get("enabled") and cfg.get("token"):
        return {"X-Argus-Token": str(cfg["token"])}
    return {}


def _get(path, *, text=False):
    try:
        r = httpx.get(_bridge_base() + path, headers=_headers(), timeout=10.0)
        r.raise_for_status()
        return r.text if text else r.json()
    except Exception as exc:
        st.session_state["last_error"] = f"GET {path}: {exc}"
        return None


def _post(path, json_body=None):
    try:
        r = httpx.post(_bridge_base() + path, headers=_headers(),
                       json=json_body, timeout=60.0)
        r.raise_for_status()
        return r.json()
    except Exception as exc:
        st.session_state["last_error"] = f"POST {path}: {exc}"
        return None


RISK_COLOURS = {
    "critical": "#8B0000",
    "high":     "#D7263D",
    "medium":   "#F46036",
    "low":      "#F2C14E",
    "none":     "#6C757D",
}

SOURCE_ICONS = {
    "detector":     "det",
    "llm":          "llm",
    "llm+critique": "llm+",
    "diff":         "diff",
    "probe":        "probe",
}


def _dot(ok):
    return "OK" if ok else "X"


def _truncate(text, n=80):
    if text is None:
        return ""
    text = str(text).replace("\n", " ")
    return text if len(text) <= n else text[: n - 1] + "..."


def _flatten(findings):
    rows = []
    for entry in findings:
        detail_list = entry.get("findings") or []
        common = {
            "id": entry.get("id"),
            "timestamp": entry.get("timestamp"),
            "risk": entry.get("risk"),
            "url": entry.get("url"),
            "method": entry.get("method"),
            "status": entry.get("status_code"),
            "owasp": entry.get("owasp_category"),
            "cwe": entry.get("cwe"),
            "cvss": entry.get("cvss"),
            "source": entry.get("source"),
            "occurrences": entry.get("occurrences", 1),
            "follow_up": entry.get("follow_up"),
            "recommend": entry.get("recommend") or [],
        }
        if not detail_list:
            rows.append({**common, "type": None, "confidence": None,
                         "parameter": None, "evidence": None})
            continue
        for f in detail_list:
            rows.append({**common, "type": f.get("type"),
                         "confidence": f.get("confidence"),
                         "parameter": f.get("parameter"),
                         "evidence": f.get("evidence")})
    return pd.DataFrame(rows)


st.set_page_config(page_title="Argus - Local LLM Pentest", layout="wide")
cfg = _load_config()

state = _get("/state") or {}
health = state.get("health") or {}
summary = state.get("summary") or {"by_risk": {}, "by_owasp": {}, "total": 0, "session_id": "-"}
raw_findings = state.get("findings") or []
metrics_snapshot = state.get("metrics") or {}

with st.sidebar:
    st.title("Argus")
    st.caption("Local LLM-assisted pentest triage")

    st.subheader("Model")
    st.code(cfg.get("model", "?"), language="text")
    st.caption(f"Ollama: {cfg.get('ollama_url', '?')}")
    st.caption(f"Rate limit: {cfg.get('rate_limit_per_minute', '?')}/min")
    if cfg.get("router", {}).get("enabled"):
        st.caption(
            f"Router: code={cfg['router'].get('code','-')}  "
            f"auth={cfg['router'].get('auth','-')}  "
            f"general={cfg['router'].get('general','-')}"
        )

    st.subheader("Health")
    st.write(f"{_dot(bool(health.get('ollama')))} Ollama")
    st.write(f"{_dot(bool(health.get('chroma')))} ChromaDB")
    st.write(f"{_dot(bool(health.get('db')))} SQLite")
    st.write(f"{_dot(bool(health.get('cache')))} LLM cache")

    st.subheader("Metrics")
    if metrics_snapshot:
        st.caption(f"LLM calls: {metrics_snapshot.get('llm_calls', 0)}  "
                   f"(fails {metrics_snapshot.get('llm_failures', 0)})")
        st.caption(f"Cache: {metrics_snapshot.get('cache_hits', 0)} hit / "
                   f"{metrics_snapshot.get('cache_misses', 0)} miss")
        p50 = metrics_snapshot.get("llm_latency_p50_ms")
        p95 = metrics_snapshot.get("llm_latency_p95_ms")
        if p50 is not None:
            st.caption(f"LLM p50/p95: {p50} / {p95} ms")
        st.caption(
            f"Filter kept/drop: {metrics_snapshot.get('filter_kept', 0)} / "
            f"{metrics_snapshot.get('filter_dropped', 0)}"
        )
        st.caption(f"Dedup collapsed: {metrics_snapshot.get('dedup_collapsed', 0)}")
        if metrics_snapshot.get("probes_issued"):
            st.caption(f"Probes issued: {metrics_snapshot['probes_issued']}")

    st.subheader("Session")
    st.caption(f"ID: {summary.get('session_id', '-')}")
    if st.button("Clear session", type="primary"):
        res = _post("/session/clear")
        if res:
            st.success(f"New session: {res.get('new_session')}")
        st.rerun()

    if st.button("Generate Markdown report"):
        md = _get("/session/report", text=True)
        if md:
            st.session_state["report_md"] = md
            st.success("Report generated - scroll down")

    refresh = st.slider("Auto-refresh (seconds)", 0, 30, 5)

st.title("Findings")
by_risk = summary.get("by_risk", {})
c1, c2, c3, c4, c5 = st.columns(5)
c1.metric("Critical", by_risk.get("critical", 0))
c2.metric("High", by_risk.get("high", 0))
c3.metric("Medium", by_risk.get("medium", 0))
c4.metric("Low", by_risk.get("low", 0))
c5.metric("Total", summary.get("total", 0))

df = _flatten(raw_findings)

if df.empty:
    st.info("No findings yet - send some traffic through Burp.")
else:
    fcol1, fcol2, fcol3, fcol4 = st.columns([1, 1, 1, 2])
    risks = sorted(df["risk"].dropna().unique().tolist())
    owasps = sorted([o for o in df["owasp"].dropna().unique().tolist() if o])
    sources = sorted(df["source"].dropna().unique().tolist())
    pick_risks = fcol1.multiselect("Risk", risks, default=risks)
    pick_owasps = fcol2.multiselect("OWASP", owasps, default=owasps)
    pick_sources = fcol3.multiselect("Source", sources, default=sources)
    search = fcol4.text_input("Search URL / evidence / type / CWE", "")

    view = df.copy()
    if pick_risks:
        view = view[view["risk"].isin(pick_risks)]
    if pick_owasps:
        view = view[view["owasp"].isin(pick_owasps)]
    if pick_sources:
        view = view[view["source"].isin(pick_sources)]
    if search:
        s = search.lower()
        view = view[
            view["url"].str.lower().str.contains(s, na=False)
            | view["type"].fillna("").str.lower().str.contains(s, na=False)
            | view["evidence"].fillna("").str.lower().str.contains(s, na=False)
            | view["cwe"].fillna("").str.lower().str.contains(s, na=False)
        ]

    view_display = view.copy()
    view_display["evidence"] = view_display["evidence"].apply(lambda x: _truncate(x, 120))
    view_display["follow_up"] = view_display["follow_up"].apply(lambda x: _truncate(x, 120))
    view_display["src"] = view_display["source"].map(lambda s: SOURCE_ICONS.get(s, s or "?"))
    view_display["occ"] = view_display["occurrences"].fillna(1).astype(int)

    column_config = {
        "timestamp": st.column_config.TextColumn("Time", width="small"),
        "risk": st.column_config.TextColumn("Risk", width="small"),
        "src": st.column_config.TextColumn("src", width="small",
                                           help="det detector / llm LLM / llm+ critiqued / diff / probe"),
        "occ": st.column_config.NumberColumn("x", width="small",
                                             help="occurrences (dedup count)"),
        "url": st.column_config.TextColumn("URL", width="large"),
        "method": st.column_config.TextColumn("M", width="small"),
        "status": st.column_config.NumberColumn("Status", width="small"),
        "owasp": st.column_config.TextColumn("OWASP", width="medium"),
        "cwe": st.column_config.TextColumn("CWE", width="small"),
        "cvss": st.column_config.NumberColumn("CVSS", width="small", format="%.1f"),
        "type": st.column_config.TextColumn("Type", width="small"),
        "confidence": st.column_config.TextColumn("Conf.", width="small"),
        "parameter": st.column_config.TextColumn("Param", width="small"),
        "evidence": st.column_config.TextColumn("Evidence", width="large"),
        "follow_up": st.column_config.TextColumn("Follow-up", width="medium"),
    }

    st.dataframe(
        view_display.drop(columns=["recommend", "source", "occurrences", "id"]),
        use_container_width=True,
        hide_index=True,
        column_config=column_config,
    )

    csv_buf = io.StringIO()
    export = view.copy()
    export["recommend"] = export["recommend"].apply(
        lambda lst: " | ".join(lst) if lst else ""
    )
    export.to_csv(csv_buf, index=False)
    st.download_button(
        "Download session findings (CSV)",
        data=csv_buf.getvalue(),
        file_name="argus_findings.csv",
        mime="text/csv",
    )

    st.subheader("Details")
    row_ids = view["id"].dropna().unique().tolist()
    if row_ids:
        pick = st.selectbox("Expand finding by id", row_ids)
        entry = next((e for e in raw_findings if e.get("id") == pick), None)
        if entry:
            colour = RISK_COLOURS.get(entry.get("risk", "none"), "#6C757D")
            st.markdown(
                f"<div style='padding:8px;border-left:6px solid {colour};'>"
                f"<b>{entry.get('risk', '?').upper()}</b> - {entry.get('url', '')}"
                f" | {entry.get('owasp_category') or '-'}"
                f" | CWE {entry.get('cwe') or '-'}"
                f" | CVSS {entry.get('cvss') or '-'}"
                f" | source {entry.get('source') or '-'}"
                f" | x{entry.get('occurrences', 1)}"
                f"</div>",
                unsafe_allow_html=True,
            )
            st.write("**Follow-up:**", entry.get("follow_up") or "-")
            st.write("**Recommendations:**")
            for r in entry.get("recommend") or []:
                st.write(f"- {r}")
            st.write("**Findings:**")
            for f in entry.get("findings") or []:
                with st.expander(
                    f"{f.get('type', '?')}  |  {f.get('confidence', '?')}"
                    f"  |  src={f.get('source', '?')}"
                    f"  |  param={f.get('parameter') or '-'}"
                ):
                    st.code(f.get("evidence", ""), language="text")
                    st.write(f.get("detail", ""))
            st.download_button(
                "Download finding JSON",
                data=json.dumps(entry, indent=2),
                file_name=f"argus_finding_{entry.get('id')}.json",
                mime="application/json",
            )

            col_poc, col_probe = st.columns(2)
            with col_poc:
                if st.button("Generate PoC (curl)"):
                    poc = _post("/poc", {"finding_id": entry.get("id"), "style": "curl"})
                    if poc:
                        st.code(poc.get("poc", ""), language="bash")
            with col_probe:
                if cfg.get("agentic", {}).get("enabled"):
                    if st.button("Run follow-up probes"):
                        r = _post("/probe", {"finding_id": entry.get("id")})
                        if r:
                            st.json(r)
                else:
                    st.caption("Probes disabled (config.agentic.enabled=false)")

if "report_md" in st.session_state:
    st.subheader("Engagement report")
    st.download_button(
        "Download report.md",
        data=st.session_state["report_md"],
        file_name="argus_report.md",
        mime="text/markdown",
    )
    with st.expander("Preview", expanded=True):
        st.markdown(st.session_state["report_md"])

if refresh > 0:
    time.sleep(refresh)
    st.rerun()
