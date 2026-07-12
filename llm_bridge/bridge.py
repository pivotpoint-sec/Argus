"""
FastAPI bridge that Burp (and anything else local) talks to.

Security intent: one narrow HTTP surface, bound to 127.0.0.1 by default,
behind a shared-secret bearer token, that orchestrates
filter -> detectors -> memory -> LLM -> critique -> persist. Every request
is logged and every stored finding is tied to a session_id, so an operator
can audit or archive the engagement offline.
"""
from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, PlainTextResponse

from storage import db

from . import cache as llm_cache
from . import chains as chain_mod
from . import confirmer as confirmer_mod
from . import filter as prefilter
from . import memory
from . import metrics
from . import probe as probe_mod
from . import redact
from . import report as report_mod
from . import recommender as recommender_mod
from . import sarif as sarif_mod
from .analyser import (
    _call_ollama as ollama_call,
    analyse,
    correlate_findings,
    generate_poc,
    ping_ollama,
    start_ollama_reconnect_poller,
)
from .auth import verify_token
from .config import configure_logging, load_config, validate_startup_config
from .models import (
    AnalyseRequest,
    AnalysisResult,
    BridgeState,
    ConfirmRequest,
    ConfirmResult,
    CorrelateRequest,
    CorrelateResult,
    DiffRequest,
    HealthStatus,
    PocRequest,
    ProbeRequest,
    SummaryCounts,
)

_log = configure_logging()


def _banner():
    cfg = load_config()
    db.get_engine()
    ok_ollama = ping_ollama()
    ok_chroma = memory.ping() if cfg.get("memory", {}).get("enabled", True) else True
    ok_db = db.ping()
    ok_cache = llm_cache.ping()
    router_on = "on" if cfg.get("router", {}).get("enabled") else "off"
    auth_on = "ENFORCED" if cfg.get("auth", {}).get("enabled") else "disabled"
    probe_on = "ENABLED" if cfg.get("agentic", {}).get("enabled") else "off"
    banner = (
        "\n========================================================\n"
        " Argus - local LLM-assisted pentest bridge (v1.1)\n"
        f" model         : {cfg['model']}   (router: {router_on})\n"
        f" ollama        : {'OK' if ok_ollama else 'UNREACHABLE'} ({cfg['ollama_url']})\n"
        f" chromadb      : {'OK' if ok_chroma else 'DISABLED/ERROR'}\n"
        f" sqlite        : {'OK' if ok_db else 'ERROR'}\n"
        f" llm cache     : {'OK' if ok_cache else 'DISABLED/ERROR'}  rows={llm_cache.size()}\n"
        f" auth          : {auth_on}\n"
        f" agentic probe : {probe_on}\n"
        f" session_id    : {db.current_session_id()}\n"
        f" listening     : http://{cfg['bridge_host']}:{cfg['bridge_port']}\n"
        "========================================================\n"
    )
    _log.info(banner)
    print(banner)


@asynccontextmanager
async def _lifespan(app: FastAPI):
    # Fail fast if auth is enforced but the token is missing / weak / default.
    # Runs before the banner so failures show a clear error rather than partial
    # startup output.
    validate_startup_config(load_config())
    _banner()
    # Background ping so the bridge keeps pre-filtering and re-attaches
    # automatically when Ollama comes back up after a restart.
    try:
        start_ollama_reconnect_poller(interval_seconds=30.0)
    except Exception as exc:  # pragma: no cover
        _log.warning("Could not start Ollama poller: %s", exc)
    yield
    _log.info("Argus bridge shutting down.")


app = FastAPI(
    title="Argus LLM Pentest Bridge",
    version="1.1.0",
    description="Local-only LLM-assisted triage for Burp Suite captures.",
    lifespan=_lifespan,
)


@app.middleware("http")
async def _size_guard(request: Request, call_next):
    cap = int(load_config().get("max_request_body_bytes", 2 * 1024 * 1024))
    cl = request.headers.get("content-length")
    if cl is not None:
        try:
            if int(cl) > cap:
                return JSONResponse(status_code=413, content={"detail": "request too large"})
        except ValueError:
            pass
    return await call_next(request)


@app.post("/analyse", response_model=AnalysisResult, dependencies=[Depends(verify_token)])
def analyse_endpoint(body: AnalyseRequest) -> AnalysisResult:
    metrics.requests_total.inc()
    try:
        if not prefilter.is_interesting(body.request, body.response, body.url):
            metrics.filter_dropped.inc()
            return AnalysisResult(risk="none", correlation_id=body.correlation_id)
        metrics.filter_kept.inc()

        session_id = db.current_session_id()
        ctx = memory.get_session_context(body.url, session_id=session_id)
        result = analyse(
            request=body.request,
            response=body.response,
            url=body.url,
            tool=body.tool,
            memory_context=ctx,
            correlation_id=body.correlation_id,
        )

        if result.risk != "none" and result.findings:
            method = body.method or prefilter.request_method(body.request)
            status = body.status_code or prefilter.response_status(body.response)
            primary = result.findings[0]
            fid = db.save_finding(
                url=body.url,
                method=method,
                status_code=status,
                risk=result.risk,
                owasp_category=result.owasp_category,
                findings=[f.model_dump() for f in result.findings],
                recommend=list(result.recommend),
                follow_up=result.interesting_for_follow_up,
                cwe=primary.cwe,
                cvss=primary.cvss,
                source=primary.source,
                correlation_id=body.correlation_id,
            )
            for f in result.findings:
                embed_text = (
                    f"{body.url} {f.type} {f.parameter or ''} :: "
                    f"{redact.redact(f.evidence)}"
                )
                is_dup, _ = memory.dedup_or_add(
                    url=body.url,
                    parameter=f.parameter,
                    finding_type=f.type,
                    detail=f.detail,
                    embedding_text=embed_text,
                    session_id=session_id,
                )
                if is_dup:
                    metrics.dedup_collapsed.inc()
                    db.increment_occurrences(url=body.url, finding_type=f.type)
            _ = fid
        return result
    except Exception as exc:
        _log.exception("analyse endpoint failed: %s", exc)
        return AnalysisResult(risk="none", correlation_id=body.correlation_id)


@app.post("/diff", response_model=AnalysisResult, dependencies=[Depends(verify_token)])
def diff_endpoint(body: DiffRequest) -> AnalysisResult:
    combined_request = (
        "=== SAMPLE A ===\n" + body.request_a + "\n\n=== SAMPLE B ===\n" + body.request_b
    )
    combined_response = (
        "=== SAMPLE A ===\n" + body.response_a + "\n\n=== SAMPLE B ===\n" + body.response_b
    )
    result = analyse(
        request=combined_request,
        response=combined_response,
        url=body.url,
        tool=body.tool + "+diff",
        memory_context="This is a DIFFERENTIAL analysis: compare A vs B.",
        correlation_id=body.correlation_id,
    )
    for f in result.findings:
        f.source = "diff"
    return result


@app.post("/poc", dependencies=[Depends(verify_token)])
def poc_endpoint(body: PocRequest) -> dict:
    row = db.get_finding(body.finding_id)
    if not row:
        raise HTTPException(status_code=404, detail="finding not found")
    primary = (row.get("findings") or [{}])[0]
    primary["url"] = row["url"]
    return {
        "finding_id": body.finding_id,
        "style": body.style,
        "poc": generate_poc(finding=primary, style=body.style),
    }


@app.post("/probe", dependencies=[Depends(verify_token)])
def probe_endpoint(body: ProbeRequest) -> dict:
    cfg = load_config().get("agentic", {})
    if not cfg.get("enabled", False):
        raise HTTPException(status_code=403, detail="agentic mode disabled")
    row = db.get_finding(body.finding_id)
    if not row:
        raise HTTPException(status_code=404, detail="finding not found")
    probes = probe_mod.execute(
        finding=row, max_probes=body.max_probes, call_model=ollama_call,
    )
    verdicts = []
    for p in probes:
        r = analyse(
            request=p["request"], response=p["response"], url=p["url"],
            tool="probe",
            memory_context=f"Follow-up to finding {body.finding_id}: {p.get('rationale','')}",
            correlation_id=row.get("correlation_id"),
        )
        verdicts.append({
            "url": p["url"], "method": p["method"],
            "rationale": p["rationale"],
            "risk": r.risk,
            "findings": [f.model_dump() for f in r.findings],
        })
    return {"finding_id": body.finding_id, "probes": verdicts}


@app.post("/correlate", response_model=CorrelateResult,
          dependencies=[Depends(verify_token)])
def correlate_endpoint(body: CorrelateRequest) -> CorrelateResult:
    """Surface logic bugs that span multiple existing findings."""
    rows = db.list_current_findings()
    if body.host:
        from urllib.parse import urlparse
        rows = [r for r in rows if urlparse(r.get("url", "")).hostname == body.host]
    if len(rows) < body.min_findings:
        return CorrelateResult(host=body.host, examined=len(rows), findings=[])
    raw = correlate_findings(findings=rows, call_model=ollama_call)
    out = []
    for f in raw:
        out.append({
            "title": str(f.get("title", ""))[:200],
            "detail": str(f.get("detail", ""))[:500],
            "cwe": f.get("cwe"),
            "cvss": f.get("cvss"),
            "related_finding_ids": [int(x) for x in (f.get("related_finding_ids") or []) if isinstance(x, (int, str)) and str(x).isdigit()],
        })
    return CorrelateResult(host=body.host, examined=len(rows), findings=out)


@app.post("/confirm", response_model=ConfirmResult,
          dependencies=[Depends(verify_token)])
def confirm_endpoint(body: ConfirmRequest) -> ConfirmResult:
    """Closed-loop confirmation: issue a targeted follow-up to prove a finding."""
    row = db.get_finding(body.finding_id)
    if not row:
        raise HTTPException(status_code=404, detail="finding not found")
    subs = row.get("findings") or []
    if body.sub_index >= len(subs):
        raise HTTPException(status_code=404, detail="sub-finding index out of range")
    sub = subs[body.sub_index]
    v = confirmer_mod.confirm(sub, base_url=row["url"])
    return ConfirmResult(
        finding_id=body.finding_id,
        sub_index=body.sub_index,
        type=str(sub.get("type", "")),
        verdict=v["verdict"],
        evidence=v["evidence"],
        elapsed_seconds=v["elapsed_seconds"],
        probe_request=v["probe_request"],
        probe_response=v["probe_response"],
    )


@app.get("/findings", dependencies=[Depends(verify_token)])
def list_findings() -> list:
    return db.list_current_findings()


@app.get("/chains", dependencies=[Depends(verify_token)])
def chains_endpoint() -> dict:
    """Run cross-request chain detectors over the current session."""
    findings = chain_mod.run_chains()
    return {"count": len(findings), "findings": findings}


@app.get("/findings/summary", response_model=SummaryCounts,
         dependencies=[Depends(verify_token)])
def findings_summary() -> SummaryCounts:
    return SummaryCounts(**db.summary())


@app.get("/state", response_model=BridgeState, dependencies=[Depends(verify_token)])
def bridge_state() -> BridgeState:
    h = HealthStatus(
        ollama=ping_ollama(),
        chroma=memory.ping(),
        db=db.ping(),
        cache=llm_cache.ping(),
    )
    return BridgeState(
        health=h,
        summary=SummaryCounts(**db.summary()),
        findings=db.list_current_findings(),
        metrics=metrics.snapshot(),
    )


@app.get("/metrics", response_class=PlainTextResponse,
         dependencies=[Depends(verify_token)])
def metrics_endpoint() -> str:
    return metrics.prometheus_text()


@app.post("/session/clear", dependencies=[Depends(verify_token)])
def session_clear() -> dict:
    old_session = db.current_session_id()
    memory.clear_session(session_id=old_session)
    probe_mod.reset_budget()
    new_session = db.archive_current_session()
    return {"archived_session": old_session, "new_session": new_session}


@app.get("/session/report", response_class=PlainTextResponse,
         dependencies=[Depends(verify_token)])
def session_report() -> str:
    sid = db.current_session_id()
    include_archived = bool(load_config().get("report", {}).get("include_archived", False))
    rows = db.list_session_findings(sid, include_archived=include_archived)
    return report_mod.render(session_id=sid, findings=rows, call_model=ollama_call)


@app.post("/recommend", dependencies=[Depends(verify_token)])
def recommend_endpoint(body: dict | None = None) -> dict:
    """Generate ranked payload recommendations from the current session."""
    body = body or {}
    return recommender_mod.recommend(
        host=body.get("host"),
        vuln_class=body.get("vuln_class"),
        limit=int(body.get("limit", 25)),
    )


@app.get("/session/sarif", dependencies=[Depends(verify_token)])
def session_sarif() -> dict:
    """Return the current session's findings as SARIF 2.1.0."""
    sid = db.current_session_id()
    include_archived = bool(load_config().get("report", {}).get("include_archived", False))
    rows = db.list_session_findings(sid, include_archived=include_archived)
    return sarif_mod.to_sarif(session_id=sid, findings=rows, tool_version=app.version)


@app.get("/health", response_model=HealthStatus)
def health() -> HealthStatus:
    return HealthStatus(
        ollama=ping_ollama(),
        chroma=memory.ping(),
        db=db.ping(),
        cache=llm_cache.ping(),
    )


if __name__ == "__main__":  # pragma: no cover
    import uvicorn
    cfg = load_config()
    uvicorn.run(
        "llm_bridge.bridge:app",
        host=cfg["bridge_host"],
        port=int(cfg["bridge_port"]),
        log_level=str(cfg.get("log_level", "info")).lower(),
        reload=False,
    )
