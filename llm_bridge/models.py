"""
Pydantic schemas shared between the FastAPI bridge and the analyser.

Security intent: a strict schema is the contract that turns LLM output into
something the rest of the pipeline can rely on. Anything outside this schema
is rejected so a hallucinating model cannot inject malformed entries into the
findings store.
"""
from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, Field


class AnalyseRequest(BaseModel):
    """A single request/response pair to triage."""

    request: str = Field(..., description="Raw HTTP request, headers + body")
    response: str = Field(..., description="Raw HTTP response, headers + body")
    url: str = Field(..., description="Full URL the request was issued against")
    tool: str = Field("burp", description="Source tool, e.g. 'burp', 'manual'")
    method: Optional[str] = Field(None, description="HTTP method if known")
    status_code: Optional[int] = Field(None, description="HTTP status if known")
    correlation_id: Optional[str] = Field(
        None, description="Caller-supplied ID; propagated into logs and DB rows"
    )


class DiffRequest(BaseModel):
    url: str
    tool: str = "burp"
    request_a: str
    response_a: str
    request_b: str
    response_b: str
    correlation_id: Optional[str] = None


class PocRequest(BaseModel):
    finding_id: int
    style: Literal["curl", "httpie", "python"] = "curl"


class ProbeRequest(BaseModel):
    finding_id: int
    max_probes: Optional[int] = None


class CorrelateRequest(BaseModel):
    host: Optional[str] = Field(
        None,
        description="If set, limit correlation to findings whose URL host matches.",
    )
    min_findings: int = Field(2, ge=2, le=50)


class CorrelateFinding(BaseModel):
    title: str
    detail: str
    cwe: Optional[str] = None
    cvss: Optional[float] = None
    related_finding_ids: list[int] = Field(default_factory=list)


class CorrelateResult(BaseModel):
    host: Optional[str] = None
    examined: int
    findings: list[CorrelateFinding] = Field(default_factory=list)


class ConfirmRequest(BaseModel):
    finding_id: int
    sub_index: int = Field(
        0, ge=0, le=20,
        description="Which sub-finding inside the row to confirm (default first).",
    )


class ConfirmResult(BaseModel):
    finding_id: int
    sub_index: int
    type: str
    verdict: str
    evidence: str
    elapsed_seconds: float
    probe_request: str
    probe_response: str


__all__ = [
    "AnalyseRequest", "DiffRequest", "PocRequest", "ProbeRequest",
    "CorrelateRequest", "CorrelateFinding", "CorrelateResult",
    "ConfirmRequest", "ConfirmResult",
    "Finding", "AnalysisResult", "HealthStatus", "SummaryCounts", "BridgeState",
    "Risk", "Confidence", "Source",
]


Risk = Literal["critical", "high", "medium", "low", "none"]
Confidence = Literal["confirmed", "likely", "possible"]
Source = Literal["detector", "llm", "llm+critique", "diff", "probe", "correlate"]


class Finding(BaseModel):
    type: str = Field(
        ...,
        description=(
            "SQLi | XSS | Command injection | IDOR | SSRF | Auth bypass | "
            "Sensitive data | Header misconfiguration | CSRF | Path traversal | "
            "SSTI | Business logic | Secret leak | JWT misconfiguration | "
            "XXE | HTTP request smuggling | GraphQL misconfiguration | "
            "Mass assignment | Parameter pollution | Vulnerable component | "
            "Insecure deserialization | Missing Subresource Integrity | "
            "NoSQL injection | Other"
        ),
    )
    parameter: Optional[str] = Field(None, description="Specific param/header involved")
    evidence: str = Field(..., description="Exact snippet that triggered the finding")
    confidence: Confidence
    detail: str = Field(..., description="One-sentence explanation")
    source: Source = Field("llm", description="Where the finding came from")
    cwe: Optional[str] = Field(None, description="e.g. CWE-79")
    cvss: Optional[float] = Field(
        None, description="CVSS 3.1 base score 0.0-10.0, best-effort"
    )


class AnalysisResult(BaseModel):
    risk: Risk
    owasp_category: Optional[str] = Field(
        None, description="OWASP Top 10 2021 category, e.g. A01:2021-Broken Access Control"
    )
    findings: list[Finding] = Field(default_factory=list)
    recommend: list[str] = Field(default_factory=list)
    interesting_for_follow_up: Optional[str] = None
    correlation_id: Optional[str] = None
    from_cache: bool = False


class HealthStatus(BaseModel):
    ollama: bool
    chroma: bool
    db: bool
    cache: bool


class SummaryCounts(BaseModel):
    by_risk: dict[str, int]
    by_owasp: dict[str, int]
    total: int
    session_id: str


class BridgeState(BaseModel):
    health: HealthStatus
    summary: SummaryCounts
    findings: list[dict]
    metrics: dict


__all__ = [
    "AnalyseRequest", "DiffRequest", "PocRequest", "ProbeRequest",
    "CorrelateRequest", "CorrelateFinding", "CorrelateResult",
    "ConfirmRequest", "ConfirmResult",
    "Finding", "AnalysisResult", "HealthStatus", "SummaryCounts", "BridgeState",
    "Risk", "Confidence", "Source",
]


if __name__ == "__main__":
    res = AnalysisResult(risk="none")
    assert res.model_dump()["risk"] == "none"
    print("models.py smoke test ok:", res.model_dump_json())
