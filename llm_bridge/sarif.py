"""
SARIF 2.1.0 export.

Security intent: SARIF is the lingua franca for static/dynamic analysis
output. Producing it lets Argus findings flow into GitHub code-scanning,
DefectDojo, JIRA Compass, Splunk, and most SAST/DAST aggregators - so
the report Argus produces becomes a tracked issue automatically rather
than a Markdown file someone might forget about.

We emit a SINGLE run per session. Each unique finding.type becomes a
SARIF rule; each persisted finding becomes a result that references its
rule and the URL it was found on.
"""
from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

_RISK_TO_SARIF_LEVEL = {
    "critical": "error",
    "high":     "error",
    "medium":   "warning",
    "low":      "note",
    "none":     "note",
}


def _rule(type_: str, cwe: str | None = None) -> dict:
    rule: dict[str, Any] = {
        "id": type_.replace(" ", "_").lower(),
        "name": type_,
        "shortDescription": {"text": type_},
        "fullDescription": {"text": f"Argus detected: {type_}"},
        "helpUri": "https://owasp.org/www-project-top-ten/",
        "defaultConfiguration": {"level": "warning"},
    }
    if cwe:
        rule["relationships"] = [{
            "target": {
                "id": cwe,
                "toolComponent": {"name": "CWE"},
            },
            "kinds": ["relevant"],
        }]
    return rule


def _result(finding_row: dict, sub: dict) -> dict:
    url = finding_row.get("url") or ""
    risk = str(finding_row.get("risk") or sub.get("risk") or "low").lower()
    type_ = str(sub.get("type") or "Other")
    body = (
        f"{sub.get('detail') or ''}\n\n"
        f"Confidence: {sub.get('confidence', '?')}\n"
        f"Parameter: {sub.get('parameter') or '-'}\n"
        f"Evidence: {sub.get('evidence', '')[:300]}\n"
        f"Source: {sub.get('source', 'llm')}"
    )
    return {
        "ruleId": type_.replace(" ", "_").lower(),
        "level": _RISK_TO_SARIF_LEVEL.get(risk, "warning"),
        "message": {"text": body},
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {"uri": url or "argus://unknown"},
                "region": {"startLine": 1, "startColumn": 1},
            },
        }],
        "properties": {
            "cwe": sub.get("cwe"),
            "cvss": sub.get("cvss"),
            "owasp_category": finding_row.get("owasp_category"),
            "occurrences": finding_row.get("occurrences", 1),
            "method": finding_row.get("method"),
            "status_code": finding_row.get("status_code"),
            "timestamp": finding_row.get("timestamp"),
            "argus_finding_id": finding_row.get("id"),
            "host": urlparse(url).hostname,
        },
    }


def to_sarif(*, session_id: str, findings: list[dict], tool_version: str = "1.1.0") -> dict:
    """Build a SARIF 2.1.0 document for the given findings."""
    seen_rules: dict[str, dict] = {}
    results: list[dict] = []
    for row in findings:
        for sub in (row.get("findings") or []):
            type_ = str(sub.get("type") or "Other")
            cwe = sub.get("cwe")
            if type_ not in seen_rules:
                seen_rules[type_] = _rule(type_, cwe)
            results.append(_result(row, sub))

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Argus",
                    "version": tool_version,
                    "informationUri": "https://github.com/your-fork/Argus",
                    "rules": list(seen_rules.values()),
                    "shortDescription": {"text": "Air-gapped LLM-assisted web app pentest triage"},
                },
            },
            "automationDetails": {"id": f"argus-{session_id}"},
            "results": results,
            "invocations": [{"executionSuccessful": True}],
        }],
    }


if __name__ == "__main__":
    doc = to_sarif(session_id="abc", findings=[{
        "id": 1, "url": "https://x/api/u?id=1", "risk": "high",
        "owasp_category": "A03:2021-Injection",
        "method": "GET", "status_code": 200, "timestamp": "2026-01-01T00:00:00Z",
        "occurrences": 1,
        "findings": [{"type": "SQLi", "parameter": "id", "evidence": "OR 1=1",
                      "confidence": "likely", "detail": "boolean OR",
                      "source": "llm", "cwe": "CWE-89", "cvss": 7.5}],
    }])
    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["results"][0]["ruleId"] == "sqli"
    print("sarif.py smoke test ok")
