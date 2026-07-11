"""
LLM self-consistency: run analyse() N times and vote.

Security intent: a single LLM pass occasionally hallucinates a finding
that does not appear on retry. Running the same prompt several times and
keeping only findings that appear in the MAJORITY of runs cuts the
hallucination rate sharply at N x compute cost. Default N=1 (no extra
cost, current behaviour); operators opt in via config.consistency.runs.

Voting rule: a (finding.type, finding.parameter or "") tuple counts as
"seen" once per run. The merged result keeps every tuple seen in at
least `min_agreement` runs, and assigns the highest confidence label
observed across the agreeing runs.

The aggregate risk is the highest risk among runs that produced any
surviving finding; otherwise "none".
"""
from __future__ import annotations

from collections import Counter, defaultdict
from typing import Callable

from .config import configure_logging, load_config
from .models import AnalysisResult, Finding

_log = configure_logging()


def _runs() -> int:
    return max(1, int(load_config().get("consistency", {}).get("runs", 1)))


def _min_agreement() -> int:
    cfg = load_config().get("consistency", {})
    n = max(1, int(cfg.get("runs", 1)))
    return max(1, int(cfg.get("min_agreement", (n // 2) + 1)))


_RISK_ORDER = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_CONF_ORDER = {"possible": 0, "likely": 1, "confirmed": 2}


def _highest_risk(rs):
    best = "none"
    for r in rs:
        if _RISK_ORDER.get(r, -1) > _RISK_ORDER.get(best, -1):
            best = r
    return best


def _key(f: dict | Finding) -> tuple[str, str]:
    if isinstance(f, Finding):
        return (str(f.type or ""), str(f.parameter or ""))
    return (str(f.get("type") or ""), str(f.get("parameter") or ""))


def vote(results: list[AnalysisResult], min_agreement: int | None = None) -> AnalysisResult:
    """Combine N AnalysisResult objects into one by majority vote.

    `min_agreement` defaults to majority-of-results ((N // 2) + 1) when not
    overridden by the caller or by config.consistency.min_agreement.
    """
    if len(results) <= 1:
        return results[0] if results else AnalysisResult(risk="none")

    if min_agreement is not None:
        threshold = max(1, int(min_agreement))
    else:
        cfg = load_config().get("consistency", {})
        if "min_agreement" in cfg:
            threshold = max(1, int(cfg["min_agreement"]))
        else:
            # Default: simple majority of however many results we got.
            threshold = (len(results) // 2) + 1
    # Tally how many runs each (type, parameter) appears in.
    counts: Counter = Counter()
    samples: dict[tuple[str, str], list[Finding]] = defaultdict(list)
    for r in results:
        seen_in_run: set = set()
        for f in r.findings:
            k = _key(f)
            if k in seen_in_run:
                continue  # one vote per run
            seen_in_run.add(k)
            counts[k] += 1
            samples[k].append(f)

    kept: list[Finding] = []
    for k, n in counts.items():
        if n < threshold:
            continue
        pool = samples[k]
        # Pick the one with the highest confidence label.
        chosen = max(pool, key=lambda f: _CONF_ORDER.get(str(f.confidence), 0))
        kept.append(chosen)

    risk = _highest_risk(r.risk for r in results) if kept else "none"
    # Owasp / recommend: take from the highest-risk run that survived.
    owasp = None
    recommend: list[str] = []
    follow_up = None
    for r in sorted(results, key=lambda x: _RISK_ORDER.get(x.risk, 0), reverse=True):
        if r.findings:
            owasp = r.owasp_category
            recommend = list(r.recommend)
            follow_up = r.interesting_for_follow_up
            break

    return AnalysisResult(
        risk=risk if kept else "none",
        owasp_category=owasp if kept else None,
        findings=kept,
        recommend=recommend if kept else [],
        interesting_for_follow_up=follow_up if kept else None,
        correlation_id=results[0].correlation_id,
        from_cache=False,
    )


def analyse_with_consistency(*, analyse_fn: Callable, **kwargs) -> AnalysisResult:
    """
    Drop-in wrapper around analyser.analyse().

    Usage:
        from llm_bridge import analyser, consistency
        result = consistency.analyse_with_consistency(
            analyse_fn=analyser.analyse, request=..., response=..., url=..., ...)
    """
    n = _runs()
    if n <= 1:
        return analyse_fn(**kwargs)
    results = []
    for i in range(n):
        try:
            results.append(analyse_fn(**kwargs))
        except Exception as exc:
            _log.warning("consistency: run %d/%d failed: %s", i + 1, n, exc)
    if not results:
        return AnalysisResult(risk="none")
    voted = vote(results)
    _log.info(
        "consistency: %d run(s), threshold=%d, kept=%d findings (raw counts: %s)",
        n, _min_agreement(), len(voted.findings),
        ", ".join(f"{r.risk}/{len(r.findings)}" for r in results),
    )
    return voted


if __name__ == "__main__":
    from .models import Finding as F
    r1 = AnalysisResult(risk="high", findings=[
        F(type="SQLi", parameter="id", evidence="x", confidence="likely", detail="d"),
        F(type="XSS", parameter="q", evidence="y", confidence="possible", detail="e"),
    ])
    r2 = AnalysisResult(risk="medium", findings=[
        F(type="SQLi", parameter="id", evidence="x", confidence="confirmed", detail="d"),
    ])
    r3 = AnalysisResult(risk="high", findings=[
        F(type="SQLi", parameter="id", evidence="x", confidence="likely", detail="d"),
        F(type="XSS", parameter="q", evidence="y", confidence="possible", detail="e"),
    ])
    # 3-run default threshold = 2: SQLi (3/3) kept, XSS (2/3) kept.
    voted = vote([r1, r2, r3])
    assert len(voted.findings) == 2, voted
    print("consistency.py smoke test ok")
