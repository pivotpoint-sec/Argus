"""
Lightweight in-memory metrics.

Security intent: give the operator a live view of what Argus is doing
during an engagement — how aggressive the filter is, how often the cache
hits, where time is going in the LLM path. Exposed both as a JSON dict
(for the dashboard and /state) and as a Prometheus text block (for
/metrics if the operator prefers to scrape).
"""
from __future__ import annotations

import bisect
import time
from threading import Lock
from typing import Any


class _Counter:
    __slots__ = ("_v", "_lock")

    def __init__(self) -> None:
        self._v = 0
        self._lock = Lock()

    def inc(self, n: int = 1) -> None:
        with self._lock:
            self._v += n

    @property
    def value(self) -> int:
        return self._v


class _LatencyHistogram:
    """Tiny bucketed latency sink; keeps the last `cap` samples in ring form."""

    __slots__ = ("_samples", "_cap", "_lock")

    def __init__(self, cap: int = 1024) -> None:
        self._samples: list[float] = []
        self._cap = cap
        self._lock = Lock()

    def observe(self, seconds: float) -> None:
        with self._lock:
            if len(self._samples) >= self._cap:
                self._samples.pop(0)
            self._samples.append(seconds)

    def percentile(self, p: float) -> float | None:
        with self._lock:
            if not self._samples:
                return None
            s = sorted(self._samples)
            idx = max(0, min(len(s) - 1, int(round((p / 100.0) * (len(s) - 1)))))
            return s[idx]

    @property
    def count(self) -> int:
        return len(self._samples)


# ---------------------------------------------------------------------------
# Singletons
# ---------------------------------------------------------------------------

requests_total    = _Counter()
filter_kept       = _Counter()
filter_dropped    = _Counter()
detector_findings = _Counter()
llm_calls         = _Counter()
llm_failures      = _Counter()
cache_hits        = _Counter()
cache_misses      = _Counter()
critique_pruned   = _Counter()
probes_issued     = _Counter()
dedup_collapsed   = _Counter()

llm_latency = _LatencyHistogram()
llm_critique_latency = _LatencyHistogram()


_started = time.time()


def snapshot() -> dict[str, Any]:
    """Return the current metrics as a plain dict."""
    return {
        "uptime_seconds": round(time.time() - _started, 2),
        "requests_total": requests_total.value,
        "filter_kept": filter_kept.value,
        "filter_dropped": filter_dropped.value,
        "detector_findings": detector_findings.value,
        "llm_calls": llm_calls.value,
        "llm_failures": llm_failures.value,
        "cache_hits": cache_hits.value,
        "cache_misses": cache_misses.value,
        "critique_pruned": critique_pruned.value,
        "probes_issued": probes_issued.value,
        "dedup_collapsed": dedup_collapsed.value,
        "llm_latency_p50_ms": _ms(llm_latency.percentile(50)),
        "llm_latency_p95_ms": _ms(llm_latency.percentile(95)),
        "llm_latency_samples": llm_latency.count,
        "critique_latency_p50_ms": _ms(llm_critique_latency.percentile(50)),
    }


def prometheus_text() -> str:
    """Render the snapshot as Prometheus text format."""
    snap = snapshot()
    lines: list[str] = []
    for k, v in snap.items():
        if v is None:
            continue
        name = f"argus_{k}"
        lines.append(f"# TYPE {name} gauge")
        lines.append(f"{name} {v}")
    return "\n".join(lines) + "\n"


def _ms(seconds: float | None) -> float | None:
    return round(seconds * 1000.0, 2) if seconds is not None else None


# Import the bisect module only so test linters don't flag unused imports.
_ = bisect
