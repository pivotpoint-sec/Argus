"""
SQLite-backed findings log (via SQLModel).

Security intent: every triage outcome is persisted locally so a tester can
reconstruct an engagement offline, export artefacts for a report, and
archive previous sessions without losing evidence.

This module also performs idempotent ALTER TABLE migrations so an existing
database from an older Argus build picks up the new columns
(cwe / cvss / source / correlation_id / occurrences) on first run.
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from typing import Any, Optional

from sqlalchemy import text
from sqlmodel import Field, Session, SQLModel, create_engine, select

from llm_bridge.config import configure_logging, load_config, resolve_path

_log = configure_logging()


class Finding(SQLModel, table=True):
    """One row per analysed request/response pair with risk != none (or any detector hit)."""

    __tablename__ = "findings"
    # extend_existing so the test suite can pop storage.db from sys.modules
    # and re-import it without SQLAlchemy raising "Table already defined".
    __table_args__ = {"extend_existing": True}

    id: Optional[int] = Field(default=None, primary_key=True)
    timestamp: str = Field(index=True)
    url: str
    method: Optional[str] = None
    status_code: Optional[int] = None
    risk: str = Field(index=True)
    owasp_category: Optional[str] = Field(default=None, index=True)
    cwe: Optional[str] = Field(default=None, index=True)
    cvss: Optional[float] = None
    source: str = Field(default="llm")
    findings_json: str = "[]"
    recommend_json: str = "[]"
    follow_up: Optional[str] = None
    session_id: str = Field(index=True)
    correlation_id: Optional[str] = Field(default=None, index=True)
    occurrences: int = Field(default=1)
    archived: bool = Field(default=False)


# ---------------------------------------------------------------------------
# Engine / session lifecycle
# ---------------------------------------------------------------------------

_engine = None
_engine_lock = Lock()
_current_session_id: str = str(uuid.uuid4())

_NEW_COLUMNS = (
    ("cwe",            "TEXT"),
    ("cvss",           "REAL"),
    ("source",         "TEXT NOT NULL DEFAULT 'llm'"),
    ("correlation_id", "TEXT"),
    ("occurrences",    "INTEGER NOT NULL DEFAULT 1"),
)


def _db_path() -> Path:
    cfg = load_config()
    return resolve_path(cfg.get("storage", {}).get("sqlite_path", "storage/findings.db"))


def _migrate(engine) -> None:
    """Add any missing columns to an existing findings table."""
    with engine.connect() as conn:
        cols = {row[1] for row in conn.execute(text("PRAGMA table_info(findings)")).fetchall()}
        for name, ddl in _NEW_COLUMNS:
            if name not in cols:
                _log.info("DB migration: adding column %s", name)
                conn.execute(text(f"ALTER TABLE findings ADD COLUMN {name} {ddl}"))
        conn.commit()


def get_engine():
    global _engine
    with _engine_lock:
        if _engine is None:
            path = _db_path()
            _engine = create_engine(
                f"sqlite:///{path}",
                echo=False,
                connect_args={"check_same_thread": False},
            )
            SQLModel.metadata.create_all(_engine)
            _migrate(_engine)
            _log.info("SQLite ready at %s", path)
        return _engine


def current_session_id() -> str:
    return _current_session_id


def new_session_id() -> str:
    global _current_session_id
    _current_session_id = str(uuid.uuid4())
    _log.info("New session started: %s", _current_session_id)
    return _current_session_id


# ---------------------------------------------------------------------------
# Public CRUD
# ---------------------------------------------------------------------------


def save_finding(
    *,
    url: str,
    method: Optional[str],
    status_code: Optional[int],
    risk: str,
    owasp_category: Optional[str],
    findings: list[dict[str, Any]],
    recommend: list[str],
    follow_up: Optional[str],
    cwe: Optional[str] = None,
    cvss: Optional[float] = None,
    source: str = "llm",
    correlation_id: Optional[str] = None,
) -> int:
    row = Finding(
        timestamp=datetime.now(timezone.utc).isoformat(),
        url=url,
        method=method,
        status_code=status_code,
        risk=risk,
        owasp_category=owasp_category,
        cwe=cwe,
        cvss=cvss,
        source=source,
        findings_json=json.dumps(findings, ensure_ascii=False),
        recommend_json=json.dumps(recommend, ensure_ascii=False),
        follow_up=follow_up,
        session_id=current_session_id(),
        correlation_id=correlation_id,
        occurrences=1,
        archived=False,
    )
    with Session(get_engine()) as s:
        s.add(row)
        s.commit()
        s.refresh(row)
        _log.info("Saved finding id=%s risk=%s url=%s", row.id, risk, url)
        return int(row.id)  # type: ignore[arg-type]


def increment_occurrences(*, url: str, finding_type: str) -> bool:
    """
    Bump the occurrences counter for the most recent matching row in this
    session. Used when the memory layer says "this is a duplicate".
    Returns True if a row was found and updated.
    """
    with Session(get_engine()) as s:
        stmt = select(Finding).where(
            Finding.session_id == current_session_id(),
            Finding.url == url,
            Finding.archived == False,  # noqa: E712
        ).order_by(Finding.id.desc()).limit(5)  # type: ignore[attr-defined]
        for row in s.exec(stmt):
            for f in json.loads(row.findings_json or "[]"):
                if str(f.get("type", "")).lower() == finding_type.lower():
                    row.occurrences = (row.occurrences or 1) + 1
                    s.add(row)
                    s.commit()
                    return True
    return False


def get_finding(finding_id: int) -> dict[str, Any] | None:
    with Session(get_engine()) as s:
        row = s.get(Finding, finding_id)
        return _row_to_dict(row) if row else None


def _row_to_dict(row: Finding) -> dict[str, Any]:
    return {
        "id": row.id,
        "timestamp": row.timestamp,
        "url": row.url,
        "method": row.method,
        "status_code": row.status_code,
        "risk": row.risk,
        "owasp_category": row.owasp_category,
        "cwe": row.cwe,
        "cvss": row.cvss,
        "source": row.source,
        "findings": json.loads(row.findings_json or "[]"),
        "recommend": json.loads(row.recommend_json or "[]"),
        "follow_up": row.follow_up,
        "session_id": row.session_id,
        "correlation_id": row.correlation_id,
        "occurrences": row.occurrences,
        "archived": bool(row.archived),
    }


def list_current_findings(include_archived: bool = False) -> list[dict[str, Any]]:
    with Session(get_engine()) as s:
        stmt = select(Finding).where(Finding.session_id == current_session_id())
        if not include_archived:
            stmt = stmt.where(Finding.archived == False)  # noqa: E712
        stmt = stmt.order_by(Finding.id.desc())  # type: ignore[attr-defined]
        return [_row_to_dict(r) for r in s.exec(stmt)]


def list_session_findings(session_id: str, *, include_archived: bool = False) -> list[dict[str, Any]]:
    with Session(get_engine()) as s:
        stmt = select(Finding).where(Finding.session_id == session_id)
        if not include_archived:
            stmt = stmt.where(Finding.archived == False)  # noqa: E712
        stmt = stmt.order_by(Finding.id.desc())  # type: ignore[attr-defined]
        return [_row_to_dict(r) for r in s.exec(stmt)]


def archive_current_session() -> str:
    """Mark all findings in the current session as archived, then rotate the session id."""
    old = current_session_id()
    with Session(get_engine()) as s:
        stmt = select(Finding).where(Finding.session_id == old, Finding.archived == False)  # noqa: E712
        for row in s.exec(stmt):
            row.archived = True
            s.add(row)
        s.commit()
    _log.info("Archived session %s", old)
    return new_session_id()


def summary() -> dict[str, Any]:
    by_risk: dict[str, int] = {}
    by_owasp: dict[str, int] = {}
    total = 0
    with Session(get_engine()) as s:
        stmt = select(Finding).where(
            Finding.session_id == current_session_id(),
            Finding.archived == False,  # noqa: E712
        )
        for row in s.exec(stmt):
            total += 1
            by_risk[row.risk] = by_risk.get(row.risk, 0) + 1
            if row.owasp_category:
                by_owasp[row.owasp_category] = by_owasp.get(row.owasp_category, 0) + 1
    return {
        "by_risk": by_risk,
        "by_owasp": by_owasp,
        "total": total,
        "session_id": current_session_id(),
    }


def ping() -> bool:
    try:
        with Session(get_engine()) as s:
            s.exec(select(Finding).limit(1)).all()
        return True
    except Exception as exc:  # pragma: no cover
        _log.warning("sqlite ping failed: %s", exc)
        return False


if __name__ == "__main__":
    eng = get_engine()
    fid = save_finding(
        url="https://x.test/smoke",
        method="GET",
        status_code=200,
        risk="low",
        owasp_category="A05:2021-Security Misconfiguration",
        findings=[{"type": "Header misconfiguration", "detail": "missing CSP"}],
        recommend=["add CSP"],
        follow_up=None,
    )
    assert fid > 0
    print("db.py smoke test ok; row id:", fid)
