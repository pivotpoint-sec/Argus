-- =============================================================================
-- Argus — SQLite schema for the findings log.
-- Mirrors storage/db.py (SQLModel). Kept here as authoritative documentation
-- of on-disk structure for offline audits.
-- =============================================================================

CREATE TABLE IF NOT EXISTS findings (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp        TEXT    NOT NULL,             -- ISO-8601 UTC
    url              TEXT    NOT NULL,
    method           TEXT,                         -- GET, POST, ...
    status_code      INTEGER,
    risk             TEXT    NOT NULL,             -- critical|high|medium|low|none
    owasp_category   TEXT,
    cwe              TEXT,                         -- e.g. CWE-79
    cvss             REAL,                         -- 0.0 - 10.0
    source           TEXT    NOT NULL DEFAULT 'llm', -- detector|llm|llm+critique|diff|probe
    findings_json    TEXT    NOT NULL DEFAULT '[]',-- serialized list[Finding]
    recommend_json   TEXT    NOT NULL DEFAULT '[]',-- serialized list[str]
    follow_up        TEXT,
    session_id       TEXT    NOT NULL,
    correlation_id   TEXT,                         -- Burp-side request id
    occurrences      INTEGER NOT NULL DEFAULT 1,   -- incremented on dedup hit
    archived         INTEGER NOT NULL DEFAULT 0    -- 0 = active, 1 = archived
);

CREATE INDEX IF NOT EXISTS idx_findings_session  ON findings(session_id);
CREATE INDEX IF NOT EXISTS idx_findings_risk     ON findings(risk);
CREATE INDEX IF NOT EXISTS idx_findings_owasp    ON findings(owasp_category);
CREATE INDEX IF NOT EXISTS idx_findings_time     ON findings(timestamp);
CREATE INDEX IF NOT EXISTS idx_findings_cwe      ON findings(cwe);
CREATE INDEX IF NOT EXISTS idx_findings_corr     ON findings(correlation_id);
