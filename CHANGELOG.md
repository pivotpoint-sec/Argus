# Changelog

All notable changes to Argus will be recorded here.

The format is loosely based on [Keep a Changelog](https://keepachangelog.com),
and this project uses semantic versioning where practical.

## [Unreleased]

## [1.1.0] - 2026-07-11

### Initial public release

First public release of Argus.

**Detection tier:**

- Deterministic detectors for SQLi, XSS, command injection, JWT
  misconfiguration, XXE, HTTP request smuggling, GraphQL
  misconfiguration, mass assignment / parameter pollution, SSTI, NoSQL
  injection, missing SRI, vulnerable-component fingerprinting, SSRF
  candidate detection, insecure deserialisation, debug-endpoint
  exposure, cloud secret leakage, stack-trace leakage, missing / weak
  security headers, private-IP leakage.
- Cross-request chain detector (IDOR chains, auth-bypass chains,
  privilege-escalation paths, session-token reuse).
- Closed-loop confirmer with per-class targeted probes.

**LLM pipeline:**

- FastAPI bridge with bearer-token auth, rate limiting, size caps,
  structured JSON logs, Prometheus metrics.
- Content-addressed LLM response cache with URL-shape normalisation.
- Multi-model router (Mistral / LLaMA-3 / CodeLlama / Phi-3).
- Self-critique pruning pass.
- LLM self-consistency voting (opt-in, N runs, majority vote).
- Business-logic correlation across findings via /correlate.

**Memory:**

- ChromaDB session memory with semantic dedup and FIFO cap.
- Redaction of JWTs, cookies, passwords, private keys, API keys.

**Reporting:**

- Markdown engagement report with executive summary, target / duration
  counters, per-finding write-ups.
- SARIF 2.1.0 export for GitHub code-scanning, DefectDojo, JIRA.
- Streamlit dashboard with live findings, PoC generator, probe button.

**Tooling:**

- Stack-aware payload recommender (/recommend) with lateral propagation
  across sibling endpoints.
- Attack-surface graph builder.
- install.sh and install.ps1 installers.
- Docker + docker-compose setup for isolated deployment.

**Safety:**

- agentic.enabled gate for follow-up HTTP probes (default: false).
- recommender.intrusive gate for intrusive payloads (default: false).

**Testing:**

- 80+ pytest tests, GitHub Actions CI matrix (Python 3.11, 3.12).
