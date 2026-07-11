# Security Policy

Argus is an offensive security tool that runs on a tester's own laptop.
If you find a bug **in Argus itself** — remote command execution via
crafted input to the bridge, authentication bypass on the auth token,
memory-safety issues in a dependency chain we've overlooked, or anything
that lets someone abuse this tool against its own operator — please
report it privately before going public.

## How to report

Email **snwaobia4@gmail.com** with the subject line `SECURITY: Argus`.

Include:

- A short description of the issue and the operator-facing impact.
- Steps to reproduce. A minimal repro script or a full request/response
  pair is ideal — vague "I think this looks suspicious" reports are
  hard to action.
- The Argus commit hash or release you tested against.
- Your suggested remediation, if you have one. Not required.

Please do **not** open a public GitHub issue for security problems, and
please don't drop a PoC on Twitter or Mastodon before we've had a chance
to fix it. Coordinated disclosure works.

## What to expect back

Argus is a side project, not a funded product. Realistic timing:

- Acknowledgement of your report: within 5 working days.
- Initial severity assessment and a plan: within 10 working days.
- Fix merged: days for anything straightforward, weeks for anything
  that touches the schema, the storage layout, or the bridge's auth model.

I'll credit reporters in the release notes unless you'd prefer to stay
anonymous. There is no paid bounty programme.

## Scope

**In scope:**

- Everything in `llm_bridge/`, `burp_extension/`, `dashboard/`,
  `installer/`, and `storage/`.
- The default `config.yaml` shipped in the repo.
- The Dockerfile and `docker-compose.yml`.

**Out of scope:**

- Bugs in upstream dependencies (Ollama, ChromaDB, FastAPI, Burp Suite
  itself, sentence-transformers, etc.). Report those to their
  maintainers — happy to coordinate if the fix needs a change in Argus
  too.
- "The default token in `config.yaml` is guessable." Yes — it's a
  placeholder the installer replaces. If you're deploying Argus without
  changing the token, that's an operator issue, not a code issue.
- Behaviours the operator explicitly opted into: `agentic.enabled`,
  `recommender.intrusive`, `consistency.runs`. These do exactly what
  the config documents them to do.
- Findings from running Argus against a third-party target. Argus is a
  tool; the operator is responsible for authorisation.

## After a fix

Fix lands as a normal commit on `main` (or a `security/…` branch if we
need to coordinate a release). A note goes into `CHANGELOG.md` naming
the CVE if one gets assigned. Reporters listed with their preferred
handle unless they've asked for anonymity.

Thanks for taking the time to look.
