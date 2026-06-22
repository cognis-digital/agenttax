# Demo 05 — Single-finding incident triage

Sometimes you have exactly one observation — an incident-response ticket — and
want it classified fast. `classify` accepts a **single finding object** (no
array, no wrapper); the tool treats it as a one-element list.

Where the data comes from: an IR ticket opened after EDR flagged an outbound
connection from a coding agent's package post-install step.

## Run it

```bash
agenttax classify demos/05-incident-single-finding/finding.json
agenttax classify demos/05-incident-single-finding/finding.json --format json
```

## What to expect

A single finding `IR-2026-0412` classified as **Agentic Supply Chain
Compromise** (high) — a typosquatted, unsigned, unpinned package pulled
mid-task is the textbook agentic supply-chain case. Note the tool reads the
`observation` field too (it merges `title`/`name`/`description`/`text`/
`message`/`detail`/`summary`/`observation`), so the extra context is folded
into the classified text.

## How to act

Pin and hash-verify agent dependencies, install only from a vetted internal
mirror, and reject unsigned/unpinned artifacts in CI before the agent can load
them. Quarantine the host and rotate any credentials the agent could reach.
