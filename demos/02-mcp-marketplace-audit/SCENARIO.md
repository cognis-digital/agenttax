# Demo 02 — MCP marketplace intake audit

You run an internal MCP-server marketplace and review every third-party
submission before it can be enabled for agents. This is the checklist output
from one intake review (five candidate behaviors), in the tool's standard
`{ "findings": [...] }` JSON shape.

Where the data comes from: a human reviewer + a manifest-hashing job that
diffs a server's advertised tool descriptions between approval and runtime.

## Run it

```bash
agenttax classify demos/02-mcp-marketplace-audit/findings.json
agenttax classify demos/02-mcp-marketplace-audit/findings.json --format csv --out intake.csv
agenttax classify demos/02-mcp-marketplace-audit/findings.json --fail-on high
```

## What to expect

- `MCP-INTAKE-01`, `-02`, `-03` → **MCP / Plugin Abuse** (high) — over-scoping,
  rug-pull, and tool-call exfiltration are the three canonical MCP abuses.
- `MCP-INTAKE-04` → **Agentic Supply Chain Compromise** (unpinned/unsigned
  package from a third-party registry).
- `MCP-INTAKE-05` → *unclassified* — a support email is not a threat.
- `--fail-on high` exits non-zero, so wiring this into the marketplace's
  intake CI **blocks the submission from being published** until the
  over-scoped/rug-pull items are remediated.

## How to act

Reject `-02` and `-03` outright (active exfiltration). For `-01`, require the
vendor to split the unscoped tool into least-privilege tools with explicit
per-tool consent. For `-04`, require a pinned, signed release before re-review.
