# Demo 07 — Multi-category attack chains

Real attacks rarely fit one box. This threat-model output for a multi-agent
finance assistant has three findings that each legitimately map to **two**
taxonomy categories. It shows that a finding can carry multiple matches, each
with its own confidence and mitigation.

Where the data comes from: a threat-modeling session on a planner +
sub-agent + MCP-tool architecture.

## Run it

```bash
agenttax classify demos/07-multi-agent-chain/findings.json
agenttax classify demos/07-multi-agent-chain/findings.json --format json
```

## What to expect

- `CHAIN-01` → **Goal Hijacking** + **Inter-Agent Trust Escalation**.
- `CHAIN-02` → **Agentic Supply Chain Compromise** + **MCP / Plugin Abuse**.
- `CHAIN-03` → **Capability / Architecture Disclosure** + **Goal Hijacking**.

In `--format json` each classification's `matches` array has two entries; the
`by_category` summary therefore shows hits spread across five categories from
just three findings.

## How to act

For chained findings, apply the mitigation for **every** matched category —
fixing only the most obvious one leaves the chain exploitable. CHAIN-03 in
particular shows why suppressing capability disclosure matters even when it
looks low-impact on its own: it is the reconnaissance step that enables the
follow-on hijack.
