# Demo 06 — SOC alert lines (bare-string array)

A SOC dumps short alert strings, one per line, with no structure. `classify`
accepts a **JSON array of bare strings** — each string becomes a finding
(`F1`, `F2`, ...) — so you can pipe a one-line-per-alert export straight in
without reshaping it into objects.

Where the data comes from: a triage queue of agent-platform alerts plus one
routine ops line.

## Run it

```bash
agenttax classify demos/06-soc-alert-lines/alerts.json
agenttax classify demos/06-soc-alert-lines/alerts.json --format csv --out soc.csv
```

## What to expect

Five of the six lines classify to one category each (Goal Hijacking,
Inter-Agent Trust Escalation, MCP / Plugin Abuse, Capability / Architecture
Disclosure, Session Context Contamination). The sixth — the database-backup
line — stays *unclassified*, confirming the classifier ignores routine ops
noise. Summary reports `classified=5  unclassified=1`.

## How to act

Open the CSV in a spreadsheet, sort by `band`, and route each classified row
to the owning team using the per-row `mitigation` column as the remediation
starting point.
