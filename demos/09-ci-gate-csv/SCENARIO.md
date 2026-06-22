# Demo 09 — CI gate + CSV export for ticketing

A pre-merge check on an agent platform's repo. This demo exercises two things
together: the `--fail-on` CI gate, and the **CSV export** (`--format csv`) for
loading classified findings into a spreadsheet or ticketing import.

Where the data comes from: a CI pre-check that runs `agenttax` over the
findings a scanner produced for the changeset.

## Run it

```bash
# CI gate: exit non-zero if anything reaches HIGH, blocking the merge
agenttax classify demos/09-ci-gate-csv/findings.json --fail-on high

# Export one row per (finding x matched category) for a ticket import
agenttax classify demos/09-ci-gate-csv/findings.json --format csv --out gate.csv
```

As a GitHub Actions step:

```yaml
- run: pip install cognis-agenttax
- run: agenttax classify findings.json --fail-on high --format sarif --out agenttax.sarif
- run: agenttax classify findings.json --format csv --out agenttax.csv   # attach as artifact
```

## What to expect

- `CI-01` → **Goal Hijacking**, `CI-02` → **MCP / Plugin Abuse**,
  `CI-03` → **Agentic Supply Chain Compromise** (all high).
- `CI-04` (whitespace lint) → *unclassified*.
- `--fail-on high` **exits 1**, failing the build.
- The CSV has a stable header
  (`finding_id,title,category_id,category_label,reference,confidence,band,matched_signals,mitigation,text`),
  one row per matched category, plus one row for the unclassified `CI-04`
  with `band=none` so nothing is dropped from the export.

## How to act

Block the merge until the three high findings are remediated; attach the CSV
to the PR and open a ticket per row using the `mitigation` column.
