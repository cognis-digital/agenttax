# Demo 08 — Clean baseline (no false positives)

A control case. These four findings are ordinary web/cloud appsec issues with
**no** agent-specific threat. A classifier is only useful if it stays quiet on
non-agent findings, so this demo asserts the absence of matches.

Where the data comes from: a routine web-app baseline scan run against a
service that happens to sit next to an agent platform.

## Run it

```bash
agenttax classify demos/08-clean-baseline/findings.json
agenttax classify demos/08-clean-baseline/findings.json --fail-on low   # exits 0 — nothing fired
```

## What to expect

All four findings come back *unclassified* (`classified=0  unclassified=4`,
`highest confidence: none`). Because nothing matched, `--fail-on low` still
**exits 0** — so a CI gate on agent threats will not be tripped by generic
appsec noise. Triage these through your normal appsec process, not the
agent-threat lane.

## How to act

Nothing here is an agent threat — route to the standard vuln-management
workflow. The point of the demo is the negative result: confidence in the
positives (demos 01-07) depends on no spurious matches here.
