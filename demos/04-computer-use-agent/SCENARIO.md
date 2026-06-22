# Demo 04 — Computer-use / browser agent red-team

A red-team exercise against a browser-driving (computer-use) agent. Every
attack vector here targets the *screen* the agent reads, which is the
distinctive risk surface of GUI-driving agents.

Where the data comes from: a red-team log of UI traps placed on test pages the
agent was instructed to operate.

## Run it

```bash
agenttax classify demos/04-computer-use-agent/findings.json
agenttax classify demos/04-computer-use-agent/findings.json --format csv
```

## What to expect

- `CUA-01` through `CUA-04` → **Computer Use Agent Visual Attack** (high):
  decoy button, visual prompt injection, hidden/off-screen text, and
  navigation to an out-of-allow-list URL.
- `CUA-05` → *unclassified* — VM RAM sizing is a capacity note.

## How to act

Constrain the agent to allow-listed apps/URLs, require human confirmation for
irreversible UI actions, run an overlay/low-contrast/off-screen-text detector
before the agent acts on rendered content, and keep it in a disposable,
monitored sandbox VM.
