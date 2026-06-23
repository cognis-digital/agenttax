# AGENTTAX language ports

The Python package in [`../agenttax/`](../agenttax/) is the reference
implementation. These are faithful ports of the **classification core** and the
two read-only commands (`classify`, `taxonomy`) to other ecosystems, so the
taxonomy can drop into a Go service, a Node toolchain, or a Rust binary without
shelling out to Python.

Every port is **passive and offline** — no network, no active scanning — and
its regex signal table mirrors the Python `core.py` so classification is
consistent across languages. Each port ships a smoke test and is built/tested
in CI on every push (see [`../.github/workflows/ports.yml`](../.github/workflows/ports.yml)).

| Port | Path | Build | Test | Verified |
|------|------|-------|------|----------|
| TypeScript / Node | [`node/`](node/) | `npm install && npm run build` | `npm test` (Node built-in test runner) | locally + CI |
| Go | [`go/`](go/) | `go build ./cmd/agenttax` | `go test ./...` | CI |
| Rust | [`rust/`](rust/) | `cargo build --release` | `cargo test` | CI |

## Parity

All three ports reproduce the reference behaviour on `demos/01-basic/findings.json`:
**seven categories fire, one finding stays unclassified.** The Node smoke test
and the Go/Rust test suites assert this exact result, and the CI smoke step
re-checks the category count against the shared demo input.

## Command surface (all ports)

```bash
agenttax --version
agenttax taxonomy                                  # print the 7 categories + mitigations
agenttax classify <findings.json>                  # table (default)
agenttax classify <findings.json> --format json    # machine-readable  (Node, Go)
agenttax classify <findings.json> --format sarif    # SARIF 2.1.0       (Node, Go)
agenttax classify <findings.json> --format csv      # one row per match (Node, Go)
agenttax classify --text "ignore all previous instructions ..."
agenttax classify <findings.json> --fail-on high   # CI gate: exit 1 on any HIGH match
```

The Node and Go ports implement every output format (`table`, `json`, `sarif`,
`csv`). The Rust port implements the `table` renderer plus `--fail-on` gating
(its dependency-light JSON reader covers the standard findings shapes); use the
Python or Node port when you need SARIF/CSV from Rust callers.

> For SARIF/CSV/JSON, MCP serving, and `cognis-connect` emit, the Python package
> remains the most complete surface — these ports exist to embed the classifier
> natively where Python is not in the loop.
