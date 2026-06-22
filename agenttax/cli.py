"""Command-line interface for AGENTTAX."""

from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from . import TOOL_NAME, TOOL_VERSION
from .core import (
    CONFIDENCE_ORDER,
    FindingsError,
    Report,
    classify_findings,
    findings_from_text,
    get_taxonomy,
    load_findings,
    to_csv,
    to_sarif,
)

_BAND_LABEL = {"high": "HIGH", "medium": "MED ", "low": "LOW ", "none": "----"}


def _render_table(report: Report) -> str:
    lines: List[str] = []
    lines.append(f"AGENTTAX — AI-agent threat taxonomy mapping  (source: {report.source})")
    lines.append("=" * 74)
    if not report.classifications:
        lines.append("No findings to classify.")
        return "\n".join(lines)

    for cl in report.classifications:
        head = f"{cl.finding_id}"
        if cl.title:
            head += f": {cl.title}"
        lines.append(head)
        snippet = cl.text if len(cl.text) <= 100 else cl.text[:97] + "..."
        lines.append(f"    \"{snippet}\"")
        if not cl.matches:
            lines.append("    [----] no taxonomy category matched (review manually)")
        for m in cl.matches:
            label = _BAND_LABEL.get(m.band, m.band.upper())
            lines.append(
                f"    [{label}] {m.label}  "
                f"(conf {m.confidence:.2f}, {m.reference})"
            )
            lines.append(f"           mitigation: {m.mitigation}")
        lines.append("")

    s = report.to_dict()["summary"]
    lines.append("-" * 74)
    cat_bits = ", ".join(
        f"{cid.split('_')[0].lower()}={n}"
        for cid, n in s["by_category"].items() if n
    ) or "none"
    lines.append(
        f"findings={s['findings']}  classified={s['classified']}  "
        f"unclassified={s['unclassified']}"
    )
    lines.append(f"category hits: {cat_bits}")
    lines.append(f"highest confidence: {s['highest_confidence']}")
    return "\n".join(lines)


def _render_taxonomy() -> str:
    lines = ["AGENTTAX — Microsoft AI-agent threat taxonomy (7 categories)",
             "=" * 74]
    for c in get_taxonomy():
        lines.append(f"{c['id']}  [{c['reference']}]")
        lines.append(f"    {c['label']}")
        lines.append(f"    {c['description']}")
        lines.append(f"    mitigation: {c['mitigation']}")
        lines.append(f"    signals: {c['signal_count']}")
        lines.append("")
    return "\n".join(lines)


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Classify security findings against Microsoft's AI-agent "
                    "threat taxonomy and attach concrete mitigations.",
    )
    p.add_argument("--version", action="version",
                   version=f"{TOOL_NAME} {TOOL_VERSION}")
    sub = p.add_subparsers(dest="command")

    cls = sub.add_parser(
        "classify",
        help="Classify a findings JSON (or --text) into taxonomy categories.")
    cls.add_argument("findings", nargs="?",
                     help="Path to a findings JSON file (list or {findings:[...]}).")
    cls.add_argument("--text",
                     help="Classify this free-text blob instead of a file "
                          "(one finding per paragraph/line).")
    cls.add_argument("--format", choices=("table", "json", "sarif", "csv"),
                     default="table", help="Output format (default: table).")
    cls.add_argument("--min-confidence", type=float, default=0.0,
                     help="Drop category matches below this confidence (0.0-1.0).")
    cls.add_argument("--fail-on", choices=("none", "low", "medium", "high"),
                     default="none",
                     help="Exit non-zero if any match reaches this confidence "
                          "band (default: none).")
    cls.add_argument("--out", help="Write output to this file instead of stdout.")

    sub.add_parser("taxonomy", help="Print the full taxonomy + mitigations.")
    return p


def _emit(text: str, out: Optional[str]) -> None:
    if out:
        with open(out, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
    else:
        print(text)


def _fail_triggered(report: Report, fail_on: str) -> bool:
    if fail_on == "none":
        return False
    threshold = CONFIDENCE_ORDER[fail_on]
    for cl in report.classifications:
        for m in cl.matches:
            if CONFIDENCE_ORDER.get(m.band, 99) <= threshold:
                return True
    return False


def _run_classify(args: argparse.Namespace) -> int:
    if args.text:
        findings = findings_from_text(args.text)
        source = "<text>"
    elif args.findings:
        try:
            findings = load_findings(args.findings)
        except (OSError, FindingsError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        source = args.findings
    else:
        print("error: provide a findings file or --text", file=sys.stderr)
        return 2

    mc = max(0.0, min(1.0, args.min_confidence))
    report = classify_findings(findings, source=source, min_confidence=mc)

    if args.format == "json":
        out = json.dumps(report.to_dict(), indent=2)
    elif args.format == "sarif":
        out = json.dumps(to_sarif(report), indent=2)
    elif args.format == "csv":
        out = to_csv(report)
    else:
        out = _render_table(report)
    _emit(out, args.out)

    return 1 if _fail_triggered(report, args.fail_on) else 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command == "classify":
        return _run_classify(args)
    if args.command == "taxonomy":
        print(_render_taxonomy())
        return 0
    parser.print_help(sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
