#!/usr/bin/env node
// AGENTTAX CLI — TypeScript/Node port. Mirrors `agenttax classify` + `taxonomy`.
// Passive, offline, no network. stdlib only.

import * as fs from "fs";
import {
  CONFIDENCE_ORDER,
  Band,
  Report,
  classifyFindings,
  findingsFromText,
  normalizeFindings,
  getTaxonomy,
  toCsv,
  toSarif,
} from "./core.js";
import { TOOL_NAME, TOOL_VERSION } from "./taxonomy.js";

const BAND_LABEL: Record<Band, string> = {
  high: "HIGH",
  medium: "MED ",
  low: "LOW ",
  none: "----",
};

function renderTable(report: Report): string {
  const lines: string[] = [];
  lines.push(`AGENTTAX — AI-agent threat taxonomy mapping  (source: ${report.source})`);
  lines.push("=".repeat(74));
  if (report.classifications.length === 0) {
    lines.push("No findings to classify.");
    return lines.join("\n");
  }
  for (const cl of report.classifications) {
    let head = cl.id;
    if (cl.title) head += `: ${cl.title}`;
    lines.push(head);
    const snippet = cl.text.length <= 100 ? cl.text : cl.text.slice(0, 97) + "...";
    lines.push(`    "${snippet}"`);
    if (cl.matches.length === 0) {
      lines.push("    [----] no taxonomy category matched (review manually)");
    }
    for (const m of cl.matches) {
      const label = BAND_LABEL[m.band] ?? m.band.toUpperCase();
      lines.push(`    [${label}] ${m.label}  (conf ${m.confidence.toFixed(2)}, ${m.reference})`);
      lines.push(`           mitigation: ${m.mitigation}`);
    }
    lines.push("");
  }
  const s = report.summary;
  lines.push("-".repeat(74));
  const catBits =
    Object.entries(s.by_category)
      .filter(([, n]) => n)
      .map(([cid, n]) => `${cid.split("_")[0].toLowerCase()}=${n}`)
      .join(", ") || "none";
  lines.push(
    `findings=${s.findings}  classified=${s.classified}  unclassified=${s.unclassified}`
  );
  lines.push(`category hits: ${catBits}`);
  lines.push(`highest confidence: ${s.highest_confidence}`);
  return lines.join("\n");
}

function renderTaxonomy(): string {
  const lines = ["AGENTTAX — Microsoft AI-agent threat taxonomy (7 categories)", "=".repeat(74)];
  for (const c of getTaxonomy()) {
    lines.push(`${c.id}  [${c.reference}]`);
    lines.push(`    ${c.label}`);
    lines.push(`    ${c.description}`);
    lines.push(`    mitigation: ${c.mitigation}`);
    lines.push(`    signals: ${c.signal_count}`);
    lines.push("");
  }
  return lines.join("\n");
}

function failTriggered(report: Report, failOn: string): boolean {
  if (failOn === "none") return false;
  const threshold = CONFIDENCE_ORDER[failOn as Band];
  for (const cl of report.classifications)
    for (const m of cl.matches)
      if ((CONFIDENCE_ORDER[m.band] ?? 99) <= threshold) return true;
  return false;
}

interface Args {
  command?: string;
  findings?: string;
  text?: string;
  format: string;
  minConfidence: number;
  failOn: string;
  out?: string;
}

function parseArgs(argv: string[]): Args {
  const a: Args = { format: "table", minConfidence: 0.0, failOn: "none" };
  if (argv.includes("--version")) {
    process.stdout.write(`${TOOL_NAME} ${TOOL_VERSION}\n`);
    process.exit(0);
  }
  a.command = argv[0];
  for (let i = 1; i < argv.length; i++) {
    const t = argv[i];
    if (t === "--text") a.text = argv[++i];
    else if (t === "--format") a.format = argv[++i];
    else if (t === "--min-confidence") a.minConfidence = parseFloat(argv[++i]);
    else if (t === "--fail-on") a.failOn = argv[++i];
    else if (t === "--out") a.out = argv[++i];
    else if (!t.startsWith("--") && a.findings === undefined) a.findings = t;
  }
  return a;
}

function emit(text: string, out?: string): void {
  if (out) fs.writeFileSync(out, text + "\n", "utf-8");
  else process.stdout.write(text + "\n");
}

export function main(argv: string[]): number {
  const a = parseArgs(argv);

  if (a.command === "taxonomy") {
    process.stdout.write(renderTaxonomy() + "\n");
    return 0;
  }
  if (a.command !== "classify") {
    process.stderr.write(`usage: ${TOOL_NAME} {classify,taxonomy} [...]\n`);
    return 2;
  }

  let findings;
  let source: string;
  if (a.text) {
    findings = findingsFromText(a.text);
    source = "<text>";
  } else if (a.findings) {
    let raw: string;
    try {
      raw = fs.readFileSync(a.findings, "utf-8");
    } catch (e) {
      process.stderr.write(`error: ${(e as Error).message}\n`);
      return 2;
    }
    try {
      findings = normalizeFindings(JSON.parse(raw));
    } catch (e) {
      process.stderr.write(`error: invalid JSON in ${a.findings}: ${(e as Error).message}\n`);
      return 2;
    }
    source = a.findings;
  } else {
    process.stderr.write("error: provide a findings file or --text\n");
    return 2;
  }

  const mc = Math.max(0.0, Math.min(1.0, a.minConfidence));
  const report = classifyFindings(findings, source, mc);

  let out: string;
  if (a.format === "json") out = JSON.stringify(report, null, 2);
  else if (a.format === "sarif") out = JSON.stringify(toSarif(report), null, 2);
  else if (a.format === "csv") out = toCsv(report);
  else out = renderTable(report);
  emit(out, a.out);

  return failTriggered(report, a.failOn) ? 1 : 0;
}

// Run when invoked directly.
const invoked = process.argv[1] && /cli\.(ts|js)$/.test(process.argv[1]);
if (invoked) {
  process.exit(main(process.argv.slice(2)));
}
