// AGENTTAX core classification — TypeScript/Node port of agenttax/core.py.
// Deterministic, transparent, offline. No network, no ML, no runtime deps.

import {
  TAXONOMY,
  TOOL_NAME,
  TOOL_VERSION,
  SATURATION,
  BAND_HIGH,
  BAND_MEDIUM,
  Category,
} from "./taxonomy.js";

export type Band = "high" | "medium" | "low" | "none";

export const CONFIDENCE_ORDER: Record<Band, number> = {
  high: 0,
  medium: 1,
  low: 2,
  none: 3,
};

export interface CategoryMatch {
  category_id: string;
  label: string;
  reference: string;
  confidence: number;
  band: Band;
  matched_signals: string[];
  mitigation: string;
}

export interface Classification {
  id: string;
  title: string;
  text: string;
  top_band: Band;
  matches: CategoryMatch[];
}

export interface ReportSummary {
  findings: number;
  classified: number;
  unclassified: number;
  by_category: Record<string, number>;
  highest_confidence: Band;
}

export interface Report {
  tool: string;
  version: string;
  source: string;
  summary: ReportSummary;
  classifications: Classification[];
}

export interface Finding {
  id: string;
  title: string;
  text: string;
}

function round3(n: number): number {
  return Math.round(n * 1000) / 1000;
}

export function band(conf: number): Band {
  if (conf >= BAND_HIGH) return "high";
  if (conf >= BAND_MEDIUM) return "medium";
  if (conf > 0) return "low";
  return "none";
}

const _compiled = new Map<string, RegExp>();
function rx(pattern: string): RegExp {
  let r = _compiled.get(pattern);
  if (!r) {
    r = new RegExp(pattern, "i");
    _compiled.set(pattern, r);
  }
  return r;
}

export function classifyText(text: string, minConfidence = 0.0): CategoryMatch[] {
  const matches: CategoryMatch[] = [];
  for (const cat of TAXONOMY) {
    let raw = 0.0;
    const hits: string[] = [];
    for (const sig of cat.signals) {
      if (rx(sig.pattern).test(text)) {
        raw += sig.weight;
        hits.push(sig.pattern);
      }
    }
    if (raw <= 0) continue;
    const confidence = round3(Math.min(1.0, raw / SATURATION));
    if (confidence < minConfidence) continue;
    matches.push({
      category_id: cat.id,
      label: cat.label,
      reference: cat.reference,
      confidence,
      band: band(confidence),
      matched_signals: hits,
      mitigation: cat.mitigation,
    });
  }
  matches.sort((a, b) =>
    a.confidence !== b.confidence
      ? b.confidence - a.confidence
      : a.category_id < b.category_id
      ? -1
      : a.category_id > b.category_id
      ? 1
      : 0
  );
  return matches;
}

const _FIELD_KEYS = [
  "title",
  "name",
  "description",
  "text",
  "message",
  "detail",
  "summary",
  "observation",
];

export function normalizeFindings(data: unknown): Finding[] {
  let items: unknown[];
  if (data !== null && typeof data === "object" && !Array.isArray(data)) {
    const obj = data as Record<string, unknown>;
    if (obj.findings !== undefined) {
      items = obj.findings as unknown[];
    } else {
      items = [obj];
    }
  } else if (Array.isArray(data)) {
    items = data;
  } else {
    throw new Error("findings root must be a JSON object or array");
  }
  if (!Array.isArray(items)) throw new Error("`findings` must be an array");

  const out: Finding[] = [];
  items.forEach((item, idx) => {
    if (typeof item === "string") {
      out.push({ id: `F${idx + 1}`, title: "", text: item });
      return;
    }
    if (item === null || typeof item !== "object") {
      throw new Error(`finding #${idx} must be an object or string`);
    }
    const obj = item as Record<string, unknown>;
    const fid = String(obj.id ?? obj.rule ?? `F${idx + 1}`);
    const title = String(obj.title ?? obj.name ?? "");
    const parts = _FIELD_KEYS.map((k) => (obj[k] != null ? String(obj[k]) : "")).filter(
      (p) => p
    );
    let text = parts.join(" ").trim();
    if (!text) text = JSON.stringify(obj);
    out.push({ id: fid, title, text });
  });
  return out;
}

export function findingsFromText(text: string): Finding[] {
  const chunks = text
    .split(/\n\s*\n|\r?\n/)
    .map((c) => c.trim())
    .filter((c) => c);
  const used = chunks.length ? chunks : text.trim() ? [text.trim()] : [];
  return used.map((c, i) => ({ id: `T${i + 1}`, title: "", text: c }));
}

export function classifyFindings(
  findings: Finding[],
  source = "<findings>",
  minConfidence = 0.0
): Report {
  const classifications: Classification[] = findings.map((f) => {
    const matches = classifyText(f.text, minConfidence);
    const topBand: Band = matches.length
      ? matches
          .map((m) => m.band)
          .reduce((a, b) => (CONFIDENCE_ORDER[a] <= CONFIDENCE_ORDER[b] ? a : b))
      : "none";
    return { id: f.id, title: f.title, text: f.text, top_band: topBand, matches };
  });

  const byCategory: Record<string, number> = {};
  for (const cat of TAXONOMY) byCategory[cat.id] = 0;
  for (const cl of classifications)
    for (const m of cl.matches) byCategory[m.category_id] = (byCategory[m.category_id] ?? 0) + 1;

  const unclassified = classifications.filter((c) => c.matches.length === 0).length;
  const bands = classifications.map((c) => c.top_band);
  const highest: Band = bands.length
    ? bands.reduce((a, b) => (CONFIDENCE_ORDER[a] <= CONFIDENCE_ORDER[b] ? a : b))
    : "none";

  return {
    tool: TOOL_NAME,
    version: TOOL_VERSION,
    source,
    summary: {
      findings: classifications.length,
      classified: classifications.length - unclassified,
      unclassified,
      by_category: byCategory,
      highest_confidence: highest,
    },
    classifications,
  };
}

export function getTaxonomy(): Array<Record<string, unknown>> {
  return TAXONOMY.map((c: Category) => ({
    id: c.id,
    label: c.label,
    reference: c.reference,
    description: c.description,
    mitigation: c.mitigation,
    signal_count: c.signals.length,
  }));
}

// ---- SARIF ----
export function toSarif(report: Report): Record<string, unknown> {
  const ruleIndex: Record<string, number> = {};
  const rules = TAXONOMY.map((cat, i) => {
    ruleIndex[cat.id] = i;
    return {
      id: cat.id,
      name: cat.label,
      shortDescription: { text: cat.label },
      fullDescription: { text: cat.description },
      helpUri: "https://cognis.digital/agenttax",
      help: { text: "Mitigation: " + cat.mitigation },
      properties: {
        reference: cat.reference,
        tags: ["ai-security", "agentic", "microsoft-taxonomy"],
      },
    };
  });
  const bandToLevel: Record<Band, string> = {
    high: "error",
    medium: "warning",
    low: "note",
    none: "none",
  };
  const results: unknown[] = [];
  for (const cl of report.classifications) {
    for (const m of cl.matches) {
      results.push({
        ruleId: m.category_id,
        ruleIndex: ruleIndex[m.category_id],
        level: bandToLevel[m.band] ?? "note",
        message: {
          text: `[${m.label}] ${cl.id}: confidence ${m.confidence.toFixed(
            2
          )} (${m.band}). Mitigation: ${m.mitigation}`,
        },
        properties: {
          findingId: cl.id,
          confidence: m.confidence,
          band: m.band,
          matchedSignals: m.matched_signals,
        },
        locations: [
          {
            physicalLocation: {
              artifactLocation: { uri: report.source },
              logicalLocations: [{ name: cl.id }],
            },
          },
        ],
      });
    }
  }
  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: TOOL_NAME,
            version: TOOL_VERSION,
            informationUri: "https://cognis.digital/agenttax",
            rules,
          },
        },
        results,
      },
    ],
  };
}

// ---- CSV ----
export const CSV_COLUMNS = [
  "finding_id",
  "title",
  "category_id",
  "category_label",
  "reference",
  "confidence",
  "band",
  "matched_signals",
  "mitigation",
  "text",
];

function csvCell(v: string): string {
  if (/[",\n]/.test(v)) return '"' + v.replace(/"/g, '""') + '"';
  return v;
}

export function toCsv(report: Report): string {
  const lines: string[] = [CSV_COLUMNS.join(",")];
  for (const cl of report.classifications) {
    if (cl.matches.length === 0) {
      lines.push([cl.id, cl.title, "", "", "", "", "none", "", "", cl.text].map(csvCell).join(","));
      continue;
    }
    for (const m of cl.matches) {
      lines.push(
        [
          cl.id,
          cl.title,
          m.category_id,
          m.label,
          m.reference,
          m.confidence.toFixed(3),
          m.band,
          m.matched_signals.join("; "),
          m.mitigation,
          cl.text,
        ]
          .map(csvCell)
          .join(",")
      );
    }
  }
  return lines.join("\n");
}

export { TAXONOMY, TOOL_NAME, TOOL_VERSION };
