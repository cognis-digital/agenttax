"""Core classification engine for AGENTTAX.

Maps free-form security findings / observations onto Microsoft's published
AI-agent threat taxonomy and attaches a concrete mitigation per matched
category.

The taxonomy implemented here (7 categories) mirrors the threat classes
Microsoft describes for agentic AI systems:

  * AGENTIC_SUPPLY_CHAIN_COMPROMISE — poisoned models / tools / packages /
    skills an agent depends on.
  * GOAL_HIJACKING — prompt-injection / instruction-smuggling that subverts
    the agent's objective.
  * INTER_AGENT_TRUST_ESCALATION — one agent over-trusting another, or
    privilege/role escalation across an agent mesh.
  * COMPUTER_USE_AGENT_VISUAL_ATTACK — attacks on screen-reading / GUI-driving
    agents via crafted on-screen content (visual prompt injection, decoy UI).
  * SESSION_CONTEXT_CONTAMINATION — cross-session / cross-tenant memory bleed,
    poisoned conversation history or RAG context.
  * MCP_PLUGIN_ABUSE — abuse of Model Context Protocol servers / tools /
    plugins (rug-pull, unvetted tool, excessive scope).
  * CAPABILITY_ARCHITECTURE_DISCLOSURE — leakage of the agent's system prompt,
    tools, model, or internal architecture.

Classification is transparent and deterministic: each category owns a set of
weighted keyword / regex signals. A finding's text is matched against every
category; matched signals accumulate a raw score that is normalised into a
0.0-1.0 confidence. There is no ML and no network access — everything is
computed locally so the rules are auditable.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional, Tuple

TOOL_NAME = "agenttax"
TOOL_VERSION = "0.1.0"

# Confidence buckets used for table rendering / --fail-on policy.
CONFIDENCE_ORDER = {"high": 0, "medium": 1, "low": 2, "none": 3}


@dataclass
class Signal:
    """A single weighted regex signal belonging to a category."""

    pattern: str
    weight: float
    note: str = ""
    _rx: Optional["re.Pattern[str]"] = field(default=None, repr=False, compare=False)

    def compiled(self) -> "re.Pattern[str]":
        if self._rx is None:
            self._rx = re.compile(self.pattern, re.IGNORECASE)
        return self._rx


@dataclass
class Category:
    """A taxonomy category: id, human label, MS reference, signals, mitigation."""

    id: str
    label: str
    reference: str
    description: str
    mitigation: str
    signals: List[Signal]


# --------------------------------------------------------------------------
# Taxonomy definition — the heart of the tool.
# --------------------------------------------------------------------------
def _s(pattern: str, weight: float, note: str = "") -> Signal:
    return Signal(pattern=pattern, weight=weight, note=note)


TAXONOMY: List[Category] = [
    Category(
        id="AGENTIC_SUPPLY_CHAIN_COMPROMISE",
        label="Agentic Supply Chain Compromise",
        reference="MS-AIATT/SC",
        description=(
            "An agent depends on a poisoned or tampered artifact — model "
            "weights, a downloaded tool/skill, a package, or a remote prompt — "
            "that an attacker controls."
        ),
        mitigation=(
            "Pin and verify every agent dependency (model, tool, skill, "
            "package) by hash/signature; install from vetted registries only; "
            "enforce SBOM + provenance (SLSA) checks in CI and reject "
            "unsigned or unpinned artifacts before the agent loads them."
        ),
        signals=[
            _s(r"\bsupply[- ]?chain\b", 3.0),
            _s(r"\b(poisoned|tampered|backdoor(ed)?|trojan(ized)?)\b", 2.5),
            _s(r"\b(unsigned|unpinned|unverified)\b.*\b(package|model|tool|skill|dependency|artifact)", 2.0),
            _s(r"\b(typosquat|dependency confusion|malicious package)\b", 2.5),
            _s(r"\b(model weights?|checkpoint|safetensors|pickle)\b.*\b(downloaded|untrusted|public)", 2.0),
            _s(r"\b(pip install|npm install|huggingface|registry)\b.*\b(arbitrary|unverified|attacker)", 1.5),
            _s(r"\bskill\b.*\b(third[- ]party|untrusted|side[- ]load)", 1.5),
            _s(r"\b(no|missing)\b.*\b(hash|signature|checksum|sbom|provenance)\b", 1.5),
        ],
    ),
    Category(
        id="GOAL_HIJACKING",
        label="Goal Hijacking",
        reference="MS-AIATT/GH",
        description=(
            "Injected instructions (direct or indirect prompt injection) "
            "override the agent's intended objective and redirect its actions."
        ),
        mitigation=(
            "Treat all tool output, retrieved documents, and user content as "
            "untrusted data, never as instructions; enforce a signed/immutable "
            "system objective, spotlight/delimiter untrusted spans, and gate "
            "high-impact actions behind allow-lists and human confirmation."
        ),
        signals=[
            _s(r"ignore (all )?(previous|prior|above) (instructions|prompts?)", 3.0),
            _s(r"\b(prompt[- ]?injection|jailbreak)\b", 3.0),
            _s(r"\b(indirect|cross[- ]domain)\b.*injection", 2.5),
            _s(r"\bdisregard\b.*\b(rules|guidelines|policy|system)\b", 2.0),
            _s(r"\b(override|subvert|hijack)\b.*\b(goal|objective|task|instruction)", 2.5),
            _s(r"\bnew instructions?\b.*\b(from now|instead)\b", 1.5),
            _s(r"\b(act as|pretend to be|you are now)\b", 1.0),
            _s(r"\bsmuggl(ed|ing)\b.*\binstruction", 2.0),
            _s(r"\bhidden\b.*\b(instruction|directive|command)\b", 1.5),
        ],
    ),
    Category(
        id="INTER_AGENT_TRUST_ESCALATION",
        label="Inter-Agent Trust Escalation",
        reference="MS-AIATT/IA",
        description=(
            "In a multi-agent system one agent implicitly trusts another, "
            "letting a compromised or malicious agent escalate privilege, "
            "impersonate a role, or relay poisoned instructions across the mesh."
        ),
        mitigation=(
            "Authenticate every agent-to-agent message (mTLS + signed, scoped "
            "tokens); apply least-privilege per agent role; never let one "
            "agent inherit another's credentials; mediate cross-agent calls "
            "through a broker that re-validates authority on each hop."
        ),
        signals=[
            _s(r"\b(multi[- ]?agent|agent[- ]?to[- ]?agent|agent mesh|orchestrator)\b", 2.0),
            _s(r"\b(privilege|trust)\b.*\bescalat", 3.0),
            _s(r"\b(impersonat|spoof)\w*\b.*\b(agent|role|service)\b", 2.5),
            _s(r"\b(sub[- ]?agent|worker agent|delegate(d)?)\b.*\b(trust|credential|privilege|unchecked)", 2.0),
            _s(r"\b(confused deputy|relay|pivot)\b", 2.0),
            _s(r"\b(shared|inherited)\b.*\b(credential|token|identity)\b.*\bagent", 2.0),
            _s(r"\bagent\b.*\b(blindly|implicitly)\b.*trust", 2.5),
            _s(r"\bA2A\b", 1.5),
        ],
    ),
    Category(
        id="COMPUTER_USE_AGENT_VISUAL_ATTACK",
        label="Computer Use Agent Visual Attack",
        reference="MS-AIATT/CUA",
        description=(
            "A screen-reading / GUI-driving (computer-use) agent is attacked "
            "through crafted on-screen content: visual prompt injection, "
            "decoy buttons, hidden overlays, or adversarial screenshots."
        ),
        mitigation=(
            "Constrain computer-use agents to allow-listed apps/URLs and "
            "actions; require confirmation for irreversible UI actions; detect "
            "off-screen/low-contrast/overlay text before acting on it; and "
            "isolate the agent in a disposable, monitored sandbox VM."
        ),
        signals=[
            _s(r"\b(computer[- ]?use|cua|screen[- ]?reading|gui[- ]?driving)\b", 3.0),
            _s(r"\b(screenshot|screen capture)\b.*\b(inject|manipulat|adversarial|crafted)", 2.5),
            _s(r"\bvisual\b.*\b(prompt[- ]?injection|attack|trick)", 3.0),
            _s(r"\b(decoy|fake|spoofed)\b.*\b(button|ui|dialog|element)\b", 2.5),
            _s(r"\b(overlay|hidden text|invisible text|off[- ]screen)\b", 2.0),
            _s(r"\b(click|type|navigate)\b.*\b(malicious|attacker[- ]controlled|untrusted)\b", 1.5),
            _s(r"\b(ocr|pixel|rendered)\b.*\b(instruction|injection)\b", 2.0),
            _s(r"\bbrowser(-use)? agent\b", 1.5),
        ],
    ),
    Category(
        id="SESSION_CONTEXT_CONTAMINATION",
        label="Session Context Contamination",
        reference="MS-AIATT/SCC",
        description=(
            "The agent's context window, memory, or retrieval corpus is "
            "contaminated — cross-session/cross-tenant bleed, poisoned "
            "conversation history, or tainted RAG documents."
        ),
        mitigation=(
            "Isolate memory and retrieval per session/tenant with hard "
            "namespace boundaries; sanitize and provenance-tag everything "
            "written to long-term memory or a vector store; expire/scope "
            "context aggressively and never reuse another principal's history."
        ),
        signals=[
            _s(r"\b(cross[- ]?session|cross[- ]?tenant|session bleed|context bleed)\b", 3.0),
            _s(r"\b(memory|context)\b.*\b(poison|contaminat|leak|bleed)", 2.5),
            _s(r"\b(conversation history|chat history)\b.*\b(poison|inject|tamper)", 2.0),
            _s(r"\brag\b.*\b(poison|tainted|malicious|untrusted)", 2.5),
            _s(r"\b(vector store|embedding|knowledge base)\b.*\b(poison|inject)", 2.0),
            _s(r"\b(persistent|long[- ]?term) memory\b.*\b(attacker|inject|poison|tamper)", 2.0),
            _s(r"\bcontext window\b.*\b(stuff|overflow|inject)", 1.5),
            _s(r"\bdata\b.*\bleak\w*\b.*\bbetween\b.*\b(user|session|tenant)", 2.0),
        ],
    ),
    Category(
        id="MCP_PLUGIN_ABUSE",
        label="MCP / Plugin Abuse",
        reference="MS-AIATT/MCP",
        description=(
            "Abuse of a Model Context Protocol server, tool, or plugin: "
            "unvetted/over-scoped tools, rug-pull description swaps, or a "
            "malicious MCP server exfiltrating data through tool calls."
        ),
        mitigation=(
            "Vet and pin MCP servers/plugins; enforce least-privilege tool "
            "scopes and explicit user consent per tool; detect tool-description "
            "changes (rug-pull) by hashing manifests; sandbox tool execution "
            "and log every invocation for review."
        ),
        signals=[
            _s(r"\bmcp\b", 2.0),
            _s(r"\b(model context protocol)\b", 2.5),
            _s(r"\bplugin\b.*\b(malicious|unvetted|over[- ]?scoped|abuse)", 2.0),
            _s(r"\b(rug[- ]?pull|description swap|tool[- ]?poisoning)\b", 3.0),
            _s(r"\btool\b.*\b(over[- ]?privileged|excessive scope|unscoped)\b", 2.0),
            _s(r"\b(mcp server|tool server)\b.*\b(untrusted|malicious|exfiltrat)", 2.5),
            _s(r"\btool[- ]?call\b.*\bexfiltrat", 2.0),
            _s(r"\b(unvetted|third[- ]party)\b.*\b(tool|plugin|mcp)\b", 1.5),
        ],
    ),
    Category(
        id="CAPABILITY_ARCHITECTURE_DISCLOSURE",
        label="Capability / Architecture Disclosure",
        reference="MS-AIATT/CAD",
        description=(
            "The agent leaks its own internals: system prompt, available "
            "tools, model identity/version, guardrails, or backend "
            "architecture — intelligence an attacker uses to plan further "
            "attacks."
        ),
        mitigation=(
            "Never echo the system prompt, tool list, or model/architecture "
            "details to users; classify and block self-disclosure in output "
            "filters; treat prompts/tool schemas as secrets; and return "
            "generic errors that do not reveal backend internals."
        ),
        signals=[
            _s(r"\b(system prompt|hidden prompt)\b.*\b(leak|disclos|reveal|exfiltrat|dump)", 3.0),
            _s(r"\b(reveal|leak|disclos|dump)\w*\b.*\b(system prompt|instructions|tool list|tools available)", 2.5),
            _s(r"\b(model (name|version|family)|architecture|backend)\b.*\b(disclos|leak|reveal|fingerprint)", 2.0),
            _s(r"\bprint your (instructions|system prompt|tools|configuration)\b", 2.5),
            _s(r"\b(enumerat|fingerprint)\w*\b.*\b(capabilit|tool|model)\b", 2.0),
            _s(r"\b(guardrail|safety filter)\b.*\b(reveal|disclos|enumerat)", 1.5),
            _s(r"\bwhat (tools|capabilities|model)\b.*\byou\b", 1.0),
            _s(r"\binformation disclosure\b", 1.5),
        ],
    ),
]

_CATEGORY_BY_ID = {c.id: c for c in TAXONOMY}

# Normalisation: a category's raw score is divided by this saturating value so
# that a couple of strong hits already yield high confidence, but confidence is
# bounded at 1.0.
_SATURATION = 5.0

# Confidence band thresholds.
_BAND_HIGH = 0.66
_BAND_MEDIUM = 0.33


class FindingsError(ValueError):
    """Raised when a findings document cannot be parsed."""


@dataclass
class CategoryMatch:
    category_id: str
    label: str
    reference: str
    confidence: float
    band: str
    matched_signals: List[str]
    mitigation: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Classification:
    finding_id: str
    title: str
    text: str
    matches: List[CategoryMatch] = field(default_factory=list)

    @property
    def top_band(self) -> str:
        if not self.matches:
            return "none"
        return min((m.band for m in self.matches), key=lambda b: CONFIDENCE_ORDER[b])

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.finding_id,
            "title": self.title,
            "text": self.text,
            "top_band": self.top_band,
            "matches": [m.to_dict() for m in self.matches],
        }


@dataclass
class Report:
    source: str
    classifications: List[Classification] = field(default_factory=list)

    @property
    def category_counts(self) -> Dict[str, int]:
        c: Dict[str, int] = {cat.id: 0 for cat in TAXONOMY}
        for cl in self.classifications:
            for m in cl.matches:
                c[m.category_id] = c.get(m.category_id, 0) + 1
        return c

    @property
    def unclassified(self) -> int:
        return sum(1 for cl in self.classifications if not cl.matches)

    def highest_band(self) -> str:
        bands = [cl.top_band for cl in self.classifications]
        if not bands:
            return "none"
        return min(bands, key=lambda b: CONFIDENCE_ORDER[b])

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool": TOOL_NAME,
            "version": TOOL_VERSION,
            "source": self.source,
            "summary": {
                "findings": len(self.classifications),
                "classified": len(self.classifications) - self.unclassified,
                "unclassified": self.unclassified,
                "by_category": self.category_counts,
                "highest_confidence": self.highest_band(),
            },
            "classifications": [c.to_dict() for c in self.classifications],
        }


# --------------------------------------------------------------------------
# Loading
# --------------------------------------------------------------------------
def _band(conf: float) -> str:
    if conf >= _BAND_HIGH:
        return "high"
    if conf >= _BAND_MEDIUM:
        return "medium"
    if conf > 0:
        return "low"
    return "none"


def load_findings(path: str) -> List[Dict[str, Any]]:
    """Load a findings JSON file into a normalised list of dict findings.

    Accepts either a top-level list, or an object with a ``findings`` array.
    Each finding may use ``id``/``title``/``description``/``text``/``message``
    keys (flexible to match common scanner outputs).
    """
    with open(path, "r", encoding="utf-8") as fh:
        raw = fh.read()
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise FindingsError(f"invalid JSON in {path}: {exc}") from exc
    return normalize_findings(data)


def normalize_findings(data: Any) -> List[Dict[str, Any]]:
    if isinstance(data, dict):
        items = data.get("findings")
        if items is None:
            # A single finding object.
            items = [data]
    elif isinstance(data, list):
        items = data
    else:
        raise FindingsError("findings root must be a JSON object or array")
    if not isinstance(items, list):
        raise FindingsError("`findings` must be an array")

    out: List[Dict[str, Any]] = []
    for idx, item in enumerate(items):
        if isinstance(item, str):
            out.append({"id": f"F{idx + 1}", "title": "", "text": item})
            continue
        if not isinstance(item, dict):
            raise FindingsError(f"finding #{idx} must be an object or string")
        fid = str(item.get("id") or item.get("rule") or f"F{idx + 1}")
        title = str(item.get("title") or item.get("name") or "")
        text_parts = [
            str(item.get(k, ""))
            for k in ("title", "name", "description", "text", "message",
                      "detail", "summary", "observation")
        ]
        text = " ".join(p for p in text_parts if p).strip()
        if not text:
            text = json.dumps(item)
        out.append({"id": fid, "title": title, "text": text})
    return out


def findings_from_text(text: str) -> List[Dict[str, Any]]:
    """Split a free-text blob into findings (one per non-empty line/para)."""
    chunks = [c.strip() for c in re.split(r"\n\s*\n|\r?\n", text) if c.strip()]
    if not chunks:
        chunks = [text.strip()] if text.strip() else []
    return [{"id": f"T{i + 1}", "title": "", "text": c}
            for i, c in enumerate(chunks)]


# --------------------------------------------------------------------------
# Classification
# --------------------------------------------------------------------------
def classify_text(text: str, min_confidence: float = 0.0) -> List[CategoryMatch]:
    """Classify a single text blob against every taxonomy category."""
    matches: List[CategoryMatch] = []
    for cat in TAXONOMY:
        raw = 0.0
        hit_notes: List[str] = []
        for sig in cat.signals:
            if sig.compiled().search(text):
                raw += sig.weight
                hit_notes.append(sig.pattern)
        if raw <= 0:
            continue
        confidence = round(min(1.0, raw / _SATURATION), 3)
        if confidence < min_confidence:
            continue
        matches.append(CategoryMatch(
            category_id=cat.id,
            label=cat.label,
            reference=cat.reference,
            confidence=confidence,
            band=_band(confidence),
            matched_signals=hit_notes,
            mitigation=cat.mitigation,
        ))
    matches.sort(key=lambda m: (-m.confidence, m.category_id))
    return matches


def classify_findings(findings: List[Dict[str, Any]], source: str = "<findings>",
                      min_confidence: float = 0.0) -> Report:
    """Classify a list of normalised findings into a Report."""
    classifications: List[Classification] = []
    for f in findings:
        text = f.get("text", "")
        matches = classify_text(text, min_confidence=min_confidence)
        classifications.append(Classification(
            finding_id=str(f.get("id", "")),
            title=str(f.get("title", "")),
            text=text,
            matches=matches,
        ))
    return Report(source=source, classifications=classifications)


# Convenience alias mirroring the suite's common `scan` entry point.
def scan(target: str, min_confidence: float = 0.0) -> Dict[str, Any]:
    """Classify findings from a file path (suite-standard scan entry point)."""
    findings = load_findings(target)
    report = classify_findings(findings, source=target, min_confidence=min_confidence)
    return report.to_dict()


def get_taxonomy() -> List[Dict[str, Any]]:
    """Return the taxonomy as plain dicts (for docs / MCP introspection)."""
    return [
        {
            "id": c.id,
            "label": c.label,
            "reference": c.reference,
            "description": c.description,
            "mitigation": c.mitigation,
            "signal_count": len(c.signals),
        }
        for c in TAXONOMY
    ]


# --------------------------------------------------------------------------
# SARIF output
# --------------------------------------------------------------------------
def to_sarif(report: Report) -> Dict[str, Any]:
    """Render a Report as a SARIF 2.1.0 document.

    Each taxonomy category becomes a SARIF rule; each (finding × matched
    category) becomes a SARIF result with the confidence in properties.
    """
    rules = []
    rule_index: Dict[str, int] = {}
    for i, cat in enumerate(TAXONOMY):
        rule_index[cat.id] = i
        rules.append({
            "id": cat.id,
            "name": cat.label,
            "shortDescription": {"text": cat.label},
            "fullDescription": {"text": cat.description},
            "helpUri": "https://cognis.digital/agenttax",
            "help": {"text": "Mitigation: " + cat.mitigation},
            "properties": {"reference": cat.reference,
                           "tags": ["ai-security", "agentic", "microsoft-taxonomy"]},
        })

    band_to_level = {"high": "error", "medium": "warning",
                     "low": "note", "none": "none"}
    results = []
    for cl in report.classifications:
        for m in cl.matches:
            results.append({
                "ruleId": m.category_id,
                "ruleIndex": rule_index[m.category_id],
                "level": band_to_level.get(m.band, "note"),
                "message": {
                    "text": (f"[{m.label}] {cl.finding_id}: confidence "
                             f"{m.confidence:.2f} ({m.band}). "
                             f"Mitigation: {m.mitigation}")
                },
                "properties": {
                    "findingId": cl.finding_id,
                    "confidence": m.confidence,
                    "band": m.band,
                    "matchedSignals": m.matched_signals,
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": report.source},
                        "logicalLocations": [{"name": cl.finding_id}],
                    }
                }],
            })

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": TOOL_NAME,
                    "version": TOOL_VERSION,
                    "informationUri": "https://cognis.digital/agenttax",
                    "rules": rules,
                }
            },
            "results": results,
        }],
    }
