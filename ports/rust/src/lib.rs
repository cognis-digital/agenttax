//! AGENTTAX — Rust port of the AI-agent threat-taxonomy classifier.
//! Maps security findings onto Microsoft's AI-agent threat taxonomy with
//! per-category mitigations. Passive, offline, no network.

use regex::RegexBuilder;
use std::collections::BTreeMap;
use std::sync::OnceLock;

pub const TOOL_NAME: &str = "agenttax";
pub const TOOL_VERSION: &str = "0.1.1";

const SATURATION: f64 = 5.0;
const BAND_HIGH: f64 = 0.66;
const BAND_MEDIUM: f64 = 0.33;

pub struct Signal {
    pub pattern: &'static str,
    pub weight: f64,
}

pub struct Category {
    pub id: &'static str,
    pub label: &'static str,
    pub reference: &'static str,
    pub description: &'static str,
    pub mitigation: &'static str,
    pub signals: Vec<Signal>,
}

fn s(pattern: &'static str, weight: f64) -> Signal {
    Signal { pattern, weight }
}

/// The seven-category taxonomy. Patterns mirror the Python reference.
pub fn taxonomy() -> &'static Vec<Category> {
    static TAX: OnceLock<Vec<Category>> = OnceLock::new();
    TAX.get_or_init(|| {
        vec![
            Category {
                id: "AGENTIC_SUPPLY_CHAIN_COMPROMISE",
                label: "Agentic Supply Chain Compromise",
                reference: "MS-AIATT/SC",
                description: "An agent depends on a poisoned or tampered artifact — model weights, a downloaded tool/skill, a package, or a remote prompt — that an attacker controls.",
                mitigation: "Pin and verify every agent dependency (model, tool, skill, package) by hash/signature; install from vetted registries only; enforce SBOM + provenance (SLSA) checks in CI and reject unsigned or unpinned artifacts before the agent loads them.",
                signals: vec![
                    s(r"\bsupply[- ]?chain\b", 3.0),
                    s(r"\b(poisoned|tampered|backdoor(ed)?|trojan(ized)?)\b", 2.5),
                    s(r"\b(unsigned|unpinned|unverified)\b.*\b(package|model|tool|skill|dependency|artifact)", 2.0),
                    s(r"\b(typosquat|dependency confusion|malicious package)\b", 2.5),
                    s(r"\b(model weights?|checkpoint|safetensors|pickle)\b.*\b(downloaded|untrusted|public)", 2.0),
                    s(r"\b(pip install|npm install|huggingface|registry)\b.*\b(arbitrary|unverified|attacker)", 1.5),
                    s(r"\bskill\b.*\b(third[- ]party|untrusted|side[- ]load)", 1.5),
                    s(r"\b(no|missing)\b.*\b(hash|signature|checksum|sbom|provenance)\b", 1.5),
                ],
            },
            Category {
                id: "GOAL_HIJACKING",
                label: "Goal Hijacking",
                reference: "MS-AIATT/GH",
                description: "Injected instructions (direct or indirect prompt injection) override the agent's intended objective and redirect its actions.",
                mitigation: "Treat all tool output, retrieved documents, and user content as untrusted data, never as instructions; enforce a signed/immutable system objective, spotlight/delimiter untrusted spans, and gate high-impact actions behind allow-lists and human confirmation.",
                signals: vec![
                    s(r"ignore (all )?(previous|prior|above) (instructions|prompts?)", 3.0),
                    s(r"\b(prompt[- ]?injection|jailbreak)\b", 3.0),
                    s(r"\b(indirect|cross[- ]domain)\b.*injection", 2.5),
                    s(r"\bdisregard\b.*\b(rules|guidelines|policy|system)\b", 2.0),
                    s(r"\b(override|subvert|hijack)\b.*\b(goal|objective|task|instruction)", 2.5),
                    s(r"\bnew instructions?\b.*\b(from now|instead)\b", 1.5),
                    s(r"\b(act as|pretend to be|you are now)\b", 1.0),
                    s(r"\bsmuggl(ed|ing)\b.*\binstruction", 2.0),
                    s(r"\bhidden\b.*\b(instruction|directive|command)\b", 1.5),
                ],
            },
            Category {
                id: "INTER_AGENT_TRUST_ESCALATION",
                label: "Inter-Agent Trust Escalation",
                reference: "MS-AIATT/IA",
                description: "In a multi-agent system one agent implicitly trusts another, letting a compromised or malicious agent escalate privilege, impersonate a role, or relay poisoned instructions across the mesh.",
                mitigation: "Authenticate every agent-to-agent message (mTLS + signed, scoped tokens); apply least-privilege per agent role; never let one agent inherit another's credentials; mediate cross-agent calls through a broker that re-validates authority on each hop.",
                signals: vec![
                    s(r"\b(multi[- ]?agent|agent[- ]?to[- ]?agent|agent mesh|orchestrator)\b", 2.0),
                    s(r"\b(privilege|trust)\b.*\bescalat", 3.0),
                    s(r"\b(impersonat|spoof)\w*\b.*\b(agent|role|service)\b", 2.5),
                    s(r"\b(sub[- ]?agent|worker agent|delegate(d)?)\b.*\b(trust|credential|privilege|unchecked)", 2.0),
                    s(r"\b(confused deputy|relay|pivot)\b", 2.0),
                    s(r"\b(shared|inherited)\b.*\b(credential|token|identity)\b.*\bagent", 2.0),
                    s(r"\bagent\b.*\b(blindly|implicitly)\b.*trust", 2.5),
                    s(r"\bA2A\b", 1.5),
                ],
            },
            Category {
                id: "COMPUTER_USE_AGENT_VISUAL_ATTACK",
                label: "Computer Use Agent Visual Attack",
                reference: "MS-AIATT/CUA",
                description: "A screen-reading / GUI-driving (computer-use) agent is attacked through crafted on-screen content: visual prompt injection, decoy buttons, hidden overlays, or adversarial screenshots.",
                mitigation: "Constrain computer-use agents to allow-listed apps/URLs and actions; require confirmation for irreversible UI actions; detect off-screen/low-contrast/overlay text before acting on it; and isolate the agent in a disposable, monitored sandbox VM.",
                signals: vec![
                    s(r"\b(computer[- ]?use|cua|screen[- ]?reading|gui[- ]?driving)\b", 3.0),
                    s(r"\b(screenshot|screen capture)\b.*\b(inject|manipulat|adversarial|crafted)", 2.5),
                    s(r"\bvisual\b.*\b(prompt[- ]?injection|attack|trick)", 3.0),
                    s(r"\b(decoy|fake|spoofed)\b.*\b(button|ui|dialog|element)\b", 2.5),
                    s(r"\b(overlay|hidden text|invisible text|off[- ]screen)\b", 2.0),
                    s(r"\b(click|type|navigate)\b.*\b(malicious|attacker[- ]controlled|untrusted)\b", 1.5),
                    s(r"\b(ocr|pixel|rendered)\b.*\b(instruction|injection)\b", 2.0),
                    s(r"\bbrowser(-use)? agent\b", 1.5),
                ],
            },
            Category {
                id: "SESSION_CONTEXT_CONTAMINATION",
                label: "Session Context Contamination",
                reference: "MS-AIATT/SCC",
                description: "The agent's context window, memory, or retrieval corpus is contaminated — cross-session/cross-tenant bleed, poisoned conversation history, or tainted RAG documents.",
                mitigation: "Isolate memory and retrieval per session/tenant with hard namespace boundaries; sanitize and provenance-tag everything written to long-term memory or a vector store; expire/scope context aggressively and never reuse another principal's history.",
                signals: vec![
                    s(r"\b(cross[- ]?session|cross[- ]?tenant|session bleed|context bleed)\b", 3.0),
                    s(r"\b(memory|context)\b.*\b(poison|contaminat|leak|bleed)", 2.5),
                    s(r"\b(conversation history|chat history)\b.*\b(poison|inject|tamper)", 2.0),
                    s(r"\brag\b.*\b(poison|tainted|malicious|untrusted)", 2.5),
                    s(r"\b(vector store|embedding|knowledge base)\b.*\b(poison|inject)", 2.0),
                    s(r"\b(persistent|long[- ]?term) memory\b.*\b(attacker|inject|poison|tamper)", 2.0),
                    s(r"\bcontext window\b.*\b(stuff|overflow|inject)", 1.5),
                    s(r"\bdata\b.*\bleak\w*\b.*\bbetween\b.*\b(user|session|tenant)", 2.0),
                ],
            },
            Category {
                id: "MCP_PLUGIN_ABUSE",
                label: "MCP / Plugin Abuse",
                reference: "MS-AIATT/MCP",
                description: "Abuse of a Model Context Protocol server, tool, or plugin: unvetted/over-scoped tools, rug-pull description swaps, or a malicious MCP server exfiltrating data through tool calls.",
                mitigation: "Vet and pin MCP servers/plugins; enforce least-privilege tool scopes and explicit user consent per tool; detect tool-description changes (rug-pull) by hashing manifests; sandbox tool execution and log every invocation for review.",
                signals: vec![
                    s(r"\bmcp\b", 2.0),
                    s(r"\b(model context protocol)\b", 2.5),
                    s(r"\bplugin\b.*\b(malicious|unvetted|over[- ]?scoped|abuse)", 2.0),
                    s(r"\b(rug[- ]?pull|description swap|tool[- ]?poisoning)\b", 3.0),
                    s(r"\btool\b.*\b(over[- ]?privileged|excessive scope|unscoped)\b", 2.0),
                    s(r"\b(mcp server|tool server)\b.*\b(untrusted|malicious|exfiltrat)", 2.5),
                    s(r"\btool[- ]?call\b.*\bexfiltrat", 2.0),
                    s(r"\b(unvetted|third[- ]party)\b.*\b(tool|plugin|mcp)\b", 1.5),
                ],
            },
            Category {
                id: "CAPABILITY_ARCHITECTURE_DISCLOSURE",
                label: "Capability / Architecture Disclosure",
                reference: "MS-AIATT/CAD",
                description: "The agent leaks its own internals: system prompt, available tools, model identity/version, guardrails, or backend architecture — intelligence an attacker uses to plan further attacks.",
                mitigation: "Never echo the system prompt, tool list, or model/architecture details to users; classify and block self-disclosure in output filters; treat prompts/tool schemas as secrets; and return generic errors that do not reveal backend internals.",
                signals: vec![
                    s(r"\b(system prompt|hidden prompt)\b.*\b(leak|disclos|reveal|exfiltrat|dump)", 3.0),
                    s(r"\b(reveal|leak|disclos|dump)\w*\b.*\b(system prompt|instructions|tool list|tools available)", 2.5),
                    s(r"\b(model (name|version|family)|architecture|backend)\b.*\b(disclos|leak|reveal|fingerprint)", 2.0),
                    s(r"\bprint your (instructions|system prompt|tools|configuration)\b", 2.5),
                    s(r"\b(enumerat|fingerprint)\w*\b.*\b(capabilit|tool|model)\b", 2.0),
                    s(r"\b(guardrail|safety filter)\b.*\b(reveal|disclos|enumerat)", 1.5),
                    s(r"\bwhat (tools|capabilities|model)\b.*\byou\b", 1.0),
                    s(r"\binformation disclosure\b", 1.5),
                ],
            },
        ]
    })
}

#[derive(Clone, Debug)]
pub struct CategoryMatch {
    pub category_id: String,
    pub label: String,
    pub reference: String,
    pub confidence: f64,
    pub band: String,
    pub matched_signals: Vec<String>,
    pub mitigation: String,
}

#[derive(Clone, Debug)]
pub struct Classification {
    pub id: String,
    pub title: String,
    pub text: String,
    pub top_band: String,
    pub matches: Vec<CategoryMatch>,
}

#[derive(Clone, Debug)]
pub struct Report {
    pub source: String,
    pub classifications: Vec<Classification>,
}

#[derive(Clone, Debug)]
pub struct Finding {
    pub id: String,
    pub title: String,
    pub text: String,
}

fn band_order(b: &str) -> u8 {
    match b {
        "high" => 0,
        "medium" => 1,
        "low" => 2,
        _ => 3,
    }
}

fn band(conf: f64) -> &'static str {
    if conf >= BAND_HIGH {
        "high"
    } else if conf >= BAND_MEDIUM {
        "medium"
    } else if conf > 0.0 {
        "low"
    } else {
        "none"
    }
}

fn round3(f: f64) -> f64 {
    (f * 1000.0).round() / 1000.0
}

pub fn classify_text(text: &str, min_confidence: f64) -> Vec<CategoryMatch> {
    let mut matches: Vec<CategoryMatch> = Vec::new();
    for cat in taxonomy() {
        let mut raw = 0.0;
        let mut hits: Vec<String> = Vec::new();
        for sig in &cat.signals {
            let re = RegexBuilder::new(sig.pattern)
                .case_insensitive(true)
                .build()
                .expect("valid regex");
            if re.is_match(text) {
                raw += sig.weight;
                hits.push(sig.pattern.to_string());
            }
        }
        if raw <= 0.0 {
            continue;
        }
        let confidence = round3((raw / SATURATION).min(1.0));
        if confidence < min_confidence {
            continue;
        }
        matches.push(CategoryMatch {
            category_id: cat.id.to_string(),
            label: cat.label.to_string(),
            reference: cat.reference.to_string(),
            confidence,
            band: band(confidence).to_string(),
            matched_signals: hits,
            mitigation: cat.mitigation.to_string(),
        });
    }
    matches.sort_by(|a, b| {
        b.confidence
            .partial_cmp(&a.confidence)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(a.category_id.cmp(&b.category_id))
    });
    matches
}

pub fn findings_from_text(text: &str) -> Vec<Finding> {
    let re = regex::Regex::new(r"\n\s*\n|\r?\n").unwrap();
    let mut chunks: Vec<String> = re
        .split(text)
        .map(|c| c.trim().to_string())
        .filter(|c| !c.is_empty())
        .collect();
    if chunks.is_empty() {
        let t = text.trim();
        if !t.is_empty() {
            chunks.push(t.to_string());
        }
    }
    chunks
        .into_iter()
        .enumerate()
        .map(|(i, c)| Finding {
            id: format!("T{}", i + 1),
            title: String::new(),
            text: c,
        })
        .collect()
}

pub fn classify_findings(findings: &[Finding], min_confidence: f64) -> Report {
    let classifications = findings
        .iter()
        .map(|f| {
            let matches = classify_text(&f.text, min_confidence);
            let top_band = matches
                .iter()
                .map(|m| m.band.clone())
                .min_by_key(|b| band_order(b))
                .unwrap_or_else(|| "none".to_string());
            Classification {
                id: f.id.clone(),
                title: f.title.clone(),
                text: f.text.clone(),
                top_band,
                matches,
            }
        })
        .collect();
    Report {
        source: "<findings>".to_string(),
        classifications,
    }
}

pub fn category_counts(report: &Report) -> BTreeMap<String, usize> {
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for cat in taxonomy() {
        counts.insert(cat.id.to_string(), 0);
    }
    for cl in &report.classifications {
        for m in &cl.matches {
            *counts.entry(m.category_id.clone()).or_insert(0) += 1;
        }
    }
    counts
}

pub fn unclassified(report: &Report) -> usize {
    report
        .classifications
        .iter()
        .filter(|c| c.matches.is_empty())
        .count()
}

pub fn fail_triggered(report: &Report, fail_on: &str) -> bool {
    if fail_on == "none" {
        return false;
    }
    let threshold = band_order(fail_on);
    report
        .classifications
        .iter()
        .flat_map(|c| &c.matches)
        .any(|m| band_order(&m.band) <= threshold)
}
