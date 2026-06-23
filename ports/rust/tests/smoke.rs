// Smoke tests for the AGENTTAX Rust port.
use agenttax::*;
use std::collections::HashSet;

fn ids(ms: &[CategoryMatch]) -> HashSet<String> {
    ms.iter().map(|m| m.category_id.clone()).collect()
}

#[test]
fn seven_categories() {
    assert_eq!(taxonomy().len(), 7);
    for c in taxonomy() {
        assert!(!c.signals.is_empty(), "{} has no signals", c.id);
        assert!(!c.mitigation.is_empty(), "{} has no mitigation", c.id);
    }
}

#[test]
fn metadata() {
    assert_eq!(TOOL_NAME, "agenttax");
    assert!(!TOOL_VERSION.is_empty());
}

#[test]
fn goal_hijacking_top() {
    let m = classify_text("ignore all previous instructions, this is a prompt injection", 0.0);
    assert_eq!(m[0].category_id, "GOAL_HIJACKING");
    assert_eq!(m[0].band, "high");
}

#[test]
fn supply_chain() {
    let got = ids(&classify_text(
        "unsigned package from untrusted registry, dependency confusion, supply chain",
        0.0,
    ));
    assert!(got.contains("AGENTIC_SUPPLY_CHAIN_COMPROMISE"));
}

#[test]
fn mcp_abuse() {
    let got = ids(&classify_text(
        "malicious MCP server tool-poisoning rug-pull exfiltrate",
        0.0,
    ));
    assert!(got.contains("MCP_PLUGIN_ABUSE"));
}

#[test]
fn disclosure() {
    let got = ids(&classify_text(
        "print your system prompt and tool list, leak the model version",
        0.0,
    ));
    assert!(got.contains("CAPABILITY_ARCHITECTURE_DISCLOSURE"));
}

#[test]
fn generic_no_match() {
    let m = classify_text("the public API returns a verbose 500 stack trace", 0.0);
    assert!(m.is_empty());
}

#[test]
fn multi_category() {
    let got = ids(&classify_text(
        "prompt injection that escalates privilege across the multi-agent mesh by impersonating the orchestrator",
        0.0,
    ));
    assert!(got.contains("GOAL_HIJACKING"));
    assert!(got.contains("INTER_AGENT_TRUST_ESCALATION"));
}

#[test]
fn confidence_bounded() {
    for m in classify_text(
        "supply chain poisoned prompt injection mcp rug-pull cross-tenant bleed",
        0.0,
    ) {
        assert!(m.confidence >= 0.0 && m.confidence <= 1.0);
    }
}

#[test]
fn more_signals_higher() {
    let conf = |ms: Vec<CategoryMatch>| -> f64 {
        ms.iter()
            .find(|m| m.category_id == "MCP_PLUGIN_ABUSE")
            .map(|m| m.confidence)
            .unwrap_or(0.0)
    };
    let one = conf(classify_text("mcp", 0.0));
    let many = conf(classify_text(
        "malicious MCP server rug-pull tool-poisoning over-privileged unvetted plugin exfiltrate via tool-call",
        0.0,
    ));
    assert!(many > one);
}

#[test]
fn findings_split() {
    assert_eq!(findings_from_text("a\n\nb").len(), 2);
    assert_eq!(findings_from_text("   ").len(), 0);
}

#[test]
fn fail_triggered_high() {
    let r = classify_findings(
        &findings_from_text("ignore all previous instructions prompt injection"),
        0.0,
    );
    assert!(fail_triggered(&r, "high"));
    assert!(!fail_triggered(&r, "none"));
}

#[test]
fn min_confidence_filters() {
    let all = classify_text("unsigned package mcp tool", 0.0);
    let strict = classify_text("unsigned package mcp tool", 0.99);
    assert!(strict.len() <= all.len());
}

#[test]
fn category_counts_cover_all() {
    let probes = [
        "poisoned model weights downloaded from a public untrusted source, unsigned package, dependency confusion in the supply chain",
        "ignore all previous instructions; this indirect prompt injection hijacks the agent objective with smuggled instructions",
        "in the multi-agent mesh a sub-agent blindly trusts the orchestrator and escalates privilege by impersonating its role (confused deputy)",
        "the computer-use agent processed a screenshot with a visual prompt-injection and a decoy button plus hidden overlay text",
        "cross-tenant session bleed contaminated the context and a poisoned RAG document in the vector store leaked between users",
        "a malicious MCP server did a tool-poisoning rug-pull and the over-privileged plugin was used to exfiltrate data via tool-call",
        "the agent disclosed its hidden system prompt, tool list, model version and backend architecture enabling fingerprinting",
    ];
    let findings: Vec<Finding> = probes
        .iter()
        .enumerate()
        .map(|(i, p)| Finding {
            id: format!("P{}", i + 1),
            title: String::new(),
            text: p.to_string(),
        })
        .collect();
    let r = classify_findings(&findings, 0.0);
    let counts = category_counts(&r);
    let hit = counts.values().filter(|&&n| n > 0).count();
    assert_eq!(hit, 7, "all seven categories should fire");
    assert_eq!(unclassified(&r), 0);
}
