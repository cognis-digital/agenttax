// Package agenttax — Go port of the AGENTTAX classifier.
// Maps security findings onto Microsoft's AI-agent threat taxonomy.
// Passive, offline, no network. Standard library only.
package agenttax

import "regexp"

const (
	ToolName    = "agenttax"
	ToolVersion = "0.1.1"

	saturation = 5.0
	bandHigh   = 0.66
	bandMedium = 0.33
)

// Signal is a single weighted regex belonging to a category.
type Signal struct {
	Pattern string
	Weight  float64
	rx      *regexp.Regexp
}

func (s *Signal) compiled() *regexp.Regexp {
	if s.rx == nil {
		s.rx = regexp.MustCompile("(?i)" + s.Pattern)
	}
	return s.rx
}

// Category is a taxonomy entry: id, label, MS reference, description, mitigation, signals.
type Category struct {
	ID          string
	Label       string
	Reference   string
	Description string
	Mitigation  string
	Signals     []Signal
}

func sig(p string, w float64) Signal { return Signal{Pattern: p, Weight: w} }

// Taxonomy is the seven-category AI-agent threat taxonomy. Patterns mirror the
// Python reference implementation so classification is consistent across ports.
var Taxonomy = []Category{
	{
		ID:          "AGENTIC_SUPPLY_CHAIN_COMPROMISE",
		Label:       "Agentic Supply Chain Compromise",
		Reference:   "MS-AIATT/SC",
		Description: "An agent depends on a poisoned or tampered artifact — model weights, a downloaded tool/skill, a package, or a remote prompt — that an attacker controls.",
		Mitigation:  "Pin and verify every agent dependency (model, tool, skill, package) by hash/signature; install from vetted registries only; enforce SBOM + provenance (SLSA) checks in CI and reject unsigned or unpinned artifacts before the agent loads them.",
		Signals: []Signal{
			sig(`\bsupply[- ]?chain\b`, 3.0),
			sig(`\b(poisoned|tampered|backdoor(ed)?|trojan(ized)?)\b`, 2.5),
			sig(`\b(unsigned|unpinned|unverified)\b.*\b(package|model|tool|skill|dependency|artifact)`, 2.0),
			sig(`\b(typosquat|dependency confusion|malicious package)\b`, 2.5),
			sig(`\b(model weights?|checkpoint|safetensors|pickle)\b.*\b(downloaded|untrusted|public)`, 2.0),
			sig(`\b(pip install|npm install|huggingface|registry)\b.*\b(arbitrary|unverified|attacker)`, 1.5),
			sig(`\bskill\b.*\b(third[- ]party|untrusted|side[- ]load)`, 1.5),
			sig(`\b(no|missing)\b.*\b(hash|signature|checksum|sbom|provenance)\b`, 1.5),
		},
	},
	{
		ID:          "GOAL_HIJACKING",
		Label:       "Goal Hijacking",
		Reference:   "MS-AIATT/GH",
		Description: "Injected instructions (direct or indirect prompt injection) override the agent's intended objective and redirect its actions.",
		Mitigation:  "Treat all tool output, retrieved documents, and user content as untrusted data, never as instructions; enforce a signed/immutable system objective, spotlight/delimiter untrusted spans, and gate high-impact actions behind allow-lists and human confirmation.",
		Signals: []Signal{
			sig(`ignore (all )?(previous|prior|above) (instructions|prompts?)`, 3.0),
			sig(`\b(prompt[- ]?injection|jailbreak)\b`, 3.0),
			sig(`\b(indirect|cross[- ]domain)\b.*injection`, 2.5),
			sig(`\bdisregard\b.*\b(rules|guidelines|policy|system)\b`, 2.0),
			sig(`\b(override|subvert|hijack)\b.*\b(goal|objective|task|instruction)`, 2.5),
			sig(`\bnew instructions?\b.*\b(from now|instead)\b`, 1.5),
			sig(`\b(act as|pretend to be|you are now)\b`, 1.0),
			sig(`\bsmuggl(ed|ing)\b.*\binstruction`, 2.0),
			sig(`\bhidden\b.*\b(instruction|directive|command)\b`, 1.5),
		},
	},
	{
		ID:          "INTER_AGENT_TRUST_ESCALATION",
		Label:       "Inter-Agent Trust Escalation",
		Reference:   "MS-AIATT/IA",
		Description: "In a multi-agent system one agent implicitly trusts another, letting a compromised or malicious agent escalate privilege, impersonate a role, or relay poisoned instructions across the mesh.",
		Mitigation:  "Authenticate every agent-to-agent message (mTLS + signed, scoped tokens); apply least-privilege per agent role; never let one agent inherit another's credentials; mediate cross-agent calls through a broker that re-validates authority on each hop.",
		Signals: []Signal{
			sig(`\b(multi[- ]?agent|agent[- ]?to[- ]?agent|agent mesh|orchestrator)\b`, 2.0),
			sig(`\b(privilege|trust)\b.*\bescalat`, 3.0),
			sig(`\b(impersonat|spoof)\w*\b.*\b(agent|role|service)\b`, 2.5),
			sig(`\b(sub[- ]?agent|worker agent|delegate(d)?)\b.*\b(trust|credential|privilege|unchecked)`, 2.0),
			sig(`\b(confused deputy|relay|pivot)\b`, 2.0),
			sig(`\b(shared|inherited)\b.*\b(credential|token|identity)\b.*\bagent`, 2.0),
			sig(`\bagent\b.*\b(blindly|implicitly)\b.*trust`, 2.5),
			sig(`\bA2A\b`, 1.5),
		},
	},
	{
		ID:          "COMPUTER_USE_AGENT_VISUAL_ATTACK",
		Label:       "Computer Use Agent Visual Attack",
		Reference:   "MS-AIATT/CUA",
		Description: "A screen-reading / GUI-driving (computer-use) agent is attacked through crafted on-screen content: visual prompt injection, decoy buttons, hidden overlays, or adversarial screenshots.",
		Mitigation:  "Constrain computer-use agents to allow-listed apps/URLs and actions; require confirmation for irreversible UI actions; detect off-screen/low-contrast/overlay text before acting on it; and isolate the agent in a disposable, monitored sandbox VM.",
		Signals: []Signal{
			sig(`\b(computer[- ]?use|cua|screen[- ]?reading|gui[- ]?driving)\b`, 3.0),
			sig(`\b(screenshot|screen capture)\b.*\b(inject|manipulat|adversarial|crafted)`, 2.5),
			sig(`\bvisual\b.*\b(prompt[- ]?injection|attack|trick)`, 3.0),
			sig(`\b(decoy|fake|spoofed)\b.*\b(button|ui|dialog|element)\b`, 2.5),
			sig(`\b(overlay|hidden text|invisible text|off[- ]screen)\b`, 2.0),
			sig(`\b(click|type|navigate)\b.*\b(malicious|attacker[- ]controlled|untrusted)\b`, 1.5),
			sig(`\b(ocr|pixel|rendered)\b.*\b(instruction|injection)\b`, 2.0),
			sig(`\bbrowser(-use)? agent\b`, 1.5),
		},
	},
	{
		ID:          "SESSION_CONTEXT_CONTAMINATION",
		Label:       "Session Context Contamination",
		Reference:   "MS-AIATT/SCC",
		Description: "The agent's context window, memory, or retrieval corpus is contaminated — cross-session/cross-tenant bleed, poisoned conversation history, or tainted RAG documents.",
		Mitigation:  "Isolate memory and retrieval per session/tenant with hard namespace boundaries; sanitize and provenance-tag everything written to long-term memory or a vector store; expire/scope context aggressively and never reuse another principal's history.",
		Signals: []Signal{
			sig(`\b(cross[- ]?session|cross[- ]?tenant|session bleed|context bleed)\b`, 3.0),
			sig(`\b(memory|context)\b.*\b(poison|contaminat|leak|bleed)`, 2.5),
			sig(`\b(conversation history|chat history)\b.*\b(poison|inject|tamper)`, 2.0),
			sig(`\brag\b.*\b(poison|tainted|malicious|untrusted)`, 2.5),
			sig(`\b(vector store|embedding|knowledge base)\b.*\b(poison|inject)`, 2.0),
			sig(`\b(persistent|long[- ]?term) memory\b.*\b(attacker|inject|poison|tamper)`, 2.0),
			sig(`\bcontext window\b.*\b(stuff|overflow|inject)`, 1.5),
			sig(`\bdata\b.*\bleak\w*\b.*\bbetween\b.*\b(user|session|tenant)`, 2.0),
		},
	},
	{
		ID:          "MCP_PLUGIN_ABUSE",
		Label:       "MCP / Plugin Abuse",
		Reference:   "MS-AIATT/MCP",
		Description: "Abuse of a Model Context Protocol server, tool, or plugin: unvetted/over-scoped tools, rug-pull description swaps, or a malicious MCP server exfiltrating data through tool calls.",
		Mitigation:  "Vet and pin MCP servers/plugins; enforce least-privilege tool scopes and explicit user consent per tool; detect tool-description changes (rug-pull) by hashing manifests; sandbox tool execution and log every invocation for review.",
		Signals: []Signal{
			sig(`\bmcp\b`, 2.0),
			sig(`\b(model context protocol)\b`, 2.5),
			sig(`\bplugin\b.*\b(malicious|unvetted|over[- ]?scoped|abuse)`, 2.0),
			sig(`\b(rug[- ]?pull|description swap|tool[- ]?poisoning)\b`, 3.0),
			sig(`\btool\b.*\b(over[- ]?privileged|excessive scope|unscoped)\b`, 2.0),
			sig(`\b(mcp server|tool server)\b.*\b(untrusted|malicious|exfiltrat)`, 2.5),
			sig(`\btool[- ]?call\b.*\bexfiltrat`, 2.0),
			sig(`\b(unvetted|third[- ]party)\b.*\b(tool|plugin|mcp)\b`, 1.5),
		},
	},
	{
		ID:          "CAPABILITY_ARCHITECTURE_DISCLOSURE",
		Label:       "Capability / Architecture Disclosure",
		Reference:   "MS-AIATT/CAD",
		Description: "The agent leaks its own internals: system prompt, available tools, model identity/version, guardrails, or backend architecture — intelligence an attacker uses to plan further attacks.",
		Mitigation:  "Never echo the system prompt, tool list, or model/architecture details to users; classify and block self-disclosure in output filters; treat prompts/tool schemas as secrets; and return generic errors that do not reveal backend internals.",
		Signals: []Signal{
			sig(`\b(system prompt|hidden prompt)\b.*\b(leak|disclos|reveal|exfiltrat|dump)`, 3.0),
			sig(`\b(reveal|leak|disclos|dump)\w*\b.*\b(system prompt|instructions|tool list|tools available)`, 2.5),
			sig(`\b(model (name|version|family)|architecture|backend)\b.*\b(disclos|leak|reveal|fingerprint)`, 2.0),
			sig(`\bprint your (instructions|system prompt|tools|configuration)\b`, 2.5),
			sig(`\b(enumerat|fingerprint)\w*\b.*\b(capabilit|tool|model)\b`, 2.0),
			sig(`\b(guardrail|safety filter)\b.*\b(reveal|disclos|enumerat)`, 1.5),
			sig(`\bwhat (tools|capabilities|model)\b.*\byou\b`, 1.0),
			sig(`\binformation disclosure\b`, 1.5),
		},
	},
}
