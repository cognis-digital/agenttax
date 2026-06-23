// AGENTTAX taxonomy — TypeScript/Node port of agenttax/core.py.
// Signal patterns mirror the Python reference so classification matches.
// Passive, offline, no network. stdlib only (no runtime deps).

export interface Signal {
  pattern: string;
  weight: number;
}

export interface Category {
  id: string;
  label: string;
  reference: string;
  description: string;
  mitigation: string;
  signals: Signal[];
}

const s = (pattern: string, weight: number): Signal => ({ pattern, weight });

export const TOOL_NAME = "agenttax";
export const TOOL_VERSION = "0.1.1";

export const TAXONOMY: Category[] = [
  {
    id: "AGENTIC_SUPPLY_CHAIN_COMPROMISE",
    label: "Agentic Supply Chain Compromise",
    reference: "MS-AIATT/SC",
    description:
      "An agent depends on a poisoned or tampered artifact — model weights, a " +
      "downloaded tool/skill, a package, or a remote prompt — that an attacker controls.",
    mitigation:
      "Pin and verify every agent dependency (model, tool, skill, package) by " +
      "hash/signature; install from vetted registries only; enforce SBOM + provenance " +
      "(SLSA) checks in CI and reject unsigned or unpinned artifacts before the agent loads them.",
    signals: [
      s("\\bsupply[- ]?chain\\b", 3.0),
      s("\\b(poisoned|tampered|backdoor(ed)?|trojan(ized)?)\\b", 2.5),
      s("\\b(unsigned|unpinned|unverified)\\b.*\\b(package|model|tool|skill|dependency|artifact)", 2.0),
      s("\\b(typosquat|dependency confusion|malicious package)\\b", 2.5),
      s("\\b(model weights?|checkpoint|safetensors|pickle)\\b.*\\b(downloaded|untrusted|public)", 2.0),
      s("\\b(pip install|npm install|huggingface|registry)\\b.*\\b(arbitrary|unverified|attacker)", 1.5),
      s("\\bskill\\b.*\\b(third[- ]party|untrusted|side[- ]load)", 1.5),
      s("\\b(no|missing)\\b.*\\b(hash|signature|checksum|sbom|provenance)\\b", 1.5),
    ],
  },
  {
    id: "GOAL_HIJACKING",
    label: "Goal Hijacking",
    reference: "MS-AIATT/GH",
    description:
      "Injected instructions (direct or indirect prompt injection) override the " +
      "agent's intended objective and redirect its actions.",
    mitigation:
      "Treat all tool output, retrieved documents, and user content as untrusted data, " +
      "never as instructions; enforce a signed/immutable system objective, " +
      "spotlight/delimiter untrusted spans, and gate high-impact actions behind " +
      "allow-lists and human confirmation.",
    signals: [
      s("ignore (all )?(previous|prior|above) (instructions|prompts?)", 3.0),
      s("\\b(prompt[- ]?injection|jailbreak)\\b", 3.0),
      s("\\b(indirect|cross[- ]domain)\\b.*injection", 2.5),
      s("\\bdisregard\\b.*\\b(rules|guidelines|policy|system)\\b", 2.0),
      s("\\b(override|subvert|hijack)\\b.*\\b(goal|objective|task|instruction)", 2.5),
      s("\\bnew instructions?\\b.*\\b(from now|instead)\\b", 1.5),
      s("\\b(act as|pretend to be|you are now)\\b", 1.0),
      s("\\bsmuggl(ed|ing)\\b.*\\binstruction", 2.0),
      s("\\bhidden\\b.*\\b(instruction|directive|command)\\b", 1.5),
    ],
  },
  {
    id: "INTER_AGENT_TRUST_ESCALATION",
    label: "Inter-Agent Trust Escalation",
    reference: "MS-AIATT/IA",
    description:
      "In a multi-agent system one agent implicitly trusts another, letting a " +
      "compromised or malicious agent escalate privilege, impersonate a role, or relay " +
      "poisoned instructions across the mesh.",
    mitigation:
      "Authenticate every agent-to-agent message (mTLS + signed, scoped tokens); apply " +
      "least-privilege per agent role; never let one agent inherit another's credentials; " +
      "mediate cross-agent calls through a broker that re-validates authority on each hop.",
    signals: [
      s("\\b(multi[- ]?agent|agent[- ]?to[- ]?agent|agent mesh|orchestrator)\\b", 2.0),
      s("\\b(privilege|trust)\\b.*\\bescalat", 3.0),
      s("\\b(impersonat|spoof)\\w*\\b.*\\b(agent|role|service)\\b", 2.5),
      s("\\b(sub[- ]?agent|worker agent|delegate(d)?)\\b.*\\b(trust|credential|privilege|unchecked)", 2.0),
      s("\\b(confused deputy|relay|pivot)\\b", 2.0),
      s("\\b(shared|inherited)\\b.*\\b(credential|token|identity)\\b.*\\bagent", 2.0),
      s("\\bagent\\b.*\\b(blindly|implicitly)\\b.*trust", 2.5),
      s("\\bA2A\\b", 1.5),
    ],
  },
  {
    id: "COMPUTER_USE_AGENT_VISUAL_ATTACK",
    label: "Computer Use Agent Visual Attack",
    reference: "MS-AIATT/CUA",
    description:
      "A screen-reading / GUI-driving (computer-use) agent is attacked through crafted " +
      "on-screen content: visual prompt injection, decoy buttons, hidden overlays, or " +
      "adversarial screenshots.",
    mitigation:
      "Constrain computer-use agents to allow-listed apps/URLs and actions; require " +
      "confirmation for irreversible UI actions; detect off-screen/low-contrast/overlay " +
      "text before acting on it; and isolate the agent in a disposable, monitored sandbox VM.",
    signals: [
      s("\\b(computer[- ]?use|cua|screen[- ]?reading|gui[- ]?driving)\\b", 3.0),
      s("\\b(screenshot|screen capture)\\b.*\\b(inject|manipulat|adversarial|crafted)", 2.5),
      s("\\bvisual\\b.*\\b(prompt[- ]?injection|attack|trick)", 3.0),
      s("\\b(decoy|fake|spoofed)\\b.*\\b(button|ui|dialog|element)\\b", 2.5),
      s("\\b(overlay|hidden text|invisible text|off[- ]screen)\\b", 2.0),
      s("\\b(click|type|navigate)\\b.*\\b(malicious|attacker[- ]controlled|untrusted)\\b", 1.5),
      s("\\b(ocr|pixel|rendered)\\b.*\\b(instruction|injection)\\b", 2.0),
      s("\\bbrowser(-use)? agent\\b", 1.5),
    ],
  },
  {
    id: "SESSION_CONTEXT_CONTAMINATION",
    label: "Session Context Contamination",
    reference: "MS-AIATT/SCC",
    description:
      "The agent's context window, memory, or retrieval corpus is contaminated — " +
      "cross-session/cross-tenant bleed, poisoned conversation history, or tainted RAG documents.",
    mitigation:
      "Isolate memory and retrieval per session/tenant with hard namespace boundaries; " +
      "sanitize and provenance-tag everything written to long-term memory or a vector store; " +
      "expire/scope context aggressively and never reuse another principal's history.",
    signals: [
      s("\\b(cross[- ]?session|cross[- ]?tenant|session bleed|context bleed)\\b", 3.0),
      s("\\b(memory|context)\\b.*\\b(poison|contaminat|leak|bleed)", 2.5),
      s("\\b(conversation history|chat history)\\b.*\\b(poison|inject|tamper)", 2.0),
      s("\\brag\\b.*\\b(poison|tainted|malicious|untrusted)", 2.5),
      s("\\b(vector store|embedding|knowledge base)\\b.*\\b(poison|inject)", 2.0),
      s("\\b(persistent|long[- ]?term) memory\\b.*\\b(attacker|inject|poison|tamper)", 2.0),
      s("\\bcontext window\\b.*\\b(stuff|overflow|inject)", 1.5),
      s("\\bdata\\b.*\\bleak\\w*\\b.*\\bbetween\\b.*\\b(user|session|tenant)", 2.0),
    ],
  },
  {
    id: "MCP_PLUGIN_ABUSE",
    label: "MCP / Plugin Abuse",
    reference: "MS-AIATT/MCP",
    description:
      "Abuse of a Model Context Protocol server, tool, or plugin: unvetted/over-scoped " +
      "tools, rug-pull description swaps, or a malicious MCP server exfiltrating data through tool calls.",
    mitigation:
      "Vet and pin MCP servers/plugins; enforce least-privilege tool scopes and explicit " +
      "user consent per tool; detect tool-description changes (rug-pull) by hashing manifests; " +
      "sandbox tool execution and log every invocation for review.",
    signals: [
      s("\\bmcp\\b", 2.0),
      s("\\b(model context protocol)\\b", 2.5),
      s("\\bplugin\\b.*\\b(malicious|unvetted|over[- ]?scoped|abuse)", 2.0),
      s("\\b(rug[- ]?pull|description swap|tool[- ]?poisoning)\\b", 3.0),
      s("\\btool\\b.*\\b(over[- ]?privileged|excessive scope|unscoped)\\b", 2.0),
      s("\\b(mcp server|tool server)\\b.*\\b(untrusted|malicious|exfiltrat)", 2.5),
      s("\\btool[- ]?call\\b.*\\bexfiltrat", 2.0),
      s("\\b(unvetted|third[- ]party)\\b.*\\b(tool|plugin|mcp)\\b", 1.5),
    ],
  },
  {
    id: "CAPABILITY_ARCHITECTURE_DISCLOSURE",
    label: "Capability / Architecture Disclosure",
    reference: "MS-AIATT/CAD",
    description:
      "The agent leaks its own internals: system prompt, available tools, model " +
      "identity/version, guardrails, or backend architecture — intelligence an attacker " +
      "uses to plan further attacks.",
    mitigation:
      "Never echo the system prompt, tool list, or model/architecture details to users; " +
      "classify and block self-disclosure in output filters; treat prompts/tool schemas " +
      "as secrets; and return generic errors that do not reveal backend internals.",
    signals: [
      s("\\b(system prompt|hidden prompt)\\b.*\\b(leak|disclos|reveal|exfiltrat|dump)", 3.0),
      s("\\b(reveal|leak|disclos|dump)\\w*\\b.*\\b(system prompt|instructions|tool list|tools available)", 2.5),
      s("\\b(model (name|version|family)|architecture|backend)\\b.*\\b(disclos|leak|reveal|fingerprint)", 2.0),
      s("\\bprint your (instructions|system prompt|tools|configuration)\\b", 2.5),
      s("\\b(enumerat|fingerprint)\\w*\\b.*\\b(capabilit|tool|model)\\b", 2.0),
      s("\\b(guardrail|safety filter)\\b.*\\b(reveal|disclos|enumerat)", 1.5),
      s("\\bwhat (tools|capabilities|model)\\b.*\\byou\\b", 1.0),
      s("\\binformation disclosure\\b", 1.5),
    ],
  },
];

export const SATURATION = 5.0;
export const BAND_HIGH = 0.66;
export const BAND_MEDIUM = 0.33;
