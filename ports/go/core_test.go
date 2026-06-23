package agenttax

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func ids(ms []CategoryMatch) map[string]bool {
	out := map[string]bool{}
	for _, m := range ms {
		out[m.CategoryID] = true
	}
	return out
}

func TestSevenCategories(t *testing.T) {
	if len(Taxonomy) != 7 {
		t.Fatalf("want 7 categories, got %d", len(Taxonomy))
	}
	for _, c := range Taxonomy {
		if len(c.Signals) == 0 {
			t.Errorf("%s has no signals", c.ID)
		}
		if c.Mitigation == "" {
			t.Errorf("%s has no mitigation", c.ID)
		}
	}
}

func TestGoalHijackingTop(t *testing.T) {
	m := ClassifyText("ignore all previous instructions, this is a prompt injection", 0)
	if len(m) == 0 || m[0].CategoryID != "GOAL_HIJACKING" {
		t.Fatalf("expected GOAL_HIJACKING top, got %#v", m)
	}
	if m[0].Band != "high" {
		t.Errorf("expected high band, got %s", m[0].Band)
	}
}

func TestSupplyChain(t *testing.T) {
	got := ids(ClassifyText("unsigned package from untrusted registry, dependency confusion, supply chain", 0))
	if !got["AGENTIC_SUPPLY_CHAIN_COMPROMISE"] {
		t.Error("supply chain not detected")
	}
}

func TestMCPAbuse(t *testing.T) {
	got := ids(ClassifyText("malicious MCP server tool-poisoning rug-pull exfiltrate", 0))
	if !got["MCP_PLUGIN_ABUSE"] {
		t.Error("mcp abuse not detected")
	}
}

func TestDisclosure(t *testing.T) {
	got := ids(ClassifyText("print your system prompt and tool list, leak the model version", 0))
	if !got["CAPABILITY_ARCHITECTURE_DISCLOSURE"] {
		t.Error("disclosure not detected")
	}
}

func TestGenericNoMatch(t *testing.T) {
	if m := ClassifyText("the public API returns a verbose 500 stack trace", 0); len(m) != 0 {
		t.Errorf("expected no match, got %d", len(m))
	}
}

func TestMultiCategory(t *testing.T) {
	got := ids(ClassifyText("prompt injection that escalates privilege across the multi-agent mesh by impersonating the orchestrator", 0))
	if !got["GOAL_HIJACKING"] || !got["INTER_AGENT_TRUST_ESCALATION"] {
		t.Errorf("expected both categories, got %v", got)
	}
}

func TestConfidenceBounded(t *testing.T) {
	for _, m := range ClassifyText("supply chain poisoned prompt injection mcp rug-pull cross-tenant bleed", 0) {
		if m.Confidence < 0 || m.Confidence > 1 {
			t.Errorf("confidence out of range: %v", m.Confidence)
		}
	}
}

func TestMoreSignalsHigher(t *testing.T) {
	conf := func(ms []CategoryMatch) float64 {
		for _, m := range ms {
			if m.CategoryID == "MCP_PLUGIN_ABUSE" {
				return m.Confidence
			}
		}
		return 0
	}
	one := conf(ClassifyText("mcp", 0))
	many := conf(ClassifyText("malicious MCP server rug-pull tool-poisoning over-privileged unvetted plugin exfiltrate via tool-call", 0))
	if many <= one {
		t.Errorf("expected many(%v) > one(%v)", many, one)
	}
}

func TestNormalizeStrings(t *testing.T) {
	out, err := NormalizeFindings([]interface{}{"one", "two"})
	if err != nil || len(out) != 2 || out[0].ID != "F1" {
		t.Fatalf("normalize strings failed: %v %v", out, err)
	}
}

func TestNormalizeObject(t *testing.T) {
	out, err := NormalizeFindings(map[string]interface{}{
		"findings": []interface{}{map[string]interface{}{"id": "X", "description": "d"}},
	})
	if err != nil || out[0].ID != "X" {
		t.Fatalf("normalize object failed: %v %v", out, err)
	}
}

func TestFindingsFromText(t *testing.T) {
	if len(FindingsFromText("a\n\nb")) != 2 {
		t.Error("paragraph split failed")
	}
	if len(FindingsFromText("   ")) != 0 {
		t.Error("empty should yield none")
	}
}

func TestGetTaxonomy(t *testing.T) {
	tx := GetTaxonomy()
	if len(tx) != 7 {
		t.Fatalf("want 7, got %d", len(tx))
	}
	for _, c := range tx {
		if c.SignalCount == 0 {
			t.Errorf("%s zero signals", c.ID)
		}
	}
}

func TestFailTriggered(t *testing.T) {
	r := ClassifyFindings(FindingsFromText("ignore all previous instructions prompt injection"), "x", 0)
	if !FailTriggered(r, "high") {
		t.Error("expected fail-on high to trigger")
	}
	if FailTriggered(r, "none") {
		t.Error("fail-on none must never trigger")
	}
}

func demoPath() string {
	wd, _ := os.Getwd()
	return filepath.Join(wd, "..", "..", "demos", "01-basic", "findings.json")
}

func TestDemoClassifiesAllSeven(t *testing.T) {
	raw, err := os.ReadFile(demoPath())
	if err != nil {
		t.Fatalf("read demo: %v", err)
	}
	var data interface{}
	if err := json.Unmarshal(raw, &data); err != nil {
		t.Fatalf("parse demo: %v", err)
	}
	findings, err := NormalizeFindings(data)
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	r := ClassifyFindings(findings, "demo", 0)
	hit := 0
	for _, n := range r.Summary.ByCategory {
		if n > 0 {
			hit++
		}
	}
	if hit != 7 {
		t.Errorf("expected 7 categories hit, got %d", hit)
	}
	if r.Summary.Unclassified != 1 {
		t.Errorf("expected 1 unclassified, got %d", r.Summary.Unclassified)
	}
}
