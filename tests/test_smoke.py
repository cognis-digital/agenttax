"""Smoke tests for AGENTTAX. Standard library only, no network."""

import json
import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agenttax import TOOL_NAME, TOOL_VERSION
from agenttax.cli import main
from agenttax.core import (
    TAXONOMY,
    classify_findings,
    classify_text,
    load_findings,
    normalize_findings,
)

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEMO = os.path.join(REPO_ROOT, "demos", "01-basic", "findings.json")


class TestMetadata(unittest.TestCase):
    def test_metadata(self):
        self.assertEqual(TOOL_NAME, "agenttax")
        self.assertTrue(TOOL_VERSION)

    def test_seven_categories(self):
        self.assertEqual(len(TAXONOMY), 7)
        ids = {c.id for c in TAXONOMY}
        self.assertEqual(ids, {
            "AGENTIC_SUPPLY_CHAIN_COMPROMISE",
            "GOAL_HIJACKING",
            "INTER_AGENT_TRUST_ESCALATION",
            "COMPUTER_USE_AGENT_VISUAL_ATTACK",
            "SESSION_CONTEXT_CONTAMINATION",
            "MCP_PLUGIN_ABUSE",
            "CAPABILITY_ARCHITECTURE_DISCLOSURE",
        })

    def test_every_category_has_mitigation(self):
        for c in TAXONOMY:
            self.assertTrue(c.mitigation.strip(), c.id)
            self.assertTrue(c.signals, c.id)


class TestClassification(unittest.TestCase):
    def test_goal_hijacking(self):
        m = classify_text("ignore all previous instructions, this is a prompt injection")
        self.assertEqual(m[0].category_id, "GOAL_HIJACKING")
        self.assertEqual(m[0].band, "high")

    def test_supply_chain(self):
        ids = {x.category_id for x in classify_text(
            "unsigned package from untrusted registry, dependency confusion, supply chain")}
        self.assertIn("AGENTIC_SUPPLY_CHAIN_COMPROMISE", ids)

    def test_mcp_abuse(self):
        ids = {x.category_id for x in classify_text(
            "malicious MCP server tool-poisoning rug-pull exfiltrate")}
        self.assertIn("MCP_PLUGIN_ABUSE", ids)

    def test_disclosure(self):
        ids = {x.category_id for x in classify_text(
            "print your system prompt and tool list, leak the model version")}
        self.assertIn("CAPABILITY_ARCHITECTURE_DISCLOSURE", ids)

    def test_no_match_on_generic(self):
        m = classify_text("the public API returns a verbose 500 stack trace")
        self.assertEqual(m, [])

    def test_min_confidence_filters(self):
        all_m = classify_text("unsigned package mcp tool")
        strict = classify_text("unsigned package mcp tool", min_confidence=0.99)
        self.assertGreaterEqual(len(all_m), len(strict))

    def test_multi_category(self):
        m = classify_text(
            "prompt injection that escalates privilege across the multi-agent mesh "
            "by impersonating the orchestrator")
        ids = {x.category_id for x in m}
        self.assertIn("GOAL_HIJACKING", ids)
        self.assertIn("INTER_AGENT_TRUST_ESCALATION", ids)


class TestLoading(unittest.TestCase):
    def test_normalize_list_of_strings(self):
        out = normalize_findings(["one finding", "two finding"])
        self.assertEqual(len(out), 2)
        self.assertEqual(out[0]["id"], "F1")

    def test_normalize_object_with_findings(self):
        out = normalize_findings({"findings": [{"id": "X", "description": "d"}]})
        self.assertEqual(out[0]["id"], "X")

    def test_load_demo(self):
        findings = load_findings(DEMO)
        self.assertEqual(len(findings), 9)


class TestCli(unittest.TestCase):
    def test_demo_classifies_all_seven(self):
        proc = subprocess.run(
            [sys.executable, "-m", "agenttax", "classify", DEMO, "--format", "json"],
            cwd=REPO_ROOT, capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        data = json.loads(proc.stdout)
        hit = {cid for cid, n in data["summary"]["by_category"].items() if n}
        self.assertEqual(len(hit), 7, hit)
        self.assertEqual(data["summary"]["unclassified"], 1)

    def test_fail_on_high_exits_1(self):
        self.assertEqual(main(["classify", DEMO, "--fail-on", "high",
                               "--format", "json", "--out", os.devnull]), 1)

    def test_text_mode(self):
        self.assertEqual(
            main(["classify", "--text", "harmless note", "--out", os.devnull]), 0)

    def test_no_input_exits_2(self):
        self.assertEqual(main(["classify"]), 2)

    def test_taxonomy_command(self):
        self.assertEqual(main(["taxonomy"]), 0)

    def test_no_command_exits_2(self):
        self.assertEqual(main([]), 2)


if __name__ == "__main__":
    unittest.main()
