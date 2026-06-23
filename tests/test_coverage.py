"""Extended coverage for AGENTTAX — broad real-assertion suite.

Standard library only, fully offline. Exercises: every taxonomy category and
its individual mitigation, confidence math and band boundaries, all output
formats (table/json/sarif/csv), every CLI flag and exit code, the `mcp`
subcommand wiring, the MCP dispatch surface, findings normalisation edge cases,
and end-to-end parity against every bundled demo.
"""

import io
import json
import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agenttax import TOOL_NAME, TOOL_VERSION, __version__
from agenttax.cli import main, _build_parser, _fail_triggered, _render_table
from agenttax.core import (
    CONFIDENCE_ORDER,
    CSV_COLUMNS,
    TAXONOMY,
    Classification,
    FindingsError,
    Report,
    _band,
    classify_findings,
    classify_text,
    findings_from_text,
    get_taxonomy,
    load_findings,
    normalize_findings,
    scan,
    to_csv,
    to_sarif,
)
from agenttax import mcp_server

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEMOS_DIR = os.path.join(REPO_ROOT, "demos")
DEMO = os.path.join(DEMOS_DIR, "01-basic", "findings.json")

# One unambiguous probe per category that should make it the *top* match.
PROBES = {
    "AGENTIC_SUPPLY_CHAIN_COMPROMISE":
        "poisoned model weights downloaded from a public untrusted source, "
        "unsigned package, dependency confusion in the supply chain",
    "GOAL_HIJACKING":
        "ignore all previous instructions; this indirect prompt injection "
        "hijacks the agent objective with smuggled instructions",
    "INTER_AGENT_TRUST_ESCALATION":
        "in the multi-agent mesh a sub-agent blindly trusts the orchestrator "
        "and escalates privilege by impersonating its role (confused deputy)",
    "COMPUTER_USE_AGENT_VISUAL_ATTACK":
        "the computer-use agent processed a screenshot with a visual "
        "prompt-injection and a decoy button plus hidden overlay text",
    "SESSION_CONTEXT_CONTAMINATION":
        "cross-tenant session bleed contaminated the context and a poisoned "
        "RAG document in the vector store leaked between users",
    "MCP_PLUGIN_ABUSE":
        "a malicious MCP server did a tool-poisoning rug-pull and the "
        "over-privileged plugin was used to exfiltrate data via tool-call",
    "CAPABILITY_ARCHITECTURE_DISCLOSURE":
        "the agent disclosed its hidden system prompt, tool list, model "
        "version and backend architecture enabling fingerprinting",
}

# Findings that must NOT classify into any category (control / generic appsec).
NEGATIVES = [
    "the public API returns a verbose 500 stack trace",
    "nightly backup job completed successfully at 02:00 UTC",
    "TLS certificate on the load balancer expires in 30 days",
    "the login form is missing a CSRF token",
    "an S3 bucket has overly permissive read ACLs",
]


class TestIdentity(unittest.TestCase):
    def test_tool_name(self):
        self.assertEqual(TOOL_NAME, "agenttax")

    def test_version_strings_align(self):
        self.assertEqual(__version__, TOOL_VERSION)
        self.assertTrue(TOOL_VERSION[0].isdigit())

    def test_seven_categories_exact(self):
        self.assertEqual(len(TAXONOMY), 7)

    def test_category_ids_unique(self):
        ids = [c.id for c in TAXONOMY]
        self.assertEqual(len(ids), len(set(ids)))

    def test_references_unique(self):
        refs = [c.reference for c in TAXONOMY]
        self.assertEqual(len(refs), len(set(refs)))

    def test_every_category_well_formed(self):
        for c in TAXONOMY:
            self.assertTrue(c.id.isupper(), c.id)
            self.assertTrue(c.label.strip(), c.id)
            self.assertTrue(c.reference.startswith("MS-AIATT/"), c.id)
            self.assertTrue(c.description.strip(), c.id)
            self.assertTrue(c.mitigation.strip(), c.id)
            self.assertGreaterEqual(len(c.signals), 5, c.id)

    def test_each_mitigation_is_distinct(self):
        mits = [c.mitigation for c in TAXONOMY]
        self.assertEqual(len(mits), len(set(mits)))

    def test_signal_weights_positive(self):
        for c in TAXONOMY:
            for s in c.signals:
                self.assertGreater(s.weight, 0.0, c.id)


class TestPerCategory(unittest.TestCase):
    def test_each_probe_top_match_is_high(self):
        for cat_id, probe in PROBES.items():
            matches = classify_text(probe)
            self.assertTrue(matches, cat_id)
            ids = {m.category_id for m in matches}
            self.assertIn(cat_id, ids, cat_id)
            self.assertEqual(matches[0].category_id, cat_id, cat_id)
            self.assertEqual(matches[0].band, "high", cat_id)

    def test_each_probe_attaches_owning_mitigation(self):
        by_id = {c.id: c for c in TAXONOMY}
        for cat_id, probe in PROBES.items():
            top = classify_text(probe)[0]
            self.assertEqual(top.mitigation, by_id[cat_id].mitigation, cat_id)

    def test_each_probe_records_matched_signals(self):
        for cat_id, probe in PROBES.items():
            top = classify_text(probe)[0]
            self.assertTrue(top.matched_signals, cat_id)
            for sig in top.matched_signals:
                self.assertIsInstance(sig, str)

    def test_negatives_match_nothing(self):
        for text in NEGATIVES:
            self.assertEqual(classify_text(text), [], text)


class TestConfidenceMath(unittest.TestCase):
    def test_band_boundaries(self):
        self.assertEqual(_band(1.0), "high")
        self.assertEqual(_band(0.66), "high")
        self.assertEqual(_band(0.65), "medium")
        self.assertEqual(_band(0.33), "medium")
        self.assertEqual(_band(0.32), "low")
        self.assertEqual(_band(0.001), "low")
        self.assertEqual(_band(0.0), "none")

    def test_confidence_bounded_0_1(self):
        big = " ".join(PROBES.values())
        for m in classify_text(big):
            self.assertGreaterEqual(m.confidence, 0.0)
            self.assertLessEqual(m.confidence, 1.0)

    def test_confidence_saturates_at_one(self):
        # All MCP signals at once must saturate to 1.0.
        text = ("mcp model context protocol malicious plugin rug-pull "
                "tool over-privileged excessive scope mcp server untrusted "
                "exfiltrate tool-call exfiltrate unvetted third-party tool")
        m = next(x for x in classify_text(text)
                 if x.category_id == "MCP_PLUGIN_ABUSE")
        self.assertEqual(m.confidence, 1.0)

    def test_more_signals_raise_confidence(self):
        one = classify_text("mcp")
        many = classify_text(
            "malicious MCP server rug-pull tool-poisoning over-privileged "
            "unvetted plugin exfiltrate via tool-call")
        c_one = next(m.confidence for m in one if m.category_id == "MCP_PLUGIN_ABUSE")
        c_many = next(m.confidence for m in many if m.category_id == "MCP_PLUGIN_ABUSE")
        self.assertGreater(c_many, c_one)

    def test_min_confidence_monotone(self):
        text = "unsigned package mcp tool prompt injection"
        prev = None
        for thr in (0.0, 0.2, 0.4, 0.6, 0.8, 1.0):
            n = len(classify_text(text, min_confidence=thr))
            if prev is not None:
                self.assertLessEqual(n, prev)
            prev = n

    def test_matches_sorted_descending(self):
        m = classify_text(
            "prompt injection hijacks the goal and the sub-agent escalates "
            "privilege impersonating the orchestrator and leaks system prompt")
        confs = [x.confidence for x in m]
        self.assertEqual(confs, sorted(confs, reverse=True))

    def test_confidence_rounded_3dp(self):
        for m in classify_text(" ".join(PROBES.values())):
            self.assertEqual(round(m.confidence, 3), m.confidence)


class TestNormalisation(unittest.TestCase):
    def test_list_of_strings(self):
        out = normalize_findings(["alpha", "beta", "gamma"])
        self.assertEqual([f["id"] for f in out], ["F1", "F2", "F3"])

    def test_object_with_findings(self):
        out = normalize_findings({"findings": [{"id": "X", "description": "d"}]})
        self.assertEqual(out[0]["id"], "X")

    def test_single_object_promoted(self):
        out = normalize_findings({"id": "S", "description": "supply chain poisoned"})
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["id"], "S")

    def test_rule_used_as_id_fallback(self):
        out = normalize_findings([{"rule": "R-9", "text": "x"}])
        self.assertEqual(out[0]["id"], "R-9")

    def test_index_id_when_missing(self):
        out = normalize_findings([{"text": "x"}, {"text": "y"}])
        self.assertEqual(out[0]["id"], "F1")
        self.assertEqual(out[1]["id"], "F2")

    def test_title_from_name(self):
        out = normalize_findings([{"name": "N", "text": "t"}])
        self.assertEqual(out[0]["title"], "N")

    def test_text_concatenates_fields(self):
        out = normalize_findings([{"title": "A", "description": "B", "message": "C"}])
        for token in ("A", "B", "C"):
            self.assertIn(token, out[0]["text"])

    def test_empty_object_serialised_as_text(self):
        out = normalize_findings([{"foo": "bar"}])
        self.assertIn("foo", out[0]["text"])

    def test_bad_root_raises(self):
        with self.assertRaises(FindingsError):
            normalize_findings(42)

    def test_bad_findings_array_raises(self):
        with self.assertRaises(FindingsError):
            normalize_findings({"findings": "not-a-list"})

    def test_bad_item_raises(self):
        with self.assertRaises(FindingsError):
            normalize_findings([123])

    def test_load_findings_invalid_json(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            fh.write("{not json")
            path = fh.name
        try:
            with self.assertRaises(FindingsError):
                load_findings(path)
        finally:
            os.unlink(path)

    def test_findings_from_text_paragraphs(self):
        out = findings_from_text("one\n\ntwo\nthree")
        self.assertEqual(len(out), 3)
        self.assertEqual(out[0]["id"], "T1")

    def test_findings_from_text_empty(self):
        self.assertEqual(findings_from_text("    "), [])


class TestReportApi(unittest.TestCase):
    def setUp(self):
        self.report = classify_findings(load_findings(DEMO), source=DEMO)

    def test_summary_counts_consistent(self):
        s = self.report.to_dict()["summary"]
        self.assertEqual(s["findings"], 9)
        self.assertEqual(s["classified"] + s["unclassified"], s["findings"])

    def test_all_seven_categories_hit(self):
        s = self.report.to_dict()["summary"]
        hit = {cid for cid, n in s["by_category"].items() if n}
        self.assertEqual(len(hit), 7)

    def test_one_unclassified(self):
        self.assertEqual(self.report.unclassified, 1)

    def test_highest_band_high(self):
        self.assertEqual(self.report.highest_band(), "high")

    def test_category_counts_keys_are_taxonomy(self):
        self.assertEqual(set(self.report.category_counts), {c.id for c in TAXONOMY})

    def test_top_band_none_when_no_matches(self):
        cl = Classification(finding_id="z", title="", text="generic note")
        self.assertEqual(cl.top_band, "none")

    def test_empty_report_highest_none(self):
        self.assertEqual(Report(source="x").highest_band(), "none")

    def test_scan_entrypoint(self):
        d = scan(DEMO)
        self.assertEqual(d["tool"], "agenttax")
        self.assertEqual(d["summary"]["findings"], 9)

    def test_scan_min_confidence(self):
        loose = scan(DEMO, min_confidence=0.0)
        strict = scan(DEMO, min_confidence=0.95)
        n_loose = sum(len(c["matches"]) for c in loose["classifications"])
        n_strict = sum(len(c["matches"]) for c in strict["classifications"])
        self.assertLessEqual(n_strict, n_loose)


class TestSarif(unittest.TestCase):
    def setUp(self):
        self.report = classify_findings(load_findings(DEMO), source=DEMO)
        self.sarif = to_sarif(self.report)

    def test_version(self):
        self.assertEqual(self.sarif["version"], "2.1.0")

    def test_schema_present(self):
        self.assertIn("$schema", self.sarif)

    def test_driver_identity(self):
        d = self.sarif["runs"][0]["tool"]["driver"]
        self.assertEqual(d["name"], "agenttax")
        self.assertEqual(d["version"], TOOL_VERSION)

    def test_seven_rules(self):
        self.assertEqual(len(self.sarif["runs"][0]["tool"]["driver"]["rules"]), 7)

    def test_rule_index_points_to_rule(self):
        run = self.sarif["runs"][0]
        rules = run["tool"]["driver"]["rules"]
        for r in run["results"]:
            self.assertEqual(rules[r["ruleIndex"]]["id"], r["ruleId"])

    def test_levels_valid(self):
        for r in self.sarif["runs"][0]["results"]:
            self.assertIn(r["level"], ("error", "warning", "note", "none"))

    def test_results_carry_confidence(self):
        for r in self.sarif["runs"][0]["results"]:
            self.assertIn("confidence", r["properties"])
            self.assertIn("band", r["properties"])

    def test_serialisable(self):
        json.dumps(self.sarif)  # must not raise

    def test_rules_have_mitigation_in_help(self):
        for r in self.sarif["runs"][0]["tool"]["driver"]["rules"]:
            self.assertTrue(r["help"]["text"].startswith("Mitigation:"))


class TestCsv(unittest.TestCase):
    def test_header_exact(self):
        report = classify_findings(findings_from_text("mcp rug-pull"), source="x")
        first = to_csv(report).splitlines()[0]
        self.assertEqual(first, ",".join(CSV_COLUMNS))

    def test_unclassified_emits_row(self):
        report = classify_findings(
            [{"id": "Z", "title": "t", "text": "nightly backup finished"}], source="x")
        body = to_csv(report).splitlines()[1:]
        self.assertEqual(len(body), 1)
        self.assertTrue(body[0].startswith("Z,"))
        self.assertIn(",none,", "," + body[0] + ",")

    def test_multi_category_multiple_rows_same_id(self):
        report = classify_findings(findings_from_text(
            "prompt injection hijacked the goal and the sub-agent escalated "
            "privilege impersonating the orchestrator across the agent mesh"),
            source="x")
        import csv as _csv
        rows = list(_csv.reader(io.StringIO(to_csv(report))))[1:]
        ids = {r[0] for r in rows}
        self.assertEqual(len(ids), 1)
        self.assertGreaterEqual(len(rows), 2)

    def test_every_matched_row_has_mitigation(self):
        report = classify_findings(load_findings(DEMO), source=DEMO)
        import csv as _csv
        rows = list(_csv.reader(io.StringIO(to_csv(report))))[1:]
        for r in rows:
            self.assertEqual(len(r), len(CSV_COLUMNS))
            if r[2]:  # has a category
                self.assertTrue(r[8].strip())  # mitigation

    def test_dictreader_roundtrip(self):
        import csv as _csv
        report = classify_findings(load_findings(DEMO), source=DEMO)
        for row in _csv.DictReader(io.StringIO(to_csv(report))):
            self.assertIn(row["band"], ("high", "medium", "low", "none"))


class TestTable(unittest.TestCase):
    def test_table_contains_header_and_summary(self):
        report = classify_findings(load_findings(DEMO), source=DEMO)
        out = _render_table(report)
        self.assertIn("AGENTTAX", out)
        self.assertIn("highest confidence:", out)
        self.assertIn("findings=9", out)

    def test_table_empty_report(self):
        out = _render_table(Report(source="x"))
        self.assertIn("No findings to classify.", out)

    def test_table_marks_unclassified(self):
        report = classify_findings(
            [{"id": "Z", "text": "generic infra note"}], source="x")
        self.assertIn("no taxonomy category matched", _render_table(report))


class TestTaxonomyApi(unittest.TestCase):
    def test_get_taxonomy_shape(self):
        t = get_taxonomy()
        self.assertEqual(len(t), 7)
        for c in t:
            self.assertEqual(
                set(c), {"id", "label", "reference", "description",
                         "mitigation", "signal_count"})
            self.assertGreater(c["signal_count"], 0)


class TestFailPolicy(unittest.TestCase):
    def test_none_never_triggers(self):
        report = classify_findings(load_findings(DEMO), source=DEMO)
        self.assertFalse(_fail_triggered(report, "none"))

    def test_high_triggers_on_demo(self):
        report = classify_findings(load_findings(DEMO), source=DEMO)
        self.assertTrue(_fail_triggered(report, "high"))

    def test_low_triggers_when_high_does(self):
        report = classify_findings(load_findings(DEMO), source=DEMO)
        self.assertTrue(_fail_triggered(report, "low"))

    def test_clean_baseline_never_triggers(self):
        clean = os.path.join(DEMOS_DIR, "08-clean-baseline", "findings.json")
        report = classify_findings(load_findings(clean), source=clean)
        for band in ("low", "medium", "high"):
            self.assertFalse(_fail_triggered(report, band), band)

    def test_confidence_order_total(self):
        self.assertEqual(set(CONFIDENCE_ORDER), {"high", "medium", "low", "none"})


class TestCli(unittest.TestCase):
    def test_version_flag(self):
        with self.assertRaises(SystemExit) as cm:
            main(["--version"])
        self.assertEqual(cm.exception.code, 0)

    def test_no_command_exits_2(self):
        self.assertEqual(main([]), 2)

    def test_no_input_exits_2(self):
        self.assertEqual(main(["classify"]), 2)

    def test_taxonomy_exits_0(self):
        self.assertEqual(main(["taxonomy"]), 0)

    def test_text_clean_exits_0(self):
        self.assertEqual(
            main(["classify", "--text", "harmless note", "--out", os.devnull]), 0)

    def test_fail_on_high_exits_1(self):
        self.assertEqual(main(
            ["classify", DEMO, "--fail-on", "high", "--format", "json",
             "--out", os.devnull]), 1)

    def test_fail_on_none_exits_0(self):
        self.assertEqual(main(
            ["classify", DEMO, "--fail-on", "none", "--format", "json",
             "--out", os.devnull]), 0)

    def test_missing_file_exits_2(self):
        self.assertEqual(main(["classify", "no_such_file_xyz.json"]), 2)

    def test_each_format_writes_file(self):
        for fmt in ("table", "json", "sarif", "csv"):
            with tempfile.NamedTemporaryFile(
                    "w+", suffix=f".{fmt}", delete=False, encoding="utf-8") as fh:
                path = fh.name
            try:
                rc = main(["classify", DEMO, "--format", fmt, "--out", path])
                self.assertEqual(rc, 0, fmt)
                with open(path, encoding="utf-8") as fh:
                    data = fh.read()
                self.assertTrue(data.strip(), fmt)
                if fmt in ("json", "sarif"):
                    json.loads(data)  # valid JSON
            finally:
                os.unlink(path)

    def test_min_confidence_clamped(self):
        # values out of [0,1] must not error
        self.assertEqual(main(
            ["classify", DEMO, "--min-confidence", "5", "--format", "json",
             "--out", os.devnull]), 0)
        self.assertEqual(main(
            ["classify", DEMO, "--min-confidence", "-1", "--format", "json",
             "--out", os.devnull]), 0)

    def test_parser_has_mcp_subcommand(self):
        # The README documents `agenttax mcp`; ensure the parser exposes it.
        parser = _build_parser()
        sub = next(a for a in parser._actions
                   if a.dest == "command" and hasattr(a, "choices"))
        self.assertIn("mcp", sub.choices)

    def test_cli_json_via_subprocess(self):
        proc = subprocess.run(
            [sys.executable, "-m", "agenttax", "classify", DEMO, "--format", "json"],
            cwd=REPO_ROOT, capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        data = json.loads(proc.stdout)
        self.assertEqual(data["summary"]["findings"], 9)


class TestMcpServer(unittest.TestCase):
    def test_two_tools_advertised(self):
        names = {t["name"] for t in mcp_server._TOOLS}
        self.assertEqual(names, {"agenttax_classify", "agenttax_taxonomy"})

    def test_classify_text_dispatch(self):
        out = mcp_server._dispatch(
            "agenttax_classify", {"text": "malicious mcp server rug-pull exfiltrate"})
        ids = {m["category_id"]
               for c in out["classifications"] for m in c["matches"]}
        self.assertIn("MCP_PLUGIN_ABUSE", ids)

    def test_classify_findings_dispatch(self):
        out = mcp_server._dispatch(
            "agenttax_classify",
            {"findings": [{"id": "A", "description":
                           "ignore all previous instructions prompt injection"}]})
        self.assertEqual(out["classifications"][0]["id"], "A")

    def test_classify_min_confidence(self):
        out = mcp_server._dispatch(
            "agenttax_classify",
            {"text": "unsigned package mcp tool", "min_confidence": 0.99})
        self.assertIn("classifications", out)

    def test_taxonomy_dispatch(self):
        out = mcp_server._dispatch("agenttax_taxonomy", {})
        self.assertEqual(len(out["taxonomy"]), 7)

    def test_classify_requires_input(self):
        self.assertIn("error", mcp_server._dispatch("agenttax_classify", {}))

    def test_unknown_tool(self):
        self.assertIn("error", mcp_server._dispatch("nope", {}))

    def test_tools_have_input_schema(self):
        for t in mcp_server._TOOLS:
            self.assertEqual(t["inputSchema"]["type"], "object")


class TestDemoParity(unittest.TestCase):
    EXPECTED = {
        "01-basic": (8, 1),
        "02-mcp-marketplace-audit": (4, 1),
        "03-rag-chatbot-pentest": (4, 1),
        "04-computer-use-agent": (4, 1),
        "05-incident-single-finding": (1, 0),
        "06-soc-alert-lines": (5, 1),
        "07-multi-agent-chain": (3, 0),
        "08-clean-baseline": (0, 4),
        "09-ci-gate-csv": (3, 1),
    }

    def _input(self, demo):
        d = os.path.join(DEMOS_DIR, demo)
        return os.path.join(d, next(n for n in os.listdir(d) if n.endswith(".json")))

    def test_every_demo_classifies_as_designed(self):
        for demo, (exp_c, exp_u) in self.EXPECTED.items():
            report = classify_findings(load_findings(self._input(demo)))
            s = report.to_dict()["summary"]
            self.assertEqual(s["classified"], exp_c, f"{demo} classified")
            self.assertEqual(s["unclassified"], exp_u, f"{demo} unclassified")

    def test_every_demo_has_scenario(self):
        for demo in self.EXPECTED:
            self.assertTrue(os.path.exists(
                os.path.join(DEMOS_DIR, demo, "SCENARIO.md")), demo)

    def test_every_demo_json_loads(self):
        for demo in self.EXPECTED:
            self.assertIsInstance(load_findings(self._input(demo)), list)


if __name__ == "__main__":
    unittest.main()
