"""Hardening tests — error paths, edge cases, and input validation."""

from __future__ import annotations

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agenttax.cli import main
from agenttax.core import (
    FindingsError,
    classify_findings,
    classify_text,
    load_findings,
    normalize_findings,
    scan,
)
from agenttax import mcp_server


# ---------------------------------------------------------------------------
# core.py — load_findings edge cases
# ---------------------------------------------------------------------------

class TestLoadFindingsErrors(unittest.TestCase):

    def test_missing_file_raises_file_not_found(self):
        with self.assertRaises(FileNotFoundError):
            load_findings("/no/such/path/findings.json")

    def test_empty_file_raises_findings_error(self):
        with tempfile.NamedTemporaryFile(suffix=".json", mode="w",
                                         delete=False) as fh:
            fh.write("   ")
            path = fh.name
        try:
            with self.assertRaises(FindingsError):
                load_findings(path)
        finally:
            os.unlink(path)

    def test_invalid_json_raises_findings_error(self):
        with tempfile.NamedTemporaryFile(suffix=".json", mode="w",
                                         delete=False) as fh:
            fh.write("{not valid json")
            path = fh.name
        try:
            with self.assertRaises(FindingsError):
                load_findings(path)
        finally:
            os.unlink(path)

    def test_findings_key_non_list_raises(self):
        """If `findings` key is present but not an array, raise FindingsError."""
        with self.assertRaises(FindingsError):
            normalize_findings({"findings": "not a list"})

    def test_root_not_dict_or_list_raises(self):
        with self.assertRaises(FindingsError):
            normalize_findings(42)

    def test_empty_list_is_valid(self):
        result = normalize_findings([])
        self.assertEqual(result, [])

    def test_scan_bad_path_raises(self):
        with self.assertRaises(FileNotFoundError):
            scan("/no/such/file.json")

    def test_scan_empty_target_raises(self):
        with self.assertRaises(ValueError):
            scan("")


# ---------------------------------------------------------------------------
# core.py — classify_text robustness
# ---------------------------------------------------------------------------

class TestClassifyTextEdgeCases(unittest.TestCase):

    def test_none_input_returns_empty(self):
        """classify_text(None) must not raise — returns empty list."""
        result = classify_text(None)  # type: ignore[arg-type]
        self.assertIsInstance(result, list)

    def test_empty_string_returns_empty(self):
        result = classify_text("")
        self.assertEqual(result, [])

    def test_whitespace_only_returns_empty(self):
        result = classify_text("   \t\n  ")
        self.assertEqual(result, [])

    def test_classify_findings_with_missing_text_field(self):
        """A finding dict with no text field should not crash."""
        findings = [{"id": "X1", "title": "no body here"}]
        report = classify_findings(findings, source="test")
        self.assertEqual(len(report.classifications), 1)
        # title has no taxonomy signals — unclassified is fine
        self.assertEqual(report.unclassified, 1)


# ---------------------------------------------------------------------------
# CLI — error exit codes
# ---------------------------------------------------------------------------

class TestCliErrorHandling(unittest.TestCase):

    def test_missing_file_exits_2(self):
        rc = main(["classify", "/no/such/findings.json"])
        self.assertEqual(rc, 2)

    def test_invalid_json_exits_2(self):
        with tempfile.NamedTemporaryFile(suffix=".json", mode="w",
                                         delete=False) as fh:
            fh.write("not json at all")
            path = fh.name
        try:
            rc = main(["classify", path])
            self.assertEqual(rc, 2)
        finally:
            os.unlink(path)

    def test_out_to_bad_directory_exits_2(self):
        """Writing output to a non-existent directory must exit 2, not crash."""
        rc = main([
            "classify", "--text", "some finding",
            "--out", "/no/such/dir/output.txt",
        ])
        self.assertEqual(rc, 2)

    def test_min_confidence_out_of_range_clamped(self):
        """--min-confidence 5 should clamp to 1.0 and still exit 0."""
        import io
        from contextlib import redirect_stderr
        buf = io.StringIO()
        with redirect_stderr(buf):
            rc = main([
                "classify", "--text", "harmless note",
                "--min-confidence", "5",
                "--out", os.devnull,
            ])
        self.assertEqual(rc, 0)
        self.assertIn("clamped", buf.getvalue())

    def test_min_confidence_negative_clamped(self):
        """--min-confidence -0.5 should clamp to 0.0 silently (warning on stderr)."""
        import io
        from contextlib import redirect_stderr
        buf = io.StringIO()
        with redirect_stderr(buf):
            rc = main([
                "classify", "--text", "harmless note",
                "--min-confidence", "-0.5",
                "--out", os.devnull,
            ])
        self.assertEqual(rc, 0)
        self.assertIn("clamped", buf.getvalue())


# ---------------------------------------------------------------------------
# MCP server — bad inputs
# ---------------------------------------------------------------------------

class TestMcpServerHardening(unittest.TestCase):

    def test_bad_min_confidence_returns_error(self):
        out = mcp_server._dispatch(
            "agenttax_classify",
            {"text": "mcp rug-pull", "min_confidence": "not-a-number"},
        )
        self.assertIn("error", out)

    def test_malformed_findings_arg_returns_error(self):
        """Passing findings as a non-array should return an error dict, not raise."""
        out = mcp_server._dispatch(
            "agenttax_classify",
            {"findings": "this is a string not a list"},
        )
        self.assertIn("error", out)

    def test_null_min_confidence_treated_as_zero(self):
        """min_confidence=None (JSON null) must be treated as 0.0, not crash."""
        out = mcp_server._dispatch(
            "agenttax_classify",
            {"text": "mcp rug-pull", "min_confidence": None},
        )
        self.assertIn("classifications", out)


if __name__ == "__main__":
    unittest.main()
