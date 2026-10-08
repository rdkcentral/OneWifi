#!/usr/bin/env python3
# Copyright 2026 RDK Management — Apache-2.0 (see gcc_diff_gate.py header).
"""Unit tests for gcc_diff_gate.py's Commit-5 inline helpers: build_inline
(gate/advisory split, column dedupe, dropped count) and write_inline (envelope
shape, skipped vs ok, no-op when INLINE_JSON is unset)."""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import gcc_diff_gate as gcc_gate  # noqa: E402


class BuildInline(unittest.TestCase):
    def test_gate_advisory_split(self):
        gated = ["source/a.c:10:5: warning: variable-length array used [-Wvla]"]
        advis = ["source/b.c:3:1: warning: value computed is not used [-Wunused-value]"]
        inline, dropped = gcc_gate.build_inline(gated, advis)
        self.assertEqual(dropped, 0)
        self.assertEqual(inline[0]["path"], "source/a.c")
        self.assertEqual(inline[0]["line"], 10)
        self.assertIn("❌", inline[0]["body"]); self.assertIn("(error)", inline[0]["body"])
        self.assertIn("-Wvla", inline[0]["body"])
        self.assertIn("❗", inline[1]["body"]); self.assertIn("(warning)", inline[1]["body"])
        self.assertTrue(all(item["side"] == "RIGHT" for item in inline))

    def test_dedupes_across_columns(self):
        # Same finding at two columns (gcc macro expansion) -> one comment.
        gated = ["source/a.c:10:5: warning: vla [-Wvla]",
                 "source/a.c:10:9: warning: vla [-Wvla]"]
        inline, dropped = gcc_gate.build_inline(gated, [])
        self.assertEqual(len(inline), 1)
        self.assertEqual(dropped, 0)

    def test_drops_unparsable(self):
        inline, dropped = gcc_gate.build_inline(["no tag here"], [])
        self.assertEqual(inline, [])
        self.assertEqual(dropped, 1)


class WriteInline(unittest.TestCase):
    def setUp(self):
        self._saved = gcc_gate.INLINE_JSON

    def tearDown(self):
        gcc_gate.INLINE_JSON = self._saved

    def _tmp(self):
        fd, json_path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        return json_path

    def test_noop_when_unset(self):
        gcc_gate.INLINE_JSON = ""
        # Must not raise and must write nothing.
        gcc_gate.write_inline("ok", [{"path": "a.c", "line": 1, "side": "RIGHT", "body": "b"}])

    def test_ok_envelope(self):
        gcc_gate.INLINE_JSON = self._tmp()
        gcc_gate.write_inline("ok", [{"path": "a.c", "line": 1, "side": "RIGHT", "body": "b"}], dropped=2)
        with open(gcc_gate.INLINE_JSON) as fh:
            doc = json.load(fh)
        self.assertEqual(doc["source"], "gcc-gate")
        self.assertEqual(doc["status"], "ok")
        self.assertEqual(doc["dropped"], 2)
        self.assertEqual(len(doc["comments"]), 1)

    def test_skipped_envelope(self):
        gcc_gate.INLINE_JSON = self._tmp()
        gcc_gate.write_inline("skipped", [])
        with open(gcc_gate.INLINE_JSON) as fh:
            doc = json.load(fh)
        self.assertEqual(doc["status"], "skipped")
        self.assertEqual(doc["comments"], [])


if __name__ == "__main__":
    unittest.main()
