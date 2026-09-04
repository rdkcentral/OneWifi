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
import gcc_diff_gate as g  # noqa: E402


class BuildInline(unittest.TestCase):
    def test_gate_advisory_split(self):
        gated = ["source/a.c:10:5: warning: variable-length array used [-Wvla]"]
        advis = ["source/b.c:3:1: warning: value computed is not used [-Wunused-value]"]
        inline, dropped = g.build_inline(gated, advis)
        self.assertEqual(dropped, 0)
        self.assertEqual(inline[0]["path"], "source/a.c")
        self.assertEqual(inline[0]["line"], 10)
        self.assertIn("(gate)", inline[0]["body"])
        self.assertIn("-Wvla", inline[0]["body"])
        self.assertIn("(advisory)", inline[1]["body"])
        self.assertTrue(all(c["side"] == "RIGHT" for c in inline))

    def test_dedupes_across_columns(self):
        # Same finding at two columns (gcc macro expansion) -> one comment.
        gated = ["source/a.c:10:5: warning: vla [-Wvla]",
                 "source/a.c:10:9: warning: vla [-Wvla]"]
        inline, dropped = g.build_inline(gated, [])
        self.assertEqual(len(inline), 1)
        self.assertEqual(dropped, 0)

    def test_drops_unparsable(self):
        inline, dropped = g.build_inline(["no tag here"], [])
        self.assertEqual(inline, [])
        self.assertEqual(dropped, 1)


class WriteInline(unittest.TestCase):
    def setUp(self):
        self._saved = g.INLINE_JSON

    def tearDown(self):
        g.INLINE_JSON = self._saved

    def _tmp(self):
        fd, p = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        return p

    def test_noop_when_unset(self):
        g.INLINE_JSON = ""
        # Must not raise and must write nothing.
        g.write_inline("ok", [{"path": "a.c", "line": 1, "side": "RIGHT", "body": "b"}])

    def test_ok_envelope(self):
        g.INLINE_JSON = self._tmp()
        g.write_inline("ok", [{"path": "a.c", "line": 1, "side": "RIGHT", "body": "b"}], dropped=2)
        with open(g.INLINE_JSON) as fh:
            doc = json.load(fh)
        self.assertEqual(doc["source"], "gcc-gate")
        self.assertEqual(doc["status"], "ok")
        self.assertEqual(doc["dropped"], 2)
        self.assertEqual(len(doc["comments"]), 1)

    def test_skipped_envelope(self):
        g.INLINE_JSON = self._tmp()
        g.write_inline("skipped", [])
        with open(g.INLINE_JSON) as fh:
            doc = json.load(fh)
        self.assertEqual(doc["status"], "skipped")
        self.assertEqual(doc["comments"], [])


if __name__ == "__main__":
    unittest.main()
