#!/usr/bin/env python3
# Copyright 2026 RDK Management — Apache-2.0 (see complexity_delta.py header).
"""Unit tests for complexity_delta.py: lizard CSV parsing, the changed-line anchor, the
crossed / grew / moved rules and the files main() writes."""
import json
import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import complexity_delta as cx  # noqa: E402


class Parsing(unittest.TestCase):
    def test_parse_and_anchor(self):
        csv_text = ("NLOC,CCN,token,PARAM,length,location,file,name,long_name,start,end\n"
                    '5,2,17,1,5,"f@1-5@a.c","a.c","f","f( int a)",1,5\n'
                    '9,7,40,2,9,"g@7-15@a.c","a.c","g","g( int a , int b)",7,15\n'
                    '3,4,20,0,3,"g@20-22@a.c","a.c","g","g( void)",20,22\n')
        self.assertEqual(cx.parse_lizard_csv(csv_text), {"f": (2, 1, 5), "g": (7, 7, 15)})
        ranges = [(3, 4), (10, 12), (30, 30)]
        for start, end, expected in [(1, 5, 3), (4, 9, 4), (5, 9, None), (8, 40, 10), (31, 35, None)]:
            self.assertEqual(cx.first_changed(ranges, start, end), expected, (start, end))


class Deltas(unittest.TestCase):
    def test_find_deltas(self):
        cases = [
            # (own base, moved, head ccn, crossed?, grew?)
            ({"fn": 25}, {}, 31, True, False),      # crossed 30
            ({}, {}, 32, True, False),              # new function above 30
            ({"fn": 16}, {}, 21, False, True),      # grew 5, ends >= 20
            ({"fn": 10}, {}, 16, False, False),     # grew 6 but below the floor
            ({}, {"fn": 31}, 31, False, False),     # moved from another file: not new
            ({"fn": 31}, {}, 40, False, True),      # already above 30: grew, not crossed
        ]
        for own, moved, head, crossed, grew in cases:
            hits, soft = cx.find_deltas(own, moved, {"fn": (head, 1, 9)})
            self.assertEqual((bool(hits), bool(soft)), (crossed, grew), (own, moved, head))


class Main(unittest.TestCase):
    def _run(self, heads, bases, which="/usr/bin/lizard"):
        work = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, work)
        changed = os.path.join(work, "changed.txt")
        with open(changed, "w") as fh:
            fh.write("source/a.c\n")
        out, inline = os.path.join(work, "cx.md"), os.path.join(work, "inline.json")

        def fake_analyze(path, text=None):
            return bases.get(path) if text is not None else heads.get(os.path.normpath(path))
        diff = "@@ -40,0 +41,3 @@\n"
        with mock.patch.multiple(cx, BASE="base", OUT=out, INLINE_JSON=inline, analyze=fake_analyze,
                                 git_text=lambda *args: "text" if args[0] == "show" else diff), \
             mock.patch.object(cx.shutil, "which", lambda _name: which), \
             mock.patch("builtins.print"):
            cx.main(["complexity_delta.py", changed])
        with open(inline) as fh:
            doc = json.load(fh)
        md = open(out).read() if os.path.exists(out) else ""
        return doc, md

    def test_main(self):
        head = {"source/a.c": {"fn": (34, 30, 60)}}
        doc, md = self._run(head, {"source/a.c": {"fn": (12, 30, 50)}})
        self.assertEqual((doc["status"], [comment["line"] for comment in doc["comments"]]), ("ok", [41]))
        self.assertIn("`fn` in `source/a.c` crossed cyclomatic complexity 30 (12 -> 34)", md)
        doc, md = self._run({"source/a.c": None}, {"source/a.c": {}})       # lizard failed
        self.assertEqual((doc["status"], md), ("partial", ""))
        doc, _md = self._run(head, {}, which=None)                         # lizard missing
        self.assertEqual(doc["status"], "skipped")


if __name__ == "__main__":
    unittest.main()
