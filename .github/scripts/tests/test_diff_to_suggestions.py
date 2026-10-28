#!/usr/bin/env python3
#
# If not stated otherwise in this file or this component's LICENSE file the
# following copyright and licenses apply:
#
# Copyright 2026 RDK Management
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
"""Unit tests for diff_to_suggestions.py: parse(), line-scoping, and the candidate
envelope main() now emits for review_poster.py."""
import io
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import diff_to_suggestions as d2s  # noqa: E402

DIFF = """diff --git a/a.c b/a.c
--- a/a.c
+++ b/a.c
@@ -5,2 +5,2 @@
-int  x=1;
-int  y=2;
+int x = 1;
+int y = 2;
"""


class Parse(unittest.TestCase):
    def test_multiline_suggestion(self):
        comments = d2s.parse(DIFF)
        self.assertEqual(len(comments), 1)
        comment = comments[0]
        self.assertEqual(comment["path"], "a.c")
        self.assertEqual(comment["start_line"], 5)     # two removed lines -> ranged anchor
        self.assertEqual(comment["line"], 6)
        self.assertIn("```suggestion", comment["body"])
        self.assertIn("int x = 1;", comment["body"])

    def test_pure_insertion_dropped(self):
        # A hunk with only + lines would corrupt code on one-click apply -> dropped.
        diff = ("diff --git a/a.c b/a.c\n--- a/a.c\n+++ b/a.c\n"
                "@@ -5,0 +6,1 @@\n+int added;\n")
        self.assertEqual(d2s.parse(diff), [])


class Reflow(unittest.TestCase):
    def test_reflow_only(self):
        fits, over = "x" * 90, "x" * 120
        cases = [   # (current lines, suggested lines, dropped)
            (["foo(a,", "    b);"], ["foo(a, b);"], True),                       # join to fill
            ([f"foo({fits}, b);"], [f"foo({fits},", "    b);"], True),            # wrap a line that fits
            ([f"foo({over}, b);"], [f"foo({over},", "    b);"], False),           # wrap a line over 120
            (['f(M,"s",', "    a);"], ['f(M, "s", a);'], False),                # join + spacing fix
            (["foo(a,", "  b);"], ["foo(a,", "    b);"], False),                 # re-indent only
            (["foo(a,", "    b);", ""], ["foo(a, b);"], False),                 # join + blank line removed
            (["foo(a,", "    b);", "  bar();"], ["foo(a, b);", "    bar();"], False),   # join + re-indent
            (["x =", "    y + z;"], ["x = y + z;"], True),                         # after an operator
            (["a[i]", "    .b = 1;"], ["a[i].b = 1;"], True),                      # member access
            (["if (a)", "{"], ["if (a) {"], False),                                # brace to the if
            (["int f(void) {"], ["int f(void)", "{"], False),                      # function brace
            (["if (fd) fclose(fp);"], ["if (fd)", "    fclose(fp);"], False),     # one statement a line
            (['f("(",', "    b);"], ['f("(", b);'], True),                         # paren in a string
        ]
        for removed, added, dropped in cases:
            with self.subTest(removed=removed):
                self.assertEqual(d2s.reflow_only(removed, added), dropped)


class Scoping(unittest.TestCase):
    def test_commentable_intervals_grow_and_merge(self):
        self.assertEqual(d2s._commentable_intervals([(5, 6)], 3), [[2, 9]])
        # two close ranges merge into one rendered hunk
        self.assertEqual(d2s._commentable_intervals([(5, 5), (9, 9)], 3), [[2, 12]])

    def test_load_changed_lines_ok_and_failopen(self):
        fd, path = tempfile.mkstemp(); os.close(fd)
        self.addCleanup(os.unlink, path)
        with open(path, "w") as fh:
            fh.write("a.c:5-6\n")
        self.assertEqual(d2s.load_changed_lines(path), {"a.c": [(5, 6)]})
        with open(path, "w") as fh:
            fh.write("garbage-no-range\n")
        self.assertIsNone(d2s.load_changed_lines(path))     # fail open


class Envelope(unittest.TestCase):
    def _run_main(self, diff, changed_line=None):
        out_fd, out_path = tempfile.mkstemp(suffix=".json"); os.close(out_fd)
        self.addCleanup(os.unlink, out_path)
        env = {"CANDIDATES_OUT": out_path}
        if changed_line is not None:
            cl_fd, cl_path = tempfile.mkstemp(); os.close(cl_fd)
            self.addCleanup(os.unlink, cl_path)
            with open(cl_path, "w") as fh:
                fh.write(changed_line)
            env["CHANGED_LINES_FILE"] = cl_path
        old_stdin, old_env = sys.stdin, dict(os.environ)
        try:
            sys.stdin = io.StringIO(diff)
            os.environ.pop("CHANGED_LINES_FILE", None)
            os.environ.update(env)
            d2s.main()
        finally:
            sys.stdin = old_stdin
            os.environ.clear(); os.environ.update(old_env)
        with open(out_path) as fh:
            return json.load(fh)

    def test_envelope(self):
        out = self._run_main(DIFF, changed_line="a.c:5-6\n")
        self.assertEqual((out["source"], out["status"], out["dropped"], len(out["comments"])),
                         ("formatter", "ok", 0, 1))
        out = self._run_main(DIFF, changed_line="a.c:100-100\n")   # suggestion off the PR's lines
        self.assertEqual((out["comments"], out["dropped"]), ([], 1))
        reflow = DIFF.replace("@@ -5,2 +5,2 @@\n-int  x=1;\n-int  y=2;\n+int x = 1;\n+int y = 2;\n",
                              "@@ -5,2 +5,1 @@\n-foo(a,\n-    b);\n+foo(a, b);\n")
        out = self._run_main(reflow, changed_line="a.c:5-6\n")        # line breaks only: not posted
        self.assertEqual((out["comments"], out["dropped"]), ([], 0))
        out = self._run_main("")                                     # clang-format clean
        self.assertEqual((out["status"], out["comments"]), ("ok", []))


if __name__ == "__main__":
    unittest.main()
