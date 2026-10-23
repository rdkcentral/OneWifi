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
"""Unit tests for trim_boxes.py: box and bullet limits by heading, the "more" line."""
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import trim_boxes as tb  # noqa: E402


def box(count):
    return ["```", *[f"x.c:{num}: warning: w" for num in range(count)], "```"]


class Trim(unittest.TestCase):
    def test_trim(self):
        cases = [
            # (section lines, kept body lines per box/run, "more" counts)
            (["#### ❌ Errors (12 unique)", *box(12)], [10], [2]),        # ❌ box: 10
            (["#### ❗ warnings", *box(6)], [5], [1]),                     # other box: 5
            (["#### ❗ warnings", *box(5)], [5], []),                      # at the limit: untouched
            (["### 🧮 Complexity", *[f"- fn{num}" for num in range(7)]], [5], [2]),  # bullet run
            (["#### ❌ gate", *box(3), "#### ⚠️ coverage", *box(7)], [3, 5], [2]),   # per heading
        ]
        for lines, kept, more in cases:
            out, cuts = tb.trim(lines)
            self.assertEqual(sum(line.startswith(("x.c", "- fn")) for line in out), sum(kept), lines[0])
            self.assertEqual([line for line in out if line.startswith("_…")],
                             [f"_… {num} more not shown._" for num in more], lines[0])
            self.assertEqual((cuts, out.count("```") % 2), (len(more), 0), lines[0])

    def test_main_rewrites_file(self):
        work = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, work)
        path = os.path.join(work, "section.md")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(["#### ❗ b", *box(7)]) + "\n")
        tb.main(["trim_boxes.py", path])
        with open(path, encoding="utf-8") as fh:
            self.assertIn("_… 2 more not shown._", fh.read())


if __name__ == "__main__":
    unittest.main()
