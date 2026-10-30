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
"""Unit tests for build_attribution.py: the tier-1 classifier, make-target parsing, compile DB
matching, the tier-2 revert/recompile/restore cycle (git and the compiler stubbed) and the three
verdict shapes."""
import os
import subprocess
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import build_attribution as ba  # noqa: E402

DB = [{"file": "/w/OneWifi/source/foo.c", "directory": "/w/OneWifi",
       "arguments": ["cc", "-c", "source/foo.c", "-o", "source/foo.o", "-Wall"]}]


def done(code=0, out=""):
    return subprocess.CompletedProcess([], code, stdout=out, stderr="")


class Tier1(unittest.TestCase):
    def test_classify_path(self):
        cases = [
            # (error path, PR changed a header, class)
            ("OneWifi/source/foo.c", False, "pr"),                                   # changed file
            ("rdk-wifi-hal/src/x.c", False, "environment"),                          # sibling tree
            ("OneWifi/easymesh_project/unified-wifi-mesh/src/x.c", False, "environment"),
            ("rdk-wifi-hal/src/x.c", True, "ambiguous"),                             # header edit
            ("OneWifi/source/other.c", False, "ambiguous"),                          # not changed
            ("/usr/include/stdio.h", False, "environment"),                          # toolchain
        ]
        for path, header, expected in cases:
            self.assertEqual(ba.classify_path(path, {"source/foo.c"}, header), expected, path)
        rows = ba.tier1(["OneWifi/source/foo.c:3:1: error: x", "ld: undefined reference to `helper'"],
                        {"source/foo.c"}, False, "+int helper(void);")
        self.assertEqual(rows, [("OneWifi/source/foo.c", "pr"), ("undefined reference: helper", "pr")])

    def test_make_targets_and_db(self):
        log = ("make: *** [build/linux/bpi/makefile:697: /w/OneWifi//source/apps/em/wifi_em.o] Error 1\n"
               "make[1]: *** [Makefile:88: bar.o] Error 2\n"
               "*** [bar.o] Error 1\n"            # repeat
               "make: *** [all] Error 2\n"        # not an object
               "make[1]: *** No rule to make target 'source/del.c', needed by 'source/del.o'.  Stop.\n")
        self.assertEqual(ba.parse_make_targets(log),
                         ["/w/OneWifi//source/apps/em/wifi_em.o", "bar.o", "source/del.c"])
        self.assertIs(ba.entry_for_object(DB, "source/foo.o"), DB[0])
        self.assertIsNone(ba.entry_for_object(DB, "oo.o"))                   # path boundary
        self.assertEqual(ba.db_args(DB, DB[0]["file"]), ("/w/OneWifi", ["cc", "source/foo.c", "-Wall"]))


class Tier2(unittest.TestCase):
    def run_tier2(self, compiles, apply_rcs, status_after="", exists=True, added=""):
        """Drive recompile_on_base with git and the compiler stubbed; returns (verdicts, note).
        compiles: one result per recompile, PR tree first: an exit code, or the stderr of a
        compile that exits 1."""
        applies, results = iter(apply_rcs), iter(compiles)

        def fake_git(args):
            if args[0] == "status":
                fake_git.calls += 1
                return done(out="" if fake_git.calls == 1 else status_after)
            if "--diff-filter=A" in args:
                return done(out=added)
            if args[0] == "diff":
                return done(out="diff --git a/source/foo.c b/source/foo.c\n")
            return done(next(applies))   # apply -R, then apply

        def fake_cmd(_cmd, _cwd):
            result = next(results)
            if isinstance(result, int):
                return done(result)
            return subprocess.CompletedProcess([], 1, stdout="", stderr=result)
        fake_git.calls = 0
        with mock.patch.object(ba, "run_git", fake_git), \
             mock.patch.object(ba, "run_cmd", fake_cmd), \
             mock.patch.object(ba.os.path, "exists", lambda _path: exists):
            return ba.recompile_on_base(DB, ["source/foo.o", "gone.o"], "base")

    def test_recompile_on_base(self):
        killed = "gcc: fatal error: Killed signal terminated program cc1"
        cases = [
            # (recompiles: PR tree, base; git apply rcs; status after restore; source exists;
            #  PR-added; verdict; note start)
            ([1, 1], [0, 0], "", True, "", "environment", ""),          # fails on base too
            ([1, 0], [0, 0], "", True, "", "pr", ""),                   # the revert fixes it
            ([1], [0, 0], "", False, "source/foo.c\n", "pr", ""),       # the PR added the file
            ([1], [0, 0], "", False, "", "unknown", ""),                # the PR renamed it
            ([1, 1], [0, 0], " M x.c\n", True, "", "environment", "WARNING"),   # tree not restored
            ([1], [1], "", True, "", None, "could not revert"),         # apply -R failed
            ([0], [], "", True, "", "unknown", "the failure did not reproduce"),   # passes a retry
            ([1, -9], [0, 0], "", True, "", "unknown", ""),             # base recompile killed
            ([1, killed], [0, 0], "", True, "", "unknown", ""),         # cc1 killed, driver exits 1
        ]
        for compiles, applies, status, exists, added, verdict, note in cases:
            verdicts, got_note = self.run_tier2(compiles, applies, status, exists, added)
            self.assertEqual(verdicts.get("source/foo.o"), verdict, (compiles, applies, status))
            self.assertEqual(verdicts.get("gone.o"), "unknown")             # not in the DB
            self.assertTrue(got_note.startswith(note), got_note)

    def test_discount_build_inputs(self):
        cases = [
            # (PR changed files, verdicts in, verdicts out, note start)
            ({"build/linux/bpi/makefile"}, {"a.o": "environment"}, {"a.o": "unknown"},
             "This PR changes build inputs (build/linux/bpi/makefile)"),
            ({".github/ci-pins.env", "source/foo.c"}, {"a.o": "environment", "b.o": "pr"},
             {"a.o": "unknown", "b.o": "pr"}, "This PR changes build inputs (.github/ci-pins.env)"),
            ({"build/linux/bpi/makefile"}, {"a.o": "pr"}, {"a.o": "pr"}, ""),        # pr stands
            ({"source/foo.c", ".github/workflows/pr-comments.yml"}, {"a.o": "environment"},
             {"a.o": "environment"}, ""),                                           # not an input
        ]
        for changed, verdicts, expected, note in cases:
            got, got_note = ba.discount_build_inputs(verdicts, changed)
            self.assertEqual(got, expected, changed)
            self.assertTrue(got_note.startswith(note) and bool(got_note) == bool(note), got_note)


class Render(unittest.TestCase):
    def test_render(self):
        rows = [("rdk-wifi-hal/src/x.c", "environment")]
        cases = [
            ({"source/foo.o": "environment"}, "", "Not caused by this PR"),
            ({"source/foo.o": "pr"}, "WARNING: x", "Caused by this PR"),
            ({"source/foo.o": "environment"}, "WARNING: x", "Build failure: cause unclear"),
            ({"source/foo.o": "pr", "bar.o": "environment"}, "", "Build failure: cause unclear"),
            ({}, "", "Build failure: cause unclear"),          # no compile DB on this leg
            ({"source/foo.o": "environment", "gone.o": "unknown"}, "", "Build failure: cause unclear"),
        ]
        for verdicts, note, heading in cases:
            md, notice = ba.render(rows, verdicts, note, {"rdk-wifi-hal"})
            self.assertEqual(md[0], ba.HEADING + heading, verdicts)
            self.assertTrue(notice)
            self.assertEqual("_WARNING: x_" in md, bool(note), verdicts)
        self.assertIn("- `rdk-wifi-hal/src/x.c`: environment", ba.render(rows, {}, "", set())[0])
        # failing objects are shown the way the build summary normalizes paths
        md, _notice = ba.render(rows, {"/home/runner/work/OneWifi/OneWifi//source/a.o": "pr"}, "", set())
        self.assertIn("The errors in OneWifi/source/a.o go away", md[1])


if __name__ == "__main__":
    unittest.main()
