#!/usr/bin/env python3
# Copyright 2026 RDK Management — Apache-2.0 (see build_attribution.py header).
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
               "make: *** [all] Error 2\n")       # not an object
        self.assertEqual(ba.parse_make_targets(log), ["/w/OneWifi//source/apps/em/wifi_em.o", "bar.o"])
        self.assertIs(ba.entry_for_object(DB, "source/foo.o"), DB[0])
        self.assertIsNone(ba.entry_for_object(DB, "oo.o"))                   # path boundary
        self.assertEqual(ba.db_args(DB, DB[0]["file"]), ("/w/OneWifi", ["cc", "source/foo.c", "-Wall"]))


class Tier2(unittest.TestCase):
    def run_tier2(self, compile_rc, apply_rcs, status_after="", exists=True):
        """Drive recompile_on_base with git and the compiler stubbed; returns (verdicts, note)."""
        applies = iter(apply_rcs)

        def fake_git(args):
            if args[0] == "status":
                fake_git.calls += 1
                return done(out="" if fake_git.calls == 1 else status_after)
            if args[0] == "diff":
                return done(out="diff --git a/source/foo.c b/source/foo.c\n")
            return done(next(applies))   # apply -R, then apply
        fake_git.calls = 0
        with mock.patch.object(ba, "run_git", fake_git), \
             mock.patch.object(ba, "run_cmd", lambda _cmd, _cwd: done(compile_rc)), \
             mock.patch.object(ba.os.path, "exists", lambda _path: exists):
            return ba.recompile_on_base(DB, ["source/foo.o", "gone.o"], "base")

    def test_recompile_on_base(self):
        cases = [
            # (compile rc, git apply rcs, status after restore, source exists, verdict, note start)
            (1, [0, 0], "", True, "environment", ""),        # fails on base too
            (0, [0, 0], "", True, "pr", ""),                 # the revert fixes it
            (1, [0, 0], "", False, "pr", ""),                # the PR added the file
            (1, [0, 0], " M x.c\n", True, "environment", "WARNING"),   # tree not restored
            (1, [1], "", True, None, "could not revert"),    # apply -R failed: nothing judged
        ]
        for compile_rc, applies, status, exists, verdict, note in cases:
            verdicts, got_note = self.run_tier2(compile_rc, applies, status, exists)
            self.assertEqual(verdicts.get("source/foo.o"), verdict, (compile_rc, applies, status))
            self.assertEqual(verdicts.get("gone.o"), "unknown")             # not in the DB
            self.assertTrue(got_note.startswith(note), got_note)


class Render(unittest.TestCase):
    def test_render(self):
        rows = [("rdk-wifi-hal/src/x.c", "environment")]
        cases = [
            ({"source/foo.o": "environment"}, "", "Not caused by this PR"),
            ({"source/foo.o": "pr"}, "WARNING: x", "Caused by this PR"),
            ({"source/foo.o": "environment"}, "WARNING: x", "Build failure: cause unclear"),
            ({"source/foo.o": "pr", "bar.o": "environment"}, "", "Build failure: cause unclear"),
            ({}, "", "Build failure: cause unclear"),          # no compile DB on this leg
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
