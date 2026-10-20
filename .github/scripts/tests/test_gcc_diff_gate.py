#!/usr/bin/env python3
# Copyright 2026 RDK Management — Apache-2.0 (see gcc_diff_gate.py header).
"""Unit tests for gcc_diff_gate.py: build_inline, the envelope status main() writes, and
recompile_cmd (the per-file recompile flags)."""
import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import gcc_diff_gate as gcc_gate  # noqa: E402


class Inline(unittest.TestCase):
    def test_build_inline(self):
        gated = ["source/a.c:10:5: warning: variable-length array used [-Wvla]",
                 "source/a.c:10:9: warning: variable-length array used [-Wvla]",   # same, other column
                 "no tag here"]                                                    # dropped
        advis = ["source/b.c:3:1: warning: value computed is not used [-Wunused-value]",
                 "source/c.c:7:2: warning: array subscript 5 is above array bounds [-Warray-bounds=]"]
        inline, dropped = gcc_gate.build_inline(gated, advis)
        self.assertEqual(dropped, 1)
        self.assertEqual([(item["path"], item["line"]) for item in inline],
                         [("source/a.c", 10), ("source/b.c", 3), ("source/c.c", 7)])
        self.assertIn("❌ **gcc** `-Wvla` (error)", inline[0]["body"])
        self.assertIn("❗ **gcc** `-Wunused-value` (warning)", inline[1]["body"])
        self.assertIn("❗ **gcc** `-Warray-bounds` (warning)", inline[2]["body"])


class MainStatus(unittest.TestCase):
    """main() marks the envelope 'partial' when a changed file failed to recompile."""

    def _run_main(self, results):
        fd, db_path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        self.addCleanup(os.unlink, db_path)
        with open(db_path, "w") as fh:
            fh.write("[]")
        fd, out_path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        self.addCleanup(os.unlink, out_path)

        def fake_run(cmd, **_kwargs):
            return results[cmd[0]]

        with mock.patch.multiple(gcc_gate, BASE="base", DB=db_path, INLINE_JSON=out_path,
                                 ADVISORY_TAGS={"[-Wunused-value]", "[-Warray-bounds]"},
                                 effective_base=lambda: "base",
                                 changed_files=lambda _base: sorted(results),
                                 changed_lines=lambda _base, _name: [(1, 10)],
                                 db_args=lambda _db, name: ("/w", [name])), \
             mock.patch.object(gcc_gate.subprocess, "run", fake_run), \
             contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            gcc_gate.main()
        with open(out_path) as fh:
            return json.load(fh)

    def _ok(self, name):
        return SimpleNamespace(returncode=0, stderr=(
            f"/w/OneWifi/source/{name}:3:5: warning: value computed is not used [-Wunused-value]"))

    def test_failed_recompile_is_partial_and_keeps_findings(self):
        self.assertEqual(self._run_main({"ok.c": self._ok("ok.c")})["status"], "ok")
        doc = self._run_main({"ok.c": self._ok("ok.c"),
                              "bad.c": SimpleNamespace(returncode=1, stderr=(
                                  "gcc: error: unrecognized command-line option '-Wfoo'"))})
        self.assertEqual(doc["status"], "partial")
        self.assertEqual(len(doc["comments"]), 1)
        # A finding the inline converter cannot parse also leaves the set incomplete.
        odd = SimpleNamespace(returncode=0, stderr="/w/OneWifi/source/odd.c:3:5: error: odd [-Wunused-value]")
        self.assertEqual(self._run_main({"odd.c": odd})["status"], "partial")
        # gcc tags a level-taking warning with '=': classified under its bare name.
        level = SimpleNamespace(returncode=0, stderr=(
            "/w/OneWifi/source/lvl.c:4:9: warning: array subscript 5 is above array bounds [-Warray-bounds=]"))
        doc = self._run_main({"lvl.c": level})
        self.assertEqual((doc["status"], len(doc["comments"])), ("ok", 1))


class RecompileCmd(unittest.TestCase):
    def test_recompile_cmd(self):
        flags = ["-Wvla", "-Wint-conversion"]
        cases = [
            # (DB args, path, OPT, must be in the command, must not be)
            (["gcc", "-Werror", "-Werror=maybe-uninitialized", "a.c"], "source/a.c", "-Os",
             ["-Os", "-Wvla", "-Wint-conversion", "-Wno-error=int-conversion", os.devnull],
             ["-Werror", "-Werror=maybe-uninitialized"]),
            (["g++", "-Werror=return-type", "a.cpp"], "source/a.cpp", "-Os",      # C-only flag dropped
             ["-Os", "-Wvla", "-Wno-error=vla"],
             ["-Wint-conversion", "-Wno-error=int-conversion", "-Werror=return-type"]),
            (["gcc", "-Werror=format", "a.c"], "source/a.c", "",                  # OPT unset
             ["-Wvla"], ["-Os", "-Werror=format"]),
        ]
        with mock.patch.multiple(gcc_gate, ALL_FLAGS=flags, C_ONLY={"-Wint-conversion"}):
            for args, path, opt, present, absent in cases:
                with mock.patch.object(gcc_gate, "OPT", opt):
                    cmd = gcc_gate.recompile_cmd(args, path)
                for flag in present:
                    self.assertIn(flag, cmd, (path, opt))
                for flag in absent:
                    self.assertNotIn(flag, cmd, (path, opt))


if __name__ == "__main__":
    unittest.main()
