#!/usr/bin/env python3
# Copyright 2026 RDK Management — Apache-2.0 (see gcc_diff_gate.py header).
"""Unit tests for gcc_diff_gate.py: build_inline, the envelope status main() writes,
preexisting / base_findings (findings the base already had) and recompile_cmd (the per-file recompile flags)."""
import contextlib
import io
import json
import os
import shutil
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

    def _run_main(self, results, base=None):
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
                                 db_args=lambda _db, name: ("/w", [name]),
                                 base_findings=lambda *_args: (base, None)), \
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
        # A finding the base version of the file already had is not posted.
        known = [(2, ("-Wunused-value", "value computed is not used"))]
        doc = self._run_main({"ok.c": self._ok("ok.c")}, base=known)
        self.assertEqual((doc["status"], doc["comments"]), ("ok", []))


class Preexisting(unittest.TestCase):
    def test_preexisting(self):
        def implicit(line, name, hint=""):
            return f"/w/x.c:{line}:5: warning: implicit declaration of function ‘{name}’{hint} [-Wimplicit-function-declaration]"
        vla = "/w/x.c:{}:10: warning: ISO C90 forbids variable length array ‘buf’ [-Wvla]"
        cases = [
            # (head stderr lines, base stderr lines or None, head line numbers whose key is pre-existing)
            ([implicit(12, "foo")], [implicit(10, "foo")], {12}),                      # edited old call
            ([implicit(12, "bar")], [implicit(10, "foo")], set()),                     # new undeclared function
            ([vla.format(5), vla.format(20)], [vla.format(5)], set()),                 # one more of the same key
            ([implicit(12, "foo")], None, set()),                                      # no base: line-scoped only
            ([implicit(12, "foo", "; did you mean ‘fob’?")], [implicit(10, "foo")], {12}),  # hint ignored
        ]
        for head_lines, base_lines, expected in cases:
            head = [gcc_gate.finding(line) for line in head_lines]
            base = None if base_lines is None else [gcc_gate.finding(line) for line in base_lines]
            old = gcc_gate.preexisting(head, base)
            self.assertEqual({line for line, key in head if key in old}, expected, head_lines)


class BaseFindings(unittest.TestCase):
    def test_base_findings(self):
        warn = ("/w/.gcc-gate-base-a.c:3:5: warning: implicit declaration of function ‘foo’ "
                "[-Wimplicit-function-declaration]")
        work = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, work)
        cases = [
            # (git show rc, compile rc, compile stderr, cwd, findings kept (None = no base), problem)
            (128, 0, "", work, None, False),                                    # file the PR adds
            (0, 1, warn + "\n/w/.gcc-gate-base-a.c:9:1: error: no member named ‘old’", work, 1, False),
            (0, 1, warn + "\nfatal error: x.h: No such file\ncompilation terminated.", work, None, True),
            (0, 0, warn, os.path.join(work, "gone"), None, True),               # temp file not writable
        ]
        for show_rc, rc, stderr, cwd, kept, problem in cases:
            cmds = []

            def fake_run(cmd, show_rc=show_rc, rc=rc, stderr=stderr, **_kwargs):
                cmds.append(cmd)
                if cmd[0] == "git":
                    return SimpleNamespace(returncode=show_rc, stdout=b"int x;\n")
                return SimpleNamespace(returncode=rc, stderr=stderr)
            with mock.patch.object(gcc_gate.subprocess, "run", fake_run):
                found, why = gcc_gate.base_findings("base", "a.c", cwd, ["gcc", "-I.", "a.c"])
            self.assertEqual((None if found is None else len(found), bool(why)), (kept, problem), stderr)
            if kept:  # compiled the base text in place of the source, then removed it
                self.assertIn(os.path.join(cwd, ".gcc-gate-base-a.c"), cmds[-1])
                self.assertNotIn("a.c", cmds[-1])
            self.assertFalse(os.path.exists(os.path.join(cwd, ".gcc-gate-base-a.c")))


class RecompileCmd(unittest.TestCase):
    def test_recompile_cmd(self):
        flags = ["-Wvla", "-Wint-conversion"]
        cases = [
            # (DB args, path, OPT, GATE_CC/GATE_CXX, compiler run, must be in the command, must not be)
            (["gcc", "-Werror", "-Werror=maybe-uninitialized", "a.c"], "source/a.c", "-Os", "",
             "gcc", ["-Os", "-Wvla", "-Wint-conversion", "-Wno-error=int-conversion", os.devnull],
             ["-Werror", "-Werror=maybe-uninitialized"]),
            (["g++", "-Werror=return-type", "a.cpp"], "source/a.cpp", "-Os", "",  # C-only flag dropped
             "g++", ["-Os", "-Wvla", "-Wno-error=vla"],
             ["-Wint-conversion", "-Wno-error=int-conversion", "-Werror=return-type"]),
            (["gcc", "-Werror=format", "a.c"], "source/a.c", "", "",              # OPT unset
             "gcc", ["-Wvla", "-U_FORTIFY_SOURCE"], ["-Os", "-Werror=format"]),
            (["/usr/bin/gcc", "a.c"], "source/a.c", "-Os", "-14",                 # compiler swapped
             "gcc-14", ["-Wint-conversion"], ["/usr/bin/gcc"]),
            (["/usr/bin/g++", "a.cpp"], "source/a.cpp", "-Os", "-14",
             "g++-14", ["-Wvla"], ["/usr/bin/g++", "-Wint-conversion"]),
        ]
        with mock.patch.multiple(gcc_gate, ALL_FLAGS=flags, C_ONLY={"-Wint-conversion"}):
            for args, path, opt, suffix, compiler, present, absent in cases:
                swap = {"GATE_CC": "gcc" + suffix if suffix else "", "GATE_CXX": "g++" + suffix if suffix else ""}
                with mock.patch.multiple(gcc_gate, OPT=opt, **swap):
                    cmd = gcc_gate.recompile_cmd(args, path)
                self.assertEqual(cmd[0], compiler, (path, suffix))
                for flag in present:
                    self.assertIn(flag, cmd, (path, opt))
                for flag in absent:
                    self.assertNotIn(flag, cmd, (path, opt))


if __name__ == "__main__":
    unittest.main()
