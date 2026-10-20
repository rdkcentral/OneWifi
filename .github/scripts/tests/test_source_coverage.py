#!/usr/bin/env python3
# Copyright 2026 RDK Management — Apache-2.0 (see source_coverage.py header).
"""Unit tests for source_coverage.py: Makefile.am token handling and the added-file rule,
end to end over a small tree (no git: the Makefile.am search falls back to a directory walk)."""
import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import source_coverage as cov  # noqa: E402


class Tokens(unittest.TestCase):
    def test_normalize_am_token(self):
        cases = [
            ("$(top_srcdir)/source/db/wifi_db.c", "source/core", "source/db/wifi_db.c"),
            ("wifi_mgr.c", "source/core", "source/core/wifi_mgr.c"),
            ("$(SRC_DIR)/x.c", "source/core", None),      # unresolved make variable
            ("@EXTRA@", "source/core", None),             # automake substitution
            ("wifi_mgr.h", "source/core", None),          # not a source
        ]
        for token, am_dir, expected in cases:
            self.assertEqual(cov.normalize_am_token(token, am_dir), expected, token)


class Drift(unittest.TestCase):
    def test_main(self):
        root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, root)
        files = {
            "source/core/Makefile.am": "OneWifi_SOURCES = old.c \\\n    new.c\n",
            "source/xb/Makefile.am": "xb_SOURCES = xb.c\n",          # no leg compiles source/xb
            "build/linux/bpi/makefile": "SRC = $(ONE_WIFI_HOME)/source/core/old.c\n",
        }
        for rel, text in files.items():
            os.makedirs(os.path.join(root, os.path.dirname(rel)), exist_ok=True)
            with open(os.path.join(root, rel), "w") as fh:
                fh.write(text)
        added = os.path.join(root, "added.txt")
        out = os.path.join(root, "out.md")
        cases = [
            # (added files, flagged in the summary)
            ("source/core/new.c\nsource/core/old.c\nsource/xb/xb.c\nREADME.md\n", ["source/core/new.c"]),
            ("source/core/old.c\n", []),                                   # compiled: nothing written
        ]
        for listing, flagged in cases:
            with open(added, "w") as fh:
                fh.write(listing)
            if os.path.exists(out):
                os.unlink(out)
            with mock.patch.dict(os.environ, {"REPO_ROOT": root, "OUT": out}), \
                 mock.patch.object(cov.subprocess, "run", side_effect=OSError), \
                 mock.patch("builtins.print"):
                cov.main(["source_coverage.py", added])
            text = open(out).read() if os.path.exists(out) else ""
            self.assertEqual([line[3:-1] for line in text.splitlines() if line.startswith("- `")], flagged)


if __name__ == "__main__":
    unittest.main()
