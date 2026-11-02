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
"""Unit tests for review_poster.py: the reconcile decision, fail-open loading,
comment ownership, and the posting seam (422 skips one comment, 404 is fatal)."""
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import review_poster as rp  # noqa: E402

BOT = {"login": "github-actions[bot]", "type": "Bot"}
SUG = "```suggestion\nX\n```"


def cand(path, line, body, source="formatter", start_line=None):
    item = {"path": path, "line": line, "side": "RIGHT", "body": body, "source": source}
    if start_line is not None:
        item["start_line"] = start_line
    return item


def live(cid, path, line, body, slot="fmt"):
    """A bot review comment as GitHub returns it (marker appended, as we post)."""
    return {"id": cid, "path": path, "line": line, "user": BOT,
            "body": body.rstrip() + "\n\n" + rp.marker(slot)}


class Reconcile(unittest.TestCase):
    def test_scenario(self):
        ours = [live(1, "a.c", 5, SUG),       # still produced -> kept
                live(2, "a.c", 5, SUG),       # duplicate of 1 (newer id) -> deleted
                live(3, "a.c", None, SUG),    # GitHub nulled the line (outdated) -> deleted
                live(4, "a.c", 7, "GONE"),    # finding no longer produced -> stale
                live(5, "a.c", 8, "OLD"),     # a human replied -> never deleted or reposted
                live(7, "a.c", 8, "OLD")]     # unreplied copy of 5 -> deleted
        everyone = ours + [{"id": 6, "in_reply_to_id": 5, "user": {"login": "human", "type": "User"}}]
        cands = [cand("a.c", 5, SUG), cand("a.c", 8, "OLD"), cand("a.c", 9, "NEW"),
                 cand("a.c", 9, "NEW")]       # listed twice in one envelope -> posted once
        dele, post, outdated, overflow, shown = rp.reconcile(everyone, ours, cands, True, "fmt", 25)
        self.assertEqual(sorted(dele), [2, 3, 4, 7])
        self.assertEqual([item["line"] for item in post], [9])
        self.assertEqual((outdated, overflow, shown), (1, 0, 2))
        # An incomplete candidate set never deletes a finding as "gone".
        dele, *_ = rp.reconcile(everyone, ours, cands, False, "fmt", 25)
        self.assertEqual(sorted(dele), [2, 3, 7])

    def test_priority_and_cap(self):
        cands = [cand("a.c", 1, "b1", source="formatter"),
                 cand("a.c", 2, "b2", source="gcc-gate"),
                 cand("a.c", 3, "b3", source="clang-tidy")]
        _dele, post, _o, overflow, _s = rp.reconcile([], [], cands, True, "inline", 2)
        self.assertEqual([item["source"] for item in post], ["gcc-gate", "clang-tidy"])
        self.assertEqual(overflow, 1)

    def test_resolved(self):
        intro = "**Code style:** text.\n\n"
        cases = [   # (slot, live comment, resolved?, candidates, deleted ids, posted lines)
            ("fmt", live(1, "a.c", 5, SUG), True, [cand("a.c", 5, SUG)], [], []),              # still shown
            ("fmt", live(1, "a.c", 5, SUG), True, [], [], []),                                  # fixed: kept, not stale
            ("fmt", live(1, "a.c", None, SUG), True, [cand("a.c", 9, SUG)], [], []),           # line moved: not again
            ("fmt", live(1, "a.c", None, SUG), True,
             [cand("a.c", 9, SUG), cand("a.c", 12, SUG)], [], [12]),                           # one held back, one posts
            ("fmt", live(1, "a.c", None, SUG), False, [cand("a.c", 9, SUG)], [1], [9]),        # unresolved: as before
            ("fmt", live(1, "a.c", None, SUG), True, [cand("a.c", 9, intro + SUG)], [], []),   # text line added since
            ("fmt", live(1, "a.c", 5, SUG), True, [cand("a.c", 5, intro + SUG)], [], []),      # same, line unchanged
            ("fmt", live(1, "a.c", None, SUG), True,
             [cand("a.c", 9, SUG), cand("a.c", 9, SUG)], [], []),                              # listed twice: one finding
            ("fmt", live(1, "a.c", None, SUG), True, [cand("b.c", 9, SUG)], [], [9]),          # other file
            ("inline", live(1, "a.c", None, "W1", "inline"), True,
             [cand("a.c", 9, "W1", source="gcc-gate")], [], []),                               # inline slot too
        ]
        for slot, comment, resolved, cands, deleted, posted in cases:
            dele, post, *_ = rp.reconcile([comment], [comment], cands, True, slot, 25,
                                          {1} if resolved else set())
            self.assertEqual((sorted(dele), [item["line"] for item in post]), (deleted, posted),
                             (slot, comment["line"], resolved, cands))


class LoadCandidates(unittest.TestCase):
    def _write(self, obj):
        fd, path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        with open(path, "w") as fh:
            fh.write(obj if isinstance(obj, str) and obj.startswith("[[") else json.dumps(obj))
        self.addCleanup(os.unlink, path)
        return path

    def test_ok_files_merge(self):
        gcc = {"source": "gcc-gate", "status": "ok", "dropped": 0, "comments": [
            {"path": "a.c", "line": 10, "body": "gcc A"}, {"path": "a.c", "line": 20, "body": "gcc B"}]}
        tidy = {"source": "clang-tidy", "status": "ok", "dropped": 1, "comments": [
            {"path": "b.c", "line": 5, "side": "RIGHT", "body": "tidy A"}]}
        cands, all_ok, dropped = rp.load_candidates([self._write(gcc), self._write(tidy)])
        self.assertTrue(all_ok)
        self.assertEqual(dropped, 1)
        self.assertEqual([item["source"] for item in cands], ["gcc-gate", "gcc-gate", "clang-tidy"])

    def test_incomplete_input_fails_open(self):
        # Untrusted artifacts: anything not a complete, valid set must disable deletes
        # (all_ok False) and never raise.
        good = {"path": "a.c", "line": 5, "body": "x"}
        docs = [{"source": "gcc-gate", "status": "skipped", "dropped": 0, "comments": []},
                {"source": "gcc-gate", "status": "partial", "dropped": 0, "comments": [good]},
                {}, {"source": "gcc-gate", "dropped": 0, "comments": []},   # truncated: no status
                [], "text", None, "[" * 100000 + "]" * 100000,   # RecursionError in json.load
                {"source": "gcc-gate", "status": "ok", "dropped": [1], "comments": []}]
        for doc in docs:
            _c, all_ok, _d = rp.load_candidates([self._write(doc)])
            self.assertFalse(all_ok, doc)
        self.assertFalse(rp.load_candidates(["/no/such/file.json"])[1])
        # Wrong types, and values the review API would reject with a 422: entry dropped.
        for bad in ({"line": "NOTINT"}, {"side": "UP"}, {"start_line": 5}):
            doc = {"source": "formatter", "status": "ok", "dropped": 0, "comments": [{**good, **bad}]}
            cands, all_ok, _d = rp.load_candidates([self._write(doc)])
            self.assertEqual((cands, all_ok), ([], False), bad)
        # One incomplete producer next to a complete one still disables deletes.
        ok_doc = {"source": "gcc-gate", "status": "ok", "dropped": 0, "comments": []}
        self.assertTrue(rp.load_candidates([self._write(ok_doc)])[1])
        self.assertFalse(rp.load_candidates([self._write(ok_doc), self._write(docs[0])])[1])


class GhSeam(unittest.TestCase):
    def _gh(self, fake):
        patcher = mock.patch.object(rp, "run_gh", fake)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_fetch_ours_ownership(self):
        planted = "```suggestion\n/* " + rp.marker("inline") + " */\n```"
        rows = [{"id": 1, "user": BOT, "body": "hello\n\n" + rp.marker("fmt")},     # ours: marker
                {"id": 2, "user": BOT, "body": "```suggestion\nx\n```"},            # ours: pre-marker fmt
                {"id": 3, "user": {"login": "someone", "type": "User"}, "body": "x\n\n" + rp.marker("fmt")},
                {"id": 4, "user": BOT, "body": planted + "\n\n" + rp.marker("fmt")}]  # marker planted mid-body
        jsonl = "\n".join(json.dumps(row) for row in rows) + "\n\n"   # blank lines are fine
        self._gh(lambda args, input_text=None: (0, jsonl, ""))
        self.assertEqual([item["id"] for item in rp.fetch_ours("o/r", "1", BOT["login"], "fmt")[1]], [1, 2, 4])
        self.assertEqual(rp.fetch_ours("o/r", "1", BOT["login"], "inline")[1], [])
        self.assertEqual(rp._strip_marker(rows[3]["body"], "fmt"), planted)   # fingerprint unchanged
        # An unreadable list (API error, or a line that does not parse) posts and deletes nothing.
        for result in ((1, "", "HTTP 500"), (0, jsonl + "not json\n", "")):
            self._gh(lambda args, input_text=None, result=result: result)
            self.assertEqual(rp.fetch_ours("o/r", "1", "bot", "fmt"), (None, None))

    def test_fetch_resolved(self):
        self._gh(lambda args, input_text=None: (0, "11\nnull\n12\n", ""))   # null: first comment deleted
        self.assertEqual(rp.fetch_resolved("o/r", "1"), {11, 12})
        self._gh(lambda args, input_text=None: (1, "", "HTTP 502"))            # unreadable: as before
        self.assertEqual(rp.fetch_resolved("o/r", "1"), set())

    def test_post_comments(self):
        calls = []

        def fake(args, input_text=None):
            calls.append(json.loads(input_text))
            return (0, "{}", "")
        self._gh(fake)
        to_post = [cand("a.c", 5, SUG), cand("b.c", 9, SUG, start_line=7)]
        self.assertEqual(rp.post_comments("o/r", "1", "sha123", to_post, "fmt"), 0)
        self.assertEqual([item["commit_id"] for item in calls], ["sha123", "sha123"])  # one POST each
        self.assertTrue(calls[0]["body"].endswith(rp.marker("fmt")))
        self.assertEqual(calls[1]["start_line"], 7)
        # A 422 (line left the diff) skips just that comment; a 404 (rate limit) is fatal.
        self._gh(lambda args, input_text=None: (1, "", "gh: HTTP 422 ... not part of the diff"))
        self.assertEqual(rp.post_comments("o/r", "1", "sha", [cand("a.c", 5, "x")], "fmt"), 0)
        self._gh(lambda args, input_text=None: (1, "", "gh: HTTP 502 Bad Gateway"))   # warn, stop
        self.assertEqual(rp.post_comments("o/r", "1", "sha", [cand("a.c", 5, "x")], "fmt"), 0)
        self._gh(lambda args, input_text=None: (1, "", "gh: HTTP 404 Not Found"))
        self.assertEqual(rp.post_comments("o/r", "1", "sha", [cand("a.c", 5, "x")], "fmt"), 1)


if __name__ == "__main__":
    unittest.main()
