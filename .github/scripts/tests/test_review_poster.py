#!/usr/bin/env python3
# Copyright 2026 RDK Management — Apache-2.0 (see review_poster.py header).
"""Unit tests for review_poster.py: the reconcile decision (post/delete/protect/
priority/cap), fail-open loading, comment ownership, and the 422/404 posting seam."""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import review_poster as rp  # noqa: E402


def cand(path, line, body, source="formatter", start_line=None):
    item = {"path": path, "line": line, "side": "RIGHT", "body": body, "source": source}
    if start_line is not None:
        item["start_line"] = start_line
    return item


def live(cid, path, line, body, start_line=None, marker_slot="fmt"):
    """A bot review comment as GitHub returns it (marker appended, as we post)."""
    full_body = body.rstrip() + "\n\n" + rp.marker(marker_slot) if marker_slot else body
    item = {"id": cid, "path": path, "line": line, "body": full_body,
         "user": {"login": "github-actions[bot]", "type": "Bot"}}
    if start_line is not None:
        item["start_line"] = start_line
    return item


class Reconcile(unittest.TestCase):
    def test_posts_only_missing(self):
        ours = [live(1, "a.c", 5, "```suggestion\nX\n```")]
        cands = [cand("a.c", 5, "```suggestion\nX\n```"),      # already live
                 cand("a.c", 9, "```suggestion\nY\n```")]      # new
        dele, post, outdated, overflow, shown = rp.reconcile(ours, ours, cands, True, "fmt", 25)
        self.assertEqual(dele, [])
        self.assertEqual([item["line"] for item in post], [9])
        self.assertEqual(shown, 1)

    def test_outdated_deleted(self):
        item = live(7, "a.c", None, "```suggestion\nX\n```")   # GitHub nulled line
        dele, post, outdated, _o, _s = rp.reconcile([item], [item], [], True, "fmt", 25)
        self.assertEqual(dele, [7])
        self.assertEqual(outdated, 1)

    def test_duplicates_keep_oldest(self):
        first_copy = live(3, "a.c", 5, "```suggestion\nX\n```")
        second_copy = live(8, "a.c", 5, "```suggestion\nX\n```")   # same fingerprint, newer id
        cands = [cand("a.c", 5, "```suggestion\nX\n```")]
        dele, post, _o, _ov, shown = rp.reconcile([first_copy, second_copy], [first_copy, second_copy], cands, True, "fmt", 25)
        self.assertEqual(dele, [8])          # newer duplicate removed, oldest kept
        self.assertEqual(post, [])           # kept one already satisfies the candidate
        self.assertEqual(shown, 1)

    def test_stale_deleted_only_when_all_ok(self):
        item = live(4, "a.c", 5, "```suggestion\nGONE\n```")   # not in candidates
        # all_ok True -> stale delete
        dele, post, *_ = rp.reconcile([item], [item], [], True, "fmt", 25)
        self.assertEqual(dele, [4])
        # all_ok False (producer skipped) -> never delete "stale"
        dele2, post2, *_ = rp.reconcile([item], [item], [], False, "fmt", 25)
        self.assertEqual(dele2, [])

    def test_protected_never_deleted_nor_reposted(self):
        item = live(10, "a.c", 5, "```suggestion\nX\n```")
        reply = {"id": 11, "in_reply_to_id": 10, "user": {"login": "human", "type": "User"}}
        allc = [item, reply]
        # candidate matches the protected comment's finding -> must NOT re-post it,
        # and stale rule must NOT delete it even though we could.
        cands = [cand("a.c", 5, "```suggestion\nX\n```")]
        dele, post, _o, _ov, shown = rp.reconcile(allc, [item], cands, True, "fmt", 25)
        self.assertEqual(dele, [])
        self.assertEqual(post, [])
        self.assertEqual(shown, 1)

    def test_priority_and_cap(self):
        cands = [cand("a.c", 1, "b1", source="formatter"),
                 cand("a.c", 2, "b2", source="gcc-gate"),
                 cand("a.c", 3, "b3", source="clang-tidy")]
        dele, post, _o, overflow, _s = rp.reconcile([], [], cands, True, "inline", 2)
        self.assertEqual([item["source"] for item in post], ["gcc-gate", "clang-tidy"])
        self.assertEqual(overflow, 1)

    def test_slots_do_not_cross(self):
        # A fmt-slot comment is invisible to the inline slot (different marker), so an
        # inline run does not delete it as "stale".
        item = live(20, "a.c", 5, "gcc finding", marker_slot="fmt")
        dele, post, *_ = rp.reconcile([item], [], [], True, "inline", 25)
        self.assertEqual(dele, [])   # not ours in this slot


class LoadCandidates(unittest.TestCase):
    def _write(self, obj):
        fd, path = tempfile.mkstemp(suffix=".json"); os.close(fd)
        with open(path, "w") as fh:
            json.dump(obj, fh)
        self.addCleanup(os.unlink, path)
        return path

    def test_ok(self):
        cand_file = self._write({"source": "formatter", "status": "ok", "dropped": 2,
                         "comments": [{"path": "a.c", "line": 5, "body": "x"}]})
        cands, all_ok, dropped = rp.load_candidates([cand_file])
        self.assertTrue(all_ok)
        self.assertEqual(dropped, 2)
        self.assertEqual(len(cands), 1)
        self.assertEqual(cands[0]["source"], "formatter")

    def test_status_skipped_disables_stale(self):
        cand_file = self._write({"source": "gcc-gate", "status": "skipped", "comments": []})
        _cands, all_ok, _d = rp.load_candidates([cand_file])
        self.assertFalse(all_ok)

    def test_bad_document_shapes_fail_open(self):
        # Untrusted artifact: a wrong shape must warn and disable deletes, never raise.
        for doc in ([], "text", None, {"status": "ok", "dropped": [1], "comments": []}):
            _cands, all_ok, _d = rp.load_candidates([self._write(doc)])
            self.assertFalse(all_ok)

    def test_missing_file_fails_open(self):
        _cands, all_ok, _d = rp.load_candidates(["/no/such/file.json"])
        self.assertFalse(all_ok)

    def test_malformed_entry_dropped_and_not_ok(self):
        cand_file = self._write({"source": "formatter", "status": "ok",
                         "comments": [{"path": "a.c", "line": "NOTINT", "body": "x"}]})
        cands, all_ok, _d = rp.load_candidates([cand_file])
        self.assertEqual(cands, [])
        self.assertFalse(all_ok)


class GhSeam(unittest.TestCase):
    def test_fetch_ours_marker_and_backcompat(self):
        rows = [
            {"id": 1, "user": {"login": "github-actions[bot]", "type": "Bot"},
             "body": "hello\n\n" + rp.marker("fmt")},                 # ours (marker)
            {"id": 2, "user": {"login": "github-actions[bot]", "type": "Bot"},
             "body": "```suggestion\nx\n```"},                        # ours (backcompat)
            {"id": 3, "user": {"login": "someone", "type": "User"},
             "body": "not ours"},                                     # foreign
        ]
        jsonl = "\n".join(json.dumps(row) for row in rows)
        rp.run_gh = lambda args, input_text=None: (0, jsonl, "")
        allc, ours = rp.fetch_ours("o/r", "1", "github-actions[bot]", "fmt")
        self.assertEqual(sorted(item["id"] for item in ours), [1, 2])
        # inline slot: backcompat rule does not apply, only the marker
        _allc, ours_inline = rp.fetch_ours("o/r", "1", "github-actions[bot]", "inline")
        self.assertEqual([item["id"] for item in ours_inline], [])

    def test_fetch_ours_ignores_planted_marker(self):
        # A formatter suggestion reproduces PR source, so a PR can plant another
        # slot's marker mid-body; only the trailing marker line decides ownership.
        planted = "```suggestion\n/* " + rp.marker("inline") + " */\n```"
        rows = [{"id": 7, "user": {"login": "github-actions[bot]", "type": "Bot"},
                 "body": planted + "\n\n" + rp.marker("fmt")}]
        jsonl = "\n".join(json.dumps(row) for row in rows)
        rp.run_gh = lambda args, input_text=None: (0, jsonl, "")
        _a, ours_inline = rp.fetch_ours("o/r", "1", "github-actions[bot]", "inline")
        self.assertEqual(ours_inline, [])
        _a, ours_fmt = rp.fetch_ours("o/r", "1", "github-actions[bot]", "fmt")
        self.assertEqual([item["id"] for item in ours_fmt], [7])
        # and the fingerprint still matches the candidate it was posted from
        self.assertEqual(rp._strip_marker(rows[0]["body"], "fmt"), planted)

    def test_fetch_ours_api_failure_is_none(self):
        rp.run_gh = lambda args, input_text=None: (1, "", "HTTP 500")
        allc, ours = rp.fetch_ours("o/r", "1", "bot", "fmt")
        self.assertIsNone(allc)

    def test_post_comments_one_per_finding(self):
        calls = []
        def fake(args, input_text=None):
            calls.append(json.loads(input_text))
            return (0, "{}", "")
        rp.run_gh = fake
        to_post = [cand("a.c", 5, "```suggestion\nx\n```"),
                   cand("b.c", 9, "```suggestion\ny\n```", start_line=7)]
        self.assertEqual(rp.post_comments("o/r", "1", "sha123", to_post, "fmt"), 0)
        self.assertEqual(len(calls), 2)                       # one POST per comment
        self.assertTrue(all(item["commit_id"] == "sha123" for item in calls))
        self.assertIn(rp.marker("fmt"), calls[0]["body"])     # marker appended
        self.assertEqual(calls[1]["start_line"], 7)           # multi-line preserved

    def test_post_422_benign_skips_that_comment(self):
        rp.run_gh = lambda args, input_text=None: (1, "", "gh: HTTP 422 ... not part of the diff")
        self.assertEqual(rp.post_comments("o/r", "1", "sha", [cand("a.c", 5, "x")], "fmt"), 0)

    def test_post_404_is_fatal(self):
        rp.run_gh = lambda args, input_text=None: (1, "", "gh: HTTP 404 Not Found")
        self.assertEqual(rp.post_comments("o/r", "1", "sha", [cand("a.c", 5, "x")], "fmt"), 1)


class InlineGccTidyFixture(unittest.TestCase):
    """End-to-end: real gcc-gate + clang-tidy candidate envelopes (as the two
    Commit-5 producers write them) flow through load_candidates -> reconcile on the
    inline slot. gcc gates post before clang-tidy, the cap drops the overflow
    (advisory), and per-file `dropped` counts aggregate for the poster summary."""
    def _write(self, obj):
        fd, cand_file = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        with open(cand_file, "w") as fh:
            json.dump(obj, fh)
        return cand_file

    def test_priority_and_cap_across_files(self):
        gcc = {"source": "gcc-gate", "status": "ok", "dropped": 0, "comments": [
            {"path": "a.c", "line": 10, "side": "RIGHT", "body": "gcc A"},
            {"path": "a.c", "line": 20, "side": "RIGHT", "body": "gcc B"}]}
        tidy = {"source": "clang-tidy", "status": "ok", "dropped": 1, "comments": [
            {"path": "b.c", "line": 5, "side": "RIGHT", "body": "tidy A"}]}
        cands, all_ok, dropped = rp.load_candidates([self._write(gcc), self._write(tidy)])
        self.assertTrue(all_ok)
        self.assertEqual(dropped, 1)                    # tidy reported 1 uncommentable
        dele, post, _o, overflow, _s = rp.reconcile([], [], cands, all_ok, "inline", 2)
        # gcc-gate (priority 0) before clang-tidy (1); cap=2 keeps both gcc, drops tidy.
        self.assertEqual([item["source"] for item in post], ["gcc-gate", "gcc-gate"])
        self.assertEqual(overflow, 1)

    def test_one_skipped_producer_disables_stale(self):
        # gcc "ok" but tidy "skipped" -> all_ok False -> the inline slot keeps any
        # live comment even when the ok producer no longer lists it (fail-open).
        gcc = {"source": "gcc-gate", "status": "ok", "dropped": 0, "comments": []}
        tidy = {"source": "clang-tidy", "status": "skipped", "dropped": 0, "comments": []}
        _c, all_ok, _d = rp.load_candidates([self._write(gcc), self._write(tidy)])
        self.assertFalse(all_ok)


if __name__ == "__main__":
    unittest.main()
