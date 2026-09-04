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
"""Post idempotent PR review comments from CI candidate findings, reconciling
against what is already on the PR instead of stacking fresh comments every run.

Findings are posted as INDIVIDUAL review comments (POST /pulls/{n}/comments), not
batched under one review: a submitted COMMENTED review can never be deleted (no API
endpoint; dismiss 422s on COMMENTED reviews), so batching leaves an empty review
shell in the timeline every time its comments are later removed. Individual comments
delete cleanly and leave nothing behind.

The problem this fixes: the old format job DISMISSED prior reviews and POSTed a
new one every run. Dismissal never removes a review's inline comments, and
GitHub rejects dismissal of COMMENTED reviews anyway, so long-lived PRs grew
stacks of identical suggestions. This script instead does a comment-level
set-reconcile: post only findings that are missing, delete only ones that are
outdated / duplicated / no longer produced, and never touch a comment a human
has replied to.

It is a *trusted* stage-2 script: it runs in the base-repo context with a
`pull-requests: write` token and only ever reads passive artifact data (the
candidate JSON files) plus the PR's own comment list. It never executes PR code.

Inputs (env):
  GH_TOKEN          the token gh uses.
  REPO              owner/name.
  PR                pull-request number.
  HEAD_SHA          commit the review is anchored to.
  BOT_LOGIN         login that owns our comments (e.g. "github-actions[bot]").
  MAX_COMMENTS      cap on comments posted per run (default 25).
  SLOT              "fmt" | "inline" — which family of comments this owns. Each
                    posted body carries a hidden marker "<!-- onewifi-ci:review:SLOT -->"
                    so the two slots never reconcile against each other.
argv: one or more candidate JSON files, each:
  {"source": "...", "status": "ok"|"skipped", "dropped": N,
   "comments": [ {path, line, [start_line], side, body}, ... ]}

Fail-open contract: any load/validate failure, or a source reporting
status != "ok", disables the "stale" deletion for the slot (see reconcile) — an
empty or unreadable candidate file must NEVER be read as "everything is clean"
and wipe the live comments. Posting failures never red the PR (suggestions are
advisory); a POST 404 (usually rate limiting) is the one fatal case.
"""
import json
import os
import re
import subprocess
import sys
from collections import defaultdict

MAX_BODY_BYTES = 4096
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_ENTRIES = 1_000_000
# Lower number = posted first when the cap bites. gcc-gate findings are the
# merge-blocking ones, clang-tidy is advisory, formatter is cosmetic.
PRIORITY = {"gcc-gate": 0, "clang-tidy": 1, "formatter": 2}


def run_gh(args, input_text=None):
    """The single seam for every `gh` call, so unit tests monkeypatch one function.
    Returns (returncode, stdout, stderr)."""
    p = subprocess.run(["gh", *args], input=input_text,
                       capture_output=True, text=True)
    return p.returncode, p.stdout, p.stderr


def warn(msg):
    print(f"::warning::{msg}", file=sys.stderr)


def marker(slot):
    return f"<!-- onewifi-ci:review:{slot} -->"


def _strip_marker(body, slot):
    """Body with our marker line removed and trailing whitespace stripped — the
    canonical form both candidate bodies and live comment bodies fingerprint on."""
    mk = marker(slot)
    kept = [ln for ln in (body or "").splitlines() if ln.strip() != mk]
    return "\n".join(kept).rstrip()


def _fp(path, start_line, line, body, slot):
    return (path, start_line or None, line, _strip_marker(body, slot))


def _validate_entry(e):
    """Return a normalized candidate dict, or None if the entry is malformed."""
    if not isinstance(e, dict):
        raise ValueError("entry is not an object")
    path, line, body = e.get("path"), e.get("line"), e.get("body")
    side = e.get("side", "RIGHT")
    start_line = e.get("start_line")
    if not isinstance(path, str) or not isinstance(line, int) or not isinstance(body, str):
        raise ValueError("path/line/body have wrong types")
    if isinstance(line, bool):
        raise ValueError("line must be an int, not bool")
    if start_line is not None and (not isinstance(start_line, int) or isinstance(start_line, bool)):
        raise ValueError("start_line must be an int")
    if len(body.encode("utf-8")) > MAX_BODY_BYTES:
        raise ValueError("body exceeds size cap")
    c = {"path": path, "line": line, "side": side, "body": body}
    if start_line is not None:
        c["start_line"] = start_line
    return c


def load_candidates(paths):
    """Load every candidate file. Returns (candidates, all_ok, total_dropped).

    all_ok is True only if every file existed, parsed, validated fully, and
    reported status "ok". Anything else -> all_ok False (the stale rule is then
    suppressed so nothing is deleted for being "absent")."""
    candidates, all_ok, total_dropped = [], True, 0
    for path in paths:
        try:
            if not os.path.exists(path):
                warn(f"candidate file {path} missing — source treated as skipped (no deletes)")
                all_ok = False
                continue
            with open(path) as fh:
                if os.fstat(fh.fileno()).st_size > MAX_FILE_BYTES:
                    raise ValueError(f"exceeds {MAX_FILE_BYTES} bytes")
                doc = json.load(fh)
            source = str(doc.get("source", "unknown"))
            entries = doc.get("comments", [])
            total_dropped += int(doc.get("dropped", 0) or 0)
            if not isinstance(entries, list):
                raise ValueError("'comments' is not a list")
            if len(entries) > MAX_ENTRIES:
                raise ValueError(f"too many entries ({len(entries)})")
            if doc.get("status", "ok") != "ok":
                all_ok = False
            for e in entries:
                try:
                    c = _validate_entry(e)
                except ValueError as exc:
                    warn(f"dropping malformed candidate in {path}: {exc}")
                    all_ok = False        # incomplete set -> do not stale-delete
                    continue
                c["source"] = source
                candidates.append(c)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            warn(f"could not load candidate file {path}: {exc} — source skipped, no deletes")
            all_ok = False
    return candidates, all_ok, total_dropped


def fetch_ours(repo, pr, bot_login, slot):
    """Fetch the PR's review comments (JSONL via --paginate --jq '.[]' — a plain
    --paginate concatenates one JSON array per page and does NOT parse as one
    document). Returns (all_comments, ours) or (None, None) if the list could not
    be fetched (caller then posts nothing this run)."""
    rc, out, err = run_gh(["api", f"/repos/{repo}/pulls/{pr}/comments",
                          "--paginate", "--jq", ".[]"])
    if rc != 0:
        warn(f"could not list existing review comments: {err.strip()}")
        return None, None
    all_comments = []
    for ln in out.splitlines():
        ln = ln.strip()
        if not ln:
            continue
        try:
            all_comments.append(json.loads(ln))
        except json.JSONDecodeError:
            continue
    mk = marker(slot)
    ours = []
    for c in all_comments:
        u = c.get("user") or {}
        if u.get("login") != bot_login or u.get("type") != "Bot":
            continue
        body = c.get("body") or ""
        if mk in body:
            ours.append(c)
        elif slot == "fmt" and body.lstrip().startswith("```suggestion"):
            # backward compat: comments from before the marker existed.
            ours.append(c)
    return all_comments, ours


def reconcile(all_comments, ours, candidates, all_ok, slot, cap):
    """Decide what to delete and what to post. Returns
    (to_delete_ids, to_post, n_outdated, overflow, n_shown)."""
    our_ids = {c["id"] for c in ours}
    replied_to = {c.get("in_reply_to_id") for c in all_comments if c.get("in_reply_to_id")}
    protected_ids = our_ids & replied_to        # a human replied — never delete

    protected = [c for c in ours if c["id"] in protected_ids]
    live = [c for c in ours if c["id"] not in protected_ids]

    to_delete = []
    # outdated: GitHub nulls `line` once the anchored line no longer exists.
    outdated = [c for c in live if c.get("line") is None]
    to_delete += [c["id"] for c in outdated]
    live = [c for c in live if c.get("line") is not None]

    def fp(c):
        return _fp(c["path"], c.get("start_line"), c["line"], c.get("body") or "", slot)

    # duplicates: for one fingerprint with several live copies, keep the oldest
    # (lowest comment id) and delete the rest — the one-time cleanup of the mess
    # already sitting on long-lived PRs.
    groups = defaultdict(list)
    for c in live:
        groups[fp(c)].append(c)
    kept = []
    for group in groups.values():
        group.sort(key=lambda c: c["id"])
        kept.append(group[0])
        to_delete += [c["id"] for c in group[1:]]

    cand_fps = {_fp(c["path"], c.get("start_line"), c["line"], c["body"], slot)
                for c in candidates}

    # stale: a kept live comment whose finding is gone from the candidate set.
    # Guarded by all_ok so a skipped/empty producer never deletes everything.
    survivors = []
    for c in kept:
        if all_ok and fp(c) not in cand_fps:
            to_delete.append(c["id"])
        else:
            survivors.append(c)

    # present = what stays visible (survivors + protected); never re-post those.
    present_fps = {fp(c) for c in survivors} | {fp(c) for c in protected}
    to_post = [c for c in candidates
               if _fp(c["path"], c.get("start_line"), c["line"], c["body"], slot) not in present_fps]
    to_post.sort(key=lambda c: PRIORITY.get(c["source"], 99))
    overflow = max(0, len(to_post) - cap)
    to_post = to_post[:cap]
    return to_delete, to_post, len(outdated), overflow, len(survivors) + len(protected)


def delete_comments(repo, ids):
    for cid in ids:
        rc, _out, err = run_gh(["api", "--method", "DELETE",
                               f"/repos/{repo}/pulls/comments/{cid}"])
        if rc != 0:
            warn(f"could not delete review comment {cid}: {err.strip()} (continuing)")
        else:
            print(f"deleted stale/duplicate/outdated review comment {cid}")


def post_comments(repo, pr, head_sha, to_post, slot):
    """POST each finding as its own PR review comment. Each comment is independent:
    a benign out-of-diff 422 skips just that one and the rest still post. Returns a
    process exit code (0 = fine or advisory skips; 1 = a fatal error such as a 404
    rate limit, which stops the run so it is surfaced rather than silently swallowed)."""
    mk = marker(slot)
    posted, skipped = 0, 0
    for c in to_post:
        body = c["body"].rstrip() + "\n\n" + mk
        payload = {"commit_id": head_sha, "path": c["path"], "line": c["line"],
                   "side": c.get("side", "RIGHT"), "body": body}
        if c.get("start_line"):
            payload["start_line"] = c["start_line"]
            payload["start_side"] = c.get("side", "RIGHT")
        rc, _out, err = run_gh(["api", "--method", "POST",
                               f"/repos/{repo}/pulls/{pr}/comments", "--input", "-"],
                              input_text=json.dumps(payload))
        if rc == 0:
            posted += 1
            continue
        # A 422 has two flavours. Benign (rebase/squash-merge race): the anchored line
        # no longer exists in the diff -> "not part of the diff"; skip just this comment.
        # Any other 422 is a possible real bug (invalid payload / API), still advisory so
        # we skip it too, but say so loudly. A 404 is usually a rate limit -> stop (fatal)
        # so the run surfaces it instead of silently under-posting.
        if "HTTP 422" in err:
            if re.search(r"part of the diff|line must be part of", err, re.I):
                warn(f"skipped {c['path']}:{c['line']} — line no longer in the PR diff "
                     "(rebase/merge race); a fresh run supersedes.")
            else:
                warn(f"skipped {c['path']}:{c['line']} — 422 not an out-of-diff race; "
                     "possible invalid payload or API bug.")
            print(err)
            skipped += 1
            continue
        print(f"::error::Failed to post review comment on {c['path']}:{c['line']}:\n{err}",
              file=sys.stderr)
        print(f"posted {posted} comment(s) before the failure; {skipped} skipped.")
        return 1
    print(f"posted {posted} review comment(s); {skipped} skipped (advisory).")
    return 0


def main():
    repo = os.environ["REPO"]
    pr = os.environ["PR"]
    head_sha = os.environ["HEAD_SHA"]
    bot_login = os.environ["BOT_LOGIN"]
    slot = os.environ["SLOT"]
    cap = int(os.environ.get("MAX_COMMENTS", "25"))
    paths = sys.argv[1:]

    candidates, all_ok, dropped = load_candidates(paths)
    all_comments, ours = fetch_ours(repo, pr, bot_login, slot)
    if all_comments is None:
        warn("posting nothing this run (could not read existing comments — fail open)")
        return 0

    to_delete, to_post, n_outdated, overflow, n_shown = reconcile(
        all_comments, ours, candidates, all_ok, slot, cap)
    delete_comments(repo, to_delete)

    # Counts go to the log — there is no review-level body to carry them now. For the
    # inline slot the sticky summary surfaces them to the reader (see Commit 5).
    print(f"slot={slot}: {len(to_post)} to post · {n_shown} already shown · "
          f"{n_outdated} outdated removed · {dropped} not commentable"
          + (f" · {overflow} over the cap, will post next run" if overflow else ""))

    if not to_post:
        print(f"nothing new to post (slot={slot}); deleted {len(to_delete)} "
              "outdated/duplicate/stale.")
        return 0
    return post_comments(repo, pr, head_sha, to_post, slot)


if __name__ == "__main__":
    sys.exit(main())
