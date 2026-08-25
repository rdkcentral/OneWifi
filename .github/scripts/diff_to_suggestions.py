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
"""Convert a git-clang-format unified diff (read from stdin) into GitHub PR review
suggestions, scoped to lines the PR actually changed.

Writes two files consumed by the pr-comments.yml `format` job:
  /tmp/comments.json  - the (capped) list of review comments
  /tmp/review.json    - the full review payload for POST .../pulls/{n}/reviews

Environment:
  HEAD_SHA            required - commit the review is posted against.
  MAX_COMMENTS        optional - cap on comments per review (default 25). Large
                      reviews trigger GitHub rate limiting and fail as a misleading
                      404 error.
  CHANGED_LINES_FILE  optional - path to a file listing the PR's changed lines
                      (format: "path:start-end" per line, new-side line numbers).
                      When present, suggestions that target only lines the PR did
                      NOT change are dropped. When absent or unparseable, all
                      suggestions are kept (fail-open, same as before this filter).

Line scoping rationale: git-clang-format can reformat lines adjacent to the
actual change. The primary mechanism (verified in git_clang_format 18.1.8,
extract_lines_from_patch): when a hunk is a pure deletion (+C,0 — zero
new-side lines), the script forces line_count to 1 and formats the line at
the deletion site. ColumnLimit / SortIncludes can also cascade beyond changed
lines. Without this filter, the PR review would contain suggestions on lines
the author never touched — confusing and noisy. A suggestion is kept only if it
is BOTH (a) *relevant* — it overlaps at least one line the PR actually changed —
and (b) *postable* — its whole line range lies inside the region GitHub will accept
a comment on: the changed lines PLUS the diff context rendered around them. Neither
half suffices alone: mere overlap risks a 422 (GitHub anchors a multi-line review
comment on both endpoints and rejects the ENTIRE review if either is outside the
rendered diff, so one out-of-range suggestion drops them all); containment in the
changed lines alone was the opposite error, dropping a reformat that cascades a line
or two into commentable context. See relevant_and_postable() below.

Note: a deletions-only PR produces an empty changed-lines file (no new-side
lines) → filter active with zero lines → all suggestions dropped. This is
correct (no surviving line was changed), distinct from a missing file which
is fail-open.

A "Commit suggestion" button is just a review comment whose body is a
```suggestion block. In the diff the 'old' side (-) is the text currently in the
PR head (what we comment on); the 'new' side (+) is the replacement text.

This lives in a checked-out file (not a YAML heredoc) so it can be unit-tested
and reviewed. The 'format' job runs it from the trusted base-branch checkout.
"""
import json
import os
import re
import sys

HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
# Split on the LAST ':' — the range is always the final field, and a path may
# itself contain ':' (legal on POSIX). A greedy '.+' with the anchored numeric
# tail backtracks to the right delimiter; '[^:]+' would drop colon-in-path files.
CHANGED_LINE = re.compile(r"^(.+):(\d+)-(\d+)$")

# Upper bound on records loaded from CHANGED_LINES_FILE. That file is a stage-1
# artifact built over untrusted fork PR code (clang-format.yml runs on
# `pull_request`, whose workflow the PR author can modify), yet it is consumed
# here in the trusted `pull-requests: write` comment job — so it is
# attacker-influenced input. Ranges are kept as (start, end) intervals and NEVER
# expanded into per-line sets, so a compact hostile record like "x.c:1-1000000000"
# costs one tuple, not a billion-element set that would OOM-kill this job (and
# MemoryError is not an OSError/ValueError — it would escape the handler below and
# crash the step). This cap additionally bounds a pathological many-record file;
# beyond it we fail open (post unfiltered, still capped by MAX_COMMENTS).
MAX_CHANGED_RECORDS = 1_000_000

# Total-byte guard on the same attacker-influenced file. The record cap above counts
# newline-delimited records, but `for raw in fh` materializes one physical line at a time,
# so a single newline-free multi-GB line would OOM-kill this job before any record is seen
# (and MemoryError escapes the OSError/ValueError handler below). An fstat on the open
# handle bounds total bytes up front -- no line can exceed the file -- closing both the
# single-huge-line case and a flood of blank lines (which `continue` before the counter).
# 64 MiB is generous next to the ~20 B/record minimum implied by the 1M-record cap.
MAX_FILE_BYTES = 64 * 1024 * 1024

# GitHub renders a PR diff with a few lines of CONTEXT around each change, and those context
# lines are commentable too — so the region a review comment may anchor in is the changed
# lines GROWN by this margin (then merged where two hunks sit close enough to render as one).
# 3 is GitHub's default rendered context. This is the one value here NOT backed by a documented
# API contract: too small over-drops valid suggestions (safe); too large risks a residual 422,
# which the pr-comments.yml handler absorbs as an advisory. Set to 0 to recover strict
# containment-in-changed-lines.
DIFF_CONTEXT = 3


def load_changed_lines(path):
    """Load {file: [(start, end), ...]} changed-line intervals from a changed-lines file.

    Each line is "path:start-end" (inclusive, new-side line numbers from
    git diff -U0). Ranges are stored as intervals, NOT expanded into sets, so a
    hostile range cannot exhaust memory (see MAX_CHANGED_RECORDS). Returns None on
    any I/O or parse error, or if the record cap is exceeded (fail-open).
    """
    try:
        changed = {}
        records = 0
        with open(path) as fh:
            if os.fstat(fh.fileno()).st_size > MAX_FILE_BYTES:
                # Reject before reading: bounds memory regardless of how the bytes are
                # split into lines. Raise so the handler below fails open (post unfiltered).
                raise ValueError(f"changed-lines file exceeds {MAX_FILE_BYTES} bytes")
            for raw in fh:
                line = raw.strip()
                if not line:
                    continue                      # blank line: an empty file (deletions-only PR) is valid
                m = CHANGED_LINE.match(line)
                if not m:
                    # A malformed record must not silently shrink the map (that would
                    # drop the affected file's suggestions). Fail open instead: raise
                    # so the handler below returns None and all suggestions are kept.
                    raise ValueError(f"unparseable changed-lines record: {line!r}")
                f, s, e = m.group(1), int(m.group(2)), int(m.group(3))
                if s > e:
                    # Reversed range. With sets, range(5,3) was silently empty; with
                    # intervals a (5,2) tuple would spuriously overlap-match, so treat
                    # it as malformed and fail open rather than change matching
                    # behavior. Well-formed git-diff -U0 records always have s <= e.
                    raise ValueError(f"reversed changed-lines record: {line!r}")
                records += 1
                if records > MAX_CHANGED_RECORDS:
                    raise ValueError(
                        f"changed-lines file exceeds {MAX_CHANGED_RECORDS} records")
                changed.setdefault(f, []).append((s, e))
        return changed
    except (OSError, ValueError) as exc:
        print(f"::warning::Could not load changed-lines file {path}: {exc} "
              "(posting unfiltered)", file=sys.stderr)
        return None


def _commentable_intervals(intervals, ctx):
    """Changed intervals grown by `ctx` and merged — the line ranges GitHub will accept a
    review comment on (a hunk's changed lines plus the context lines rendered around them).
    Two grown intervals that touch/overlap (i.e. the original change gap is <= 2*ctx, which
    is exactly when git renders one contiguous hunk) merge into one region."""
    grown = sorted((max(1, s - ctx), e + ctx) for (s, e) in intervals)
    merged = []
    for s, e in grown:
        if merged and s <= merged[-1][1] + 1:     # overlaps or adjoins the previous region
            merged[-1][1] = max(merged[-1][1], e)
        else:
            merged.append([s, e])
    return merged


def parse(diff_text):
    # diff_text is the git-clang-format diff (HEAD vs its reformatted copy), NOT the
    # PR diff. So the '-' side is the current PR HEAD file: old_ln (the '-' line
    # number) is already in HEAD coordinates — exactly what a GitHub side:RIGHT
    # suggestion anchors on, and the same coordinate system as CHANGED_LINES_FILE
    # (git diff -U0 BASE HEAD, new-side). Do NOT "fix" this to the '+' range: those
    # are the reformatted-file line numbers, which match neither GitHub nor the filter.
    comments, path, old_ln = [], None, 0
    removed, added, start = [], [], None

    def flush():
        nonlocal removed, added, start
        if start is None or (not removed and not added):
            removed, added, start = [], [], None
            return
        if not removed:
            # Pure-insertion hunk (only + lines): a ```suggestion anchored here
            # replaces the anchor line and silently deletes its original content
            # on a one-click apply. clang-format's real edits always touch an
            # existing line (a line split shows a removed line too), so drop
            # these rather than risk corrupting code.
            removed, added, start = [], [], None
            return
        body = "```suggestion\n" + "".join(line + "\n" for line in added) + "```"
        c = {
            "path": path,
            "side": "RIGHT",
            "body": body,
            "line": start + len(removed) - 1,
        }
        if len(removed) > 1:
            c["start_line"] = start
            c["start_side"] = "RIGHT"
        comments.append(c)
        removed, added, start = [], [], None

    for raw in diff_text.splitlines():
        if raw.startswith("diff --git"):
            flush(); path = None; continue
        if raw.startswith("--- "):
            continue
        if raw.startswith("+++ "):
            p = raw[4:].strip()
            path = p[2:] if p.startswith("b/") else p
            continue
        m = HUNK.match(raw)
        if m:
            flush(); old_ln = int(m.group(1)); continue
        if path is None:
            continue
        if raw.startswith("-"):
            if start is None:
                start = old_ln
            removed.append(raw[1:]); old_ln += 1
        elif raw.startswith("+"):
            if start is None:
                start = old_ln
            added.append(raw[1:])
        elif raw.startswith("\\"):
            continue
        else:
            flush(); old_ln += 1
    flush()
    return comments


def main():
    comments = parse(sys.stdin.read())
    raw_total = len(comments)

    # Line-scope: drop suggestions that target only lines the PR didn't change.
    cl_path = os.environ.get("CHANGED_LINES_FILE", "")
    changed = load_changed_lines(cl_path) if cl_path else None
    if changed is not None:
        # Precompute the commentable region (changed lines grown by DIFF_CONTEXT, merged)
        # once per file; the raw changed intervals stay for the relevance test below.
        commentable = {f: _commentable_intervals(ivs, DIFF_CONTEXT)
                       for f, ivs in changed.items()}

        def relevant_and_postable(c):
            raw = changed.get(c["path"])
            if not raw:                           # file untouched by the PR
                return False
            cstart = c.get("start_line", c["line"])
            cend = c["line"]
            # (a) relevant: the comment range overlaps >=1 line the PR actually changed.
            #     Drops a reformat sitting wholly on context lines the author never touched.
            touches = any(s <= cend and cstart <= e for (s, e) in raw)
            # (b) postable: its whole range lies inside the commentable region, so GitHub
            #     accepts the anchor and does not 422 the review. Overlap alone risked that
            #     422; containment-in-changed alone over-dropped a reformat cascading a line
            #     or two into commentable context. Keep only what is both.
            postable = any(s <= cstart and cend <= e for (s, e) in commentable[c["path"]])
            return touches and postable
        before = len(comments)
        comments = [c for c in comments if relevant_and_postable(c)]
        dropped = before - len(comments)
        if dropped:
            print(f"Line-scoping: dropped {dropped} suggestion(s) off the PR's changed/commentable lines")

    total = len(comments)
    cap = int(os.environ.get("MAX_COMMENTS", "25"))
    if total > cap:
        comments = comments[:cap]
    with open("/tmp/comments.json", "w") as fh:
        json.dump(comments, fh)

    body = ("`clang-format` suggests the formatting changes below. "
            "Use **Commit suggestion** to apply them.")
    if total > cap:
        body += (f"\n\n> **Note:** showing the first {cap} of {total} suggestions. "
                 "Apply these and push, and the rest post on the next run — "
                 "or fix them all at once locally:\n"
                 "> ```\n"
                 "> pip install clang-format==18.1.8\n"
                 "> git-clang-format --style=file --extensions c,h,cpp <merge-base>\n"
                 "> ```")
    review = {
        "commit_id": os.environ["HEAD_SHA"],
        "event": "COMMENT",
        "body": body,
        "comments": comments,
    }
    with open("/tmp/review.json", "w") as fh:
        json.dump(review, fh)
    print(f"{raw_total} suggestion(s) parsed, {total} after line-scoping; "
          f"prepared {len(comments)} to post")


if __name__ == "__main__":
    main()
