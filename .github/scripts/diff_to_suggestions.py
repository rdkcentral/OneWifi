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
suggestions.

Writes two files consumed by the pr-comments.yml `format` job:
  /tmp/comments.json  - the (capped) list of review comments
  /tmp/review.json    - the full review payload for POST .../pulls/{n}/reviews

Environment:
  HEAD_SHA       required - commit the review is posted against.
  MAX_COMMENTS   optional - cap on comments per review (default 25). Large
                 reviews trigger GitHub rate limiting and fail as a misleading 404 error.

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


def parse(diff_text):
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
    print(f"{total} suggestion(s) parsed; prepared {len(comments)} to post")


if __name__ == "__main__":
    main()
