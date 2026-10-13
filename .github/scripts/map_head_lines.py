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
"""Map inline-candidate line numbers from the merge ref to the PR head (Commit 5).

makefile.yml checks out refs/pull/N/merge (HEAD), so clang-tidy and the gcc gate
report merge-result line numbers, but review comments anchor to the PR head, where
a line moves when the base branch changed the same file above it. For each path,
`git diff -U0 HEAD <head> -- <path>` lists the hunks where the two differ: a line
outside them shifts by the hunks before it; a line inside one has no counterpart
in the head, so its finding is dropped and the envelope becomes 'partial'. A path
the head does not have, or that git cannot diff, drops its findings the same way.
Only the inline candidates are mapped: the summary text and the check annotations
keep merge-ref line numbers.

Usage: map_head_lines.py <head-sha> <candidates.json>...
Rewrites each envelope in place. A missing or unreadable envelope is left alone
(the poster already treats it as incomplete); a malformed entry is passed through
for the poster to reject.
"""
import json
import re
import subprocess
import sys

HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+\d+(?:,(\d+))? @@")


def hunks_for(path, head_sha):
    """(old_start, old_len, new_len) per hunk, merge ref -> head; None if the head
    has no such file or git fails (git diff exits 0 for a path in neither tree)."""
    exists = subprocess.run(["git", "cat-file", "-e", f"{head_sha}:{path}"], capture_output=True)
    if exists.returncode != 0:
        return None
    proc = subprocess.run(
        ["git", "--literal-pathspecs", "diff", "-U0", "--no-color", "--no-ext-diff",
         "HEAD", head_sha, "--", path],
        capture_output=True, text=True)
    if proc.returncode != 0:
        return None
    hunks = []
    for text in proc.stdout.splitlines():
        hit = HUNK_RE.match(text)
        if hit:
            hunks.append((int(hit[1]), int(hit[2] or 1), int(hit[3] or 1)))
    return hunks


def map_line(hunks, line):
    """Head line for a merge-ref line, or None if that line differs in the head."""
    offset = 0
    for old_start, old_len, new_len in hunks:
        if old_len == 0:                      # lines inserted after old_start
            if line <= old_start:
                break
        elif line >= old_start + old_len:     # hunk entirely above this line
            pass
        elif line >= old_start:
            return None
        else:
            break
        offset += new_len - old_len
    return line + offset


def remap(path, head_sha):
    try:
        with open(path) as fh:
            doc = json.load(fh)
        entries = doc["comments"]
        if not isinstance(entries, list):
            return
    except (OSError, ValueError, KeyError, TypeError, RecursionError):
        return
    cache, kept, dropped = {}, [], 0
    for entry in entries:
        if not (isinstance(entry, dict) and isinstance(entry.get("path"), str)
                and isinstance(entry.get("line"), int)):
            kept.append(entry)
            continue
        if entry["path"] not in cache:
            cache[entry["path"]] = hunks_for(entry["path"], head_sha)
        hunks = cache[entry["path"]]
        line = map_line(hunks, entry["line"]) if hunks is not None else None
        start = entry.get("start_line")
        if isinstance(start, int) and line is not None:
            start = map_line(hunks, start)
            if start is None:
                line = None
        if line is None:
            dropped += 1
            continue
        entry["line"] = line
        if isinstance(entry.get("start_line"), int):
            entry["start_line"] = start
        kept.append(entry)
    if dropped:
        doc["comments"] = kept
        doc["dropped"] = (doc["dropped"] if isinstance(doc.get("dropped"), int) else 0) + dropped
        if doc.get("status") == "ok":
            doc["status"] = "partial"
        print(f"::warning::{path}: {dropped} finding(s) have no line in the PR head; not posted.")
    with open(path, "w") as fh:
        json.dump(doc, fh)


def main(argv):
    if len(argv) < 3:
        print(f"usage: {argv[0]} <head-sha> <candidates.json>...", file=sys.stderr)
        return 2
    for path in argv[2:]:
        remap(path, argv[1])
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
