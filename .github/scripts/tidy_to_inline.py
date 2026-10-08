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
"""Turn a filtered clang-tidy log into review_poster.py inline candidates (Commit 5).

Input is the already-changed-lines-scoped `tidy.log` the makefile.yml clang-tidy
step builds (only `: warning:`/`: error:` lines, clang-diagnostic filtered out,
kept only where the line number is one the PR changed). Each line looks like:

    /abs/.../OneWifi/source/foo.c:42:9: warning: message text [bugprone-xyz]

`error:` lines are WarningsAsErrors-promoted checks (the gate); `warning:` lines
are advisory. One comment per (path, line, check, msg): clang-tidy can print the
same finding under several checks / columns, and review_poster does NOT dedupe
candidates against each other, so a duplicate here would post a duplicate comment.
A line that does not parse is counted 'dropped' (surfaced in the poster summary),
never silently lost.

Usage:  tidy_to_inline.py <tidy.log> <out.json> [<failed-files.txt>]
Writes a `{"source":"clang-tidy","status":"ok","dropped":N,"comments":[...]}`
envelope. A missing/unreadable log writes status 'skipped' (empty comments), and a
non-empty (or unreadable) failed-files list, one line per changed file clang-tidy
could not fully analyze, writes status 'partial'. Either way the poster disables
stale deletion for the slot instead of deleting comments as if they were fixed.
"""
import json
import re
import sys

# path (no spaces) : line : col : sev : message [check(,check...)]
LINE_RE = re.compile(
    r"^(?P<path>[^ :]+):(?P<line>\d+):\d+: (?P<sev>warning|error): "
    r"(?P<msg>.*?) \[(?P<check>[^\]]+)\]\s*$"
)
# Strip to the LAST repo dir, same idiom as makefile.yml's summaries / gcc gate:
# the runner checks out to .../OneWifi/OneWifi/easymesh_project/OneWifi/source/...
PATH_STRIP_RE = re.compile(r"^[^ ]*/(?:OneWifi|rdk-wifi-hal)/+")


def parse(text):
    """Return (comments, dropped) from clang-tidy log text."""
    comments, seen, dropped = [], set(), 0
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        hit = LINE_RE.match(line)
        if not hit:
            dropped += 1
            continue
        path = PATH_STRIP_RE.sub("", hit["path"])
        lineno = int(hit["line"])
        # A WarningsAsErrors-promoted check prints as "[name,-warnings-as-errors]".
        check = re.sub(r",-warnings-as-errors$", "", hit["check"])
        msg = hit["msg"]
        key = (path, lineno, check, msg)
        if key in seen:
            continue
        seen.add(key)
        sev, icon = ("error", "❌") if hit["sev"] == "error" else ("warning", "❗")
        comments.append({
            "path": path,
            "line": lineno,
            "side": "RIGHT",
            "body": f"{icon} **clang-tidy** `{check}` ({sev}) — {msg}",
        })
    return comments, dropped


def main(argv):
    if len(argv) not in (3, 4):
        print(f"usage: {argv[0]} <tidy.log> <out.json> [<failed-files.txt>]", file=sys.stderr)
        return 2
    log_path, out_path = argv[1], argv[2]
    status = "ok"
    if len(argv) == 4:
        try:
            with open(argv[3]) as fh:
                if fh.read().strip():
                    status = "partial"
        except OSError:
            status = "partial"
    try:
        with open(log_path) as fh:
            text = fh.read()
    except OSError:
        # No log (e.g. no compile DB) -> skipped, not "clean": the poster then
        # leaves any existing inline comments alone rather than deleting them.
        payload = {"source": "clang-tidy", "status": "skipped", "dropped": 0, "comments": []}
        with open(out_path, "w") as fh:
            json.dump(payload, fh)
        return 0
    comments, dropped = parse(text)
    payload = {"source": "clang-tidy", "status": status, "dropped": dropped, "comments": comments}
    with open(out_path, "w") as fh:
        json.dump(payload, fh)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
