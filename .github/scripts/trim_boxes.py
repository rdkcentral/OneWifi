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
"""Shorten one section of the CI summary comment: its code boxes and bullet lists.

A box (code fence) or bullet run under a heading with ❌ keeps its first 10 lines, any other
its first 5, and a trimmed one is followed by a "… N more" line. When anything was trimmed and
a link is given, one closing line points at it: the run summary, which holds the lists in full
(up to 100 lines each). A "… N more" line from an earlier pass also counts, so a section whose
parts were trimmed one by one still gets its one link. The headings carry the totals.

Usage: trim_boxes.py <section.md> [<link>]   (rewrites the file; any error leaves it unchanged)
"""
import sys

FENCE = "```"
LOUD_LINES, QUIET_LINES = 10, 5
MORE = "_… {} more not shown._"


def trim(lines):
    """(lines with every box and bullet run cut to its limit, number of cuts)."""
    out, cuts, loud, idx = [], 0, False, 0
    while idx < len(lines):
        line = lines[idx]
        if line.startswith("#"):
            loud = "❌" in line
        limit = LOUD_LINES if loud else QUIET_LINES
        if line.startswith(FENCE):
            end = idx + 1
            while end < len(lines) and not lines[end].startswith(FENCE):
                end += 1
            body = lines[idx + 1:end]
            out += [line, *body[:limit], FENCE]
            idx = end + 1
        elif line.startswith("- "):
            end = idx
            while end < len(lines) and lines[end].startswith("- "):
                end += 1
            body = lines[idx:end]
            out += body[:limit]
            idx = end
        else:
            out.append(line)
            idx += 1
            continue
        if len(body) > limit:
            out.append(MORE.format(len(body) - limit))
            cuts += 1
    return out, cuts


def main(argv):
    path, link = (argv + ["", ""])[1:3]
    try:
        with open(path, encoding="utf-8") as fh:
            lines = fh.read().splitlines()
        out, cuts = trim(lines)
        more_before = any(line.startswith("_… ") and line.endswith(" more not shown._") for line in lines)
        if link and (cuts or more_before):
            out += ["", f"_Longer lists, up to 100 lines each: [run summary]({link})._", ""]
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(out) + "\n")
    except (OSError, UnicodeDecodeError) as exc:
        print(f"::warning::trim_boxes: {path} left as is: {exc}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
