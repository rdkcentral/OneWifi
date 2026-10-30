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
"""Cyclomatic-complexity nudge on the functions a PR changed; never fails the build.

For each .c/.cpp the PR changed, compare per-function CCN (lizard) between the PR base and
head, so only complexity the PR adds is reported:
  * CROSSED -- base < LOUD (or the function is new), head >= LOUD. A ❗ inline comment on the
               first changed line inside the function, a summary entry and an annotation.
  * GREW    -- grew by >= SOFT_DELTA and ends >= SOFT_FLOOR without crossing LOUD. Summary
               only. (Plain ">= +5" fires on ~34% of develop commits; with the floor, ~10%.)
A function the PR moved out of another changed or removed file (gone from that file's head)
keeps its base CCN there, so moving code is not "new complexity".

lizard runs with -Ecpre, which skips #else branches: without it, an #ifdef/#else pair that
opens a brace in each branch derails lizard and hides the rest of the file (2026-10: 344
functions in 8 core files, e.g. half of wifi_ctrl.c). Code only in an #else branch is not measured.

A file lizard cannot analyze (base or head) stops the comparison: an empty side would make
existing functions look new. Nothing is reported, the summary names the file(s), status 'partial'.

Env: REPO_ROOT ('.'), BASE (diff base ref), OUT ('ci-out/complexity.md', written only when
     something fires or a file could not be analyzed), INLINE_JSON
     ('ci-out/inline-complexity.json', always written: the review poster deletes stale
     comments only when every candidate file is present and 'ok'),
     LOUD (30), SOFT_DELTA (5), SOFT_FLOOR (20), LIZARD ('lizard', the CLI it shells out to).
Usage: complexity_delta.py <changed-files.txt> [<removed-files.txt>]   (repo-relative paths;
       removed = files the PR deleted or renamed away, read on the base side only)
"""
import bisect
import contextlib
import csv
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

REPO_ROOT = os.environ.get("REPO_ROOT", ".")
BASE = os.environ.get("BASE", "").strip()
OUT = os.environ.get("OUT", "ci-out/complexity.md")
INLINE_JSON = os.environ.get("INLINE_JSON", "ci-out/inline-complexity.json")
LIZARD = os.environ.get("LIZARD", "lizard")
SRC_EXT = (".c", ".cpp", ".cc", ".cxx")


def _int_env(name, default):
    try:
        return int(os.environ.get(name, "") or default)
    except ValueError:
        return default


LOUD = _int_env("LOUD", 30)
SOFT_DELTA = _int_env("SOFT_DELTA", 5)
SOFT_FLOOR = _int_env("SOFT_FLOOR", 20)


def parse_lizard_csv(text):
    """lizard --csv rows -> {function name: (ccn, start line, end line)}, the most complex
    one when a name repeats. Columns: NLOC,CCN,token,PARAM,length,location,file,name,
    long_name,start,end; long_name can hold commas, hence the csv module."""
    out = {}
    for row in csv.reader(text.splitlines()):
        try:
            ccn, start, end = int(row[1]), int(row[9]), int(row[10])
        except (IndexError, ValueError):
            continue  # a header or malformed row
        if ccn > out.get(row[7], (-1,))[0]:
            out[row[7]] = (ccn, start, end)
    return out


def analyze(path, text=None):
    """{name: (ccn, start, end)} for the file at `path`, or for `text` (a base version) written
    to a temp file with the same extension so lizard picks the right reader. None on failure."""
    tmp = None
    try:
        target = path
        if text is not None:
            fd, tmp = tempfile.mkstemp(suffix=os.path.splitext(path)[1] or ".c")
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(text)
            target = tmp
        proc = subprocess.run([LIZARD, "-Ecpre", "--csv", target], capture_output=True, text=True,
                              errors="replace", timeout=120)
        return parse_lizard_csv(proc.stdout) if proc.returncode == 0 else None
    except (OSError, subprocess.SubprocessError):
        return None
    finally:
        if tmp:
            with contextlib.suppress(OSError):
                os.unlink(tmp)


def git_text(*args):
    """stdout of a git command in REPO_ROOT, or None when it fails (e.g. a file new in the PR)."""
    proc = subprocess.run(["git", "-C", REPO_ROOT, *args], capture_output=True, text=True,
                          errors="replace")
    return proc.stdout if proc.returncode == 0 else None


def changed_lines(path):
    """Sorted (start, end) head-side line ranges the PR changed in path."""
    diff = git_text("diff", "-U0", BASE, "HEAD", "--", path) or ""
    ranges = []
    for hunk in re.finditer(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@", diff, re.M):
        first, count = int(hunk.group(1)), int(hunk.group(2) or 1)
        if count:
            ranges.append((first, first + count - 1))
    return sorted(ranges)


def first_changed(ranges, start, end):
    """The first changed line within [start, end], or None."""
    idx = bisect.bisect_left(ranges, (start,))
    if idx and ranges[idx - 1][1] >= start:
        return start
    if idx < len(ranges) and ranges[idx][0] <= end:
        return ranges[idx][0]
    return None


def moved_ccn(bases, heads, path):
    """{name: CCN} of the functions gone from another changed or removed file's head, the
    highest when several files lose the same name (an ambiguous move is never new complexity)."""
    moved = {}
    for other, funcs in bases.items():
        if other == path:
            continue
        for name, info in funcs.items():
            if name not in heads.get(other, {}):
                moved[name] = max(moved.get(name, 0), info[0])
    return moved


def find_deltas(base_map, moved_map, head_map):
    """(crossed, grew): lists of (name, base ccn or None for a new function, head ccn, start,
    end). The base CCN is the higher of this file's base and moved_map (another changed or
    removed file's base), so a moved function is not new."""
    crossed, grew = [], []
    for name, (head_ccn, start, end) in head_map.items():
        known = [ccn for ccn in (base_map.get(name), moved_map.get(name)) if ccn is not None]
        before = max(known) if known else None
        prev = before if before is not None else 0
        entry = (name, before, head_ccn, start, end)
        if prev < LOUD <= head_ccn:
            crossed.append(entry)
        elif head_ccn - prev >= SOFT_DELTA and head_ccn >= SOFT_FLOOR:
            grew.append(entry)
    return crossed, grew


def describe(before, after):
    return f"new at {after}" if before is None else f"{before} -> {after}"


def render_md(crossed, grew):
    """The summary section (its own ### heading); '' when nothing fired. Items: (path, entry)."""
    if not crossed and not grew:
        return ""
    lines = ["### 🧮 Complexity", ""]
    for path, (name, before, after, _start, _end) in crossed:
        lines.append(f"- ❗ `{name}` in `{path}` crossed cyclomatic complexity {LOUD} "
                     f"({describe(before, after)}): split it before it gets harder to test and review.")
    if grew:
        if crossed:
            lines.append("")
        lines.append(f"Functions whose cyclomatic complexity (CCN) grew by {SOFT_DELTA} or more "
                     f"and is now {SOFT_FLOOR} or above:")
        lines += [f"- `{name}` in `{path}` ({describe(before, after)})"
                  for path, (name, before, after, _start, _end) in grew]
    lines.append("")
    return "\n".join(lines)


def write_inline(status, comments):
    """The review_poster candidate envelope (source 'complexity'); never raises."""
    try:
        os.makedirs(os.path.dirname(INLINE_JSON) or ".", exist_ok=True)
        with open(INLINE_JSON, "w", encoding="utf-8") as fh:
            json.dump({"source": "complexity", "status": status, "dropped": 0,
                       "comments": comments}, fh)
    except OSError as exc:
        print(f"complexity: could not write {INLINE_JSON}: {exc}")


def write_md(text):
    """OUT (the summary section); never raises."""
    try:
        os.makedirs(os.path.dirname(OUT) or ".", exist_ok=True)
        with open(OUT, "w", encoding="utf-8") as fh:
            fh.write(text)
    except OSError as exc:
        print(f"complexity: could not write {OUT}: {exc}")


def read_list(path):
    try:
        with open(path, encoding="utf-8") as fh:
            return [line.strip() for line in fh if line.strip().endswith(SRC_EXT)]
    except (OSError, TypeError):
        return []


def main(argv):
    changed = read_list(argv[1] if len(argv) > 1 else None)
    removed = read_list(argv[2] if len(argv) > 2 else None)
    if not shutil.which(LIZARD) or not BASE:
        write_inline("skipped", [])
        print(f"complexity: skipped ({'no BASE' if not BASE else LIZARD + ' not found'}).")
        return 0
    failed = []  # files lizard could not analyze: an empty side would make old functions look new
    bases, heads = {}, {}
    for path in changed + removed:
        text = git_text("show", f"{BASE}:{path}")  # None: the file is new in the PR
        found = analyze(path, text) if text is not None else {}
        if found is None:
            failed.append(path)
        bases[path] = found or {}
    for path in changed:
        found = analyze(os.path.join(REPO_ROOT, path))
        if found is None:
            failed.append(path)
        heads[path] = found or {}
    if failed:
        names = ", ".join(f"`{path}`" for path in sorted(set(failed)))
        write_inline("partial", [])
        write_md(f"### 🧮 Complexity\n\n_Not compared for this commit: lizard could not analyze {names}._\n")
        print(f"complexity: not compared, lizard failed on {names}.")
        return 0
    crossed, grew, comments = [], [], []
    for path in changed:
        own = {name: info[0] for name, info in bases[path].items()}
        hits, soft = find_deltas(own, moved_ccn(bases, heads, path), heads[path])
        crossed += [(path, hit) for hit in sorted(hits)]
        grew += [(path, hit) for hit in sorted(soft)]
        ranges = changed_lines(path) if hits else []
        for name, before, after, start, end in hits:
            line = first_changed(ranges, start, end)
            if line is None:
                continue
            comments.append({"path": path, "line": line, "side": "RIGHT",
                             "body": f"❗ **complexity** `{name}` crossed cyclomatic complexity "
                                     f"{LOUD} ({describe(before, after)}). A function this complex "
                                     "is hard to test and review; consider splitting it."})
            print(f"::warning file={path},line={line}::complexity: {name} crossed {LOUD} "
                  f"({describe(before, after)})")
    write_inline("ok", comments)
    md = render_md(crossed, grew)
    if md:
        write_md(md)
    print(f"complexity: {len(crossed)} crossed {LOUD}, {len(grew)} grew by >= {SOFT_DELTA} "
          f"(ending >= {SOFT_FLOOR}) in {len(changed)} changed file(s).")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
