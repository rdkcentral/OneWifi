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
"""Diff-scoped gcc warning gate (PROPOSAL — branch ci/diff-scoped-warning-gate).

Gate not-yet-promoted gcc warning classes on the PR's changed lines *only*, without
promoting them tree-wide. The OneWifi tree still carries backlogs for these classes
(e.g. -Wvla: 18 sites, -Wreturn-type: 11), so a whole-file/tree -Werror would red every
PR. Instead lets recompile each changed .c/.cpp from compile_commands.json with the candidate
warnings enabled, then keep only findings whose line the PR actually changed.
A PR can then fail on a class it newly introduced on a line it touched.
The silent baseline (and the build-summary that relies on it) remains unaffected.

This is the gcc analogue of the clang-tidy changed-lines gate already in makefile.yml.
Because each file is recompiled on its own, every warning in that compile belongs to that
file, so filtering on the line number alone is sufficient (same reasoning as clang-tidy).
No need to filter on file:line pairs as analyzing full build.log would require

Env:
  BASE               PR base sha (already fetched by the caller)
  GATE_WARNINGS      space-separated -W flags that FAIL the job when introduced on a changed line
  ADVISORY_WARNINGS  space-separated -W flags that are only reported
  ENFORCE            'false' -> advisory (render ❌ but exit 0). default enforce
  REPO_DIR           dir the changed files + git history live in (default '.'; the HAL sets
                     this to '../rdk-wifi-hal' since its DB lives in the cloned OneWifi cwd)
Exit: 1 iff a GATE class fired on a changed line (and ENFORCE); else 0. Always writes a
markdown summary to stdout. Identical file ships in OneWifi and the HAL.
"""
import json
import os
import re
import subprocess
import sys

BASE = os.environ.get("BASE", "").strip()
GATE = os.environ.get("GATE_WARNINGS", "").split()
ADVISORY = os.environ.get("ADVISORY_WARNINGS", "").split()
# Rollout toggle: when false, a GATE-class finding still renders (❌ "would fail")
# but the job is NOT failed (exit 0). Lets the mechanism run on real PRs as an
# advisory before it can red anyone. Default 'true' so a missing env stays strict
# (the gate's identity). The workflow sets it to 'false' during the advisory window.
ENFORCE = os.environ.get("ENFORCE", "true").strip().lower() not in ("false", "0", "no", "off", "")
# Where the changed files + git history live. '.' for OneWifi (DB is in its own cwd);
# '../rdk-wifi-hal' for the HAL (its DB is built in the cloned OneWifi cwd, cross-dir).
REPO_DIR = os.environ.get("REPO_DIR", ".").strip() or "."
DB = "compile_commands.json"

# Map each candidate -Wflag to its [-Wflag] diagnostic tag; classify a warning line by tag.
GATE_TAGS = {f"[{w}]" for w in GATE}
ADVISORY_TAGS = {f"[{w}]" for w in ADVISORY}
ALL_FLAGS = GATE + ADVISORY
# Demote every candidate to a warning so the recompile never errors out mid-file.
NO_ERROR = [f"-Wno-error={w[2:]}" for w in ALL_FLAGS]
LINE_RE = re.compile(r"\.(?:c|cpp):(\d+):")
TAG_RE = re.compile(r"\[-W[a-z0-9-]+\]")


def changed_files():
    out = subprocess.run(
        ["git", "-C", REPO_DIR, "diff", "--name-only", "--diff-filter=ACM", BASE, "HEAD", "--", "*.c", "*.cpp"],
        capture_output=True, text=True,
    ).stdout.splitlines()
    return [f for f in out if not f.startswith("build/") and "hostap" not in f]


def changed_lines(f):
    """New-side line numbers this PR changed in f (zero-context hunks)."""
    diff = subprocess.run(
        ["git", "-C", REPO_DIR, "diff", "-U0", "--diff-filter=ACM", BASE, "HEAD", "--", f],
        capture_output=True, text=True,
    ).stdout
    lines = set()
    for m in re.finditer(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@", diff, re.M):
        start = int(m.group(1))
        count = int(m.group(2)) if m.group(2) else 1
        lines.update(range(start, start + count))
    return lines


def db_args(db, f):
    """arguments for the DB entry whose file ends with /f, minus -c and -o <out>."""
    entry = next((e for e in db if e["file"].endswith("/" + f) or e["file"].endswith(f)), None)
    if not entry:
        return None
    out, skip = [], False
    for a in entry.get("arguments", []):
        if skip:
            skip = False
            continue
        if a == "-o":
            skip = True
            continue
        if a == "-c":
            continue
        out.append(a)
    return entry["directory"], out


def main():
    if not BASE or not os.path.exists(DB):
        print("### 🚦 gcc diff-gate: no compile DB or PR base — skipped")
        return 0
    db = json.load(open(DB))
    gated, advis = [], []
    for f in changed_files():
        info = db_args(db, f)
        if not info:
            continue  # not built (not in DB) -> can't judge, skip (same as clang-tidy)
        cwd, args = info
        want = changed_lines(f)
        if not want:
            continue
        cmd = args + ["-c", "-o", os.devnull] + ALL_FLAGS + NO_ERROR
        r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
        for line in r.stderr.splitlines():
            if ": warning:" not in line and ": error:" not in line:
                continue
            m = LINE_RE.search(line)
            t = TAG_RE.search(line)
            if not m or not t:
                continue
            if int(m.group(1)) not in want:
                continue
            tag = t.group(0)
            disp = re.sub(r"^.*?/(?:OneWifi|rdk-wifi-hal)/+", "", line)
            if tag in GATE_TAGS:
                gated.append(disp)
            elif tag in ADVISORY_TAGS:
                advis.append(disp)
    gated = sorted(set(gated))
    advis = sorted(set(advis))

    # GitHub annotations (top-of-check box).
    for l in gated[:10]:
        print(f"::error::{l}".replace("%", "%25").replace("\r", "%0D"), file=sys.stderr)
    for l in advis[:10]:
        print(f"::warning::{l}".replace("%", "%25").replace("\r", "%0D"), file=sys.stderr)

    if not gated and not advis:
        print("### 🚦 gcc diff-gate: clean on changed lines")
        return 0
    if gated:
        verb = "newly-introduced on changed lines" if ENFORCE else "would fail the job (advisory: ENFORCE=false)"
        print(f"### ❌ gcc diff-gate — {len(gated)} {verb}")
        print("```")
        print("\n".join(gated[:100]))
        print("```")
        print("_Fix the finding, or waive it inline with a `// NOLINT`-style guard / refactor._")
    if advis:
        print(f"### 🚦 gcc diff-gate advisory — {len(advis)} findings")
        print("```")
        print("\n".join(advis[:100]))
        print("```")
    # In advisory mode the ❌ block above still renders, but we never red the job.
    return 1 if (gated and ENFORCE) else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        # A malformed DB entry / KeyError / json error must not masquerade as a
        # gated finding (bare `exit 1` with an empty summary). Print a summary
        # line so the comment isn't blank, warn, dump the trace to stderr for
        # debugging, and exit 0. Same approach as the clang-tidy gate.
        import traceback
        print("### 🚦 gcc diff-gate: skipped (mechanism error) — failing open")
        print(f"::warning::gcc diff-gate mechanism error: {exc}", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        sys.exit(0)
