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
A PR can then fail on a class that fires on a line it changed. NB this is
line-scoped, not base-compared: a warning already present on a line the PR
edits for an unrelated reason also counts (accepted trade-off, not literally
"newly introduced").
The silent baseline (and the build-summary that relies on it) remains unaffected.

This is the gcc analogue of the clang-tidy changed-files gate already in makefile.yml.
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


def effective_base():
    """Diff base for line attribution — HEAD^1 when it is the trustworthy base.

    On a `pull_request` event checked out with no explicit `ref:` (as makefile.yml
    does), HEAD is the merge ref refs/pull/N/merge: HEAD^1 is the CURRENT base tip,
    HEAD^2 the PR head. The frozen event-payload BASE
    (github.event.pull_request.base.sha) can drift from that fresh base parent —
    most visibly on a re-run of an OLD workflow run, where the merge ref
    re-resolves to today's base but BASE stays pinned. A two-dot
    `git diff BASE HEAD` then attributes post-fork base-branch changes to the PR
    and can fire the gate on lines the author never touched (poisoning exactly the
    'zero false positives on GATE classes' evidence the ENFORCE rollout waits on).

    Prefer HEAD^1 when (a) HEAD is a merge commit (HEAD^2 exists) AND (b) the
    payload BASE is an ancestor of HEAD^1 (a fast-forward base advance — the normal
    case). Probe (b) makes the merge-ref parent-order assumption self-verifying: if
    HEAD is not a merge commit, or the base was rewritten so BASE no longer leads
    into HEAD^1, fall back to BASE (today's exact two-dot behavior). Never raises;
    worst case it returns BASE. The HAL leg runs this same file against
    REPO_DIR=../rdk-wifi-hal, which is likewise checked out with no `ref:` (the
    default merge ref) — so HEAD^1 is its current base too and the same path
    applies; the is-ancestor probe still guards the fork / base-rewrite cases.
    """
    def git_rc(*args):
        return subprocess.run(
            ["git", "-C", REPO_DIR, *args],
            capture_output=True, text=True,
        ).returncode
    if git_rc("rev-parse", "--verify", "--quiet", "HEAD^2") != 0:
        return BASE                               # not a merge ref -> can't trust HEAD^1
    if git_rc("merge-base", "--is-ancestor", BASE, "HEAD^1") != 0:
        return BASE                               # base rewritten / BASE unfetched -> stay with BASE
    return "HEAD^1"


def changed_files(base):
    # --diff-filter=ACM intentionally omits renames (R): line-scoping a renamed
    # path via `git diff -U0 -- <newpath>` (changed_lines below) can't pair the old
    # path (pathspec-limited), so git reports the file as wholly ADDED -> every
    # line counts as "changed" -> the gate would fire on moved-but-unedited code.
    # For an advisory line gate, skipping renamed files is a safe false-negative;
    # catching their real edits would need full rename-aware line mapping. (Kept
    # deliberately — a naive ACMR would make attribution worse, not better.)
    #
    # check=True: 'git diff' returns non-zero only on error (a bad/unfetched base),
    # never merely because a diff exists. Without it an unresolvable base yields
    # empty stdout and we'd report the PR "clean" instead of surfacing the
    # mechanism error. On failure the raise propagates to main()'s top-level
    # except, which prints the skip summary and fails open.
    out = subprocess.run(
        ["git", "-C", REPO_DIR, "diff", "--name-only", "--diff-filter=ACM", base, "HEAD", "--", "*.c", "*.cpp"],
        capture_output=True, text=True, check=True,
    ).stdout.splitlines()
    # Keep every changed tracked source; db_args() in main() already skips anything the
    # compile DB didn't build. `git diff` only ever returns TRACKED files, so generated
    # build outputs (.o, libs) never appear here -- the old `not startswith("build/")`
    # dropped nothing but the one tracked source under build/:
    # build/linux/compat/coverage_stubs.c, a first-party file the bpi makefile compiles
    # (makefile:478, real DB entry). Likewise the old bare `"hostap" not in f` dropped
    # first-party sources (the HAL's wifi_hal_hostapd.c, OneWifi's wifi_hostapd_glue.c)
    # while its intended target -- the vendored hostap tree -- lives in the sibling
    # rdk-wifi-libhostap/ clone a diff can't surface. Exclude only that vendored tree,
    # by its path prefix (anchored startswith: git diff paths are repo-relative and the
    # vendored tree sits at the repo root, so a first-party path merely *containing* the
    # name is never dropped; documented intent -- a diff never reaches it in practice).
    return [f for f in out if not f.startswith("rdk-wifi-libhostap/")]


def changed_lines(base, f):
    """New-side line numbers this PR changed in f (zero-context hunks)."""
    diff = subprocess.run(
        ["git", "-C", REPO_DIR, "diff", "-U0", "--diff-filter=ACM", base, "HEAD", "--", f],
        capture_output=True, text=True, check=True,
    ).stdout
    lines = set()
    for m in re.finditer(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@", diff, re.M):
        start = int(m.group(1))
        count = int(m.group(2)) if m.group(2) else 1
        lines.update(range(start, start + count))
    return lines


def db_args(db, f):
    """arguments for the DB entry whose file is f (exact) or ends with /f, minus -c and -o <out>."""
    # Match on a path boundary: exact relative path, or a suffix that begins at a '/'. A bare
    # endswith(f) would let a root-level 'foo.c' match an unrelated '/src/notfoo.c' (or 'x/foo.c'
    # match 'x/notfoo.c') -> next() recompiles the wrong TU and misattributes the gate result.
    entry = next((e for e in db if e["file"] == f or e["file"].endswith("/" + f)), None)
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
    base = effective_base()
    db = json.load(open(DB))
    gated, advis, failed = [], [], []
    for f in changed_files(base):
        info = db_args(db, f)
        if not info:
            continue  # not built (not in DB) -> can't judge, skip (same as clang-tidy)
        cwd, args = info
        want = changed_lines(base, f)
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
            # Strip to the LAST repo dir in the path token: the runner checks out to
            # .../work/OneWifi/OneWifi/easymesh_project/OneWifi/source/..., so a
            # non-greedy '.*?' would stop at the first 'OneWifi/' and leave a broken,
            # non-repo-relative path. '[^ ]*' stays within the path token (can't eat
            # into the message text) yet backtracks to the last match. Mirrors the
            # sed idiom in makefile.yml's build/tidy summaries.
            disp = re.sub(r"^[^ ]*/(?:OneWifi|rdk-wifi-hal)/+", "", line)
            if tag in GATE_TAGS:
                gated.append(disp)
            elif tag in ADVISORY_TAGS:
                advis.append(disp)
        if r.returncode != 0:
            # Every candidate class is demoted with -Wno-error=, so a well-formed
            # recompile of an already-built file exits 0. A nonzero code is a
            # MECHANISM failure, not a clean file: gcc aborts with "unrecognized
            # command-line option" for a clang-only/mistyped GATE/ADVISORY entry
            # (which would otherwise silently disable the gate for EVERY file), or
            # the file hit a missing generated header / a killed-or-OOM compiler.
            # Verified on gcc 13.3.0: these aborts print no source-line [-Wflag]
            # tag, so the loop above finds nothing and the file would otherwise be
            # reported "clean". Record it so the summary shows incomplete coverage
            # instead. Any findings parsed above this point still count.
            reason = next((ln.strip() for ln in r.stderr.splitlines()
                           if ": error:" in ln), f"compiler exit {r.returncode}")
            reason = re.sub(r"^[^ ]*/(?:OneWifi|rdk-wifi-hal)/+", "", reason)  # same path-strip as disp
            failed.append(f"{f}: {reason}")
    gated = sorted(set(gated))
    advis = sorted(set(advis))
    failed = sorted(set(failed))

    # GitHub annotations (top-of-check box).
    for l in gated[:10]:
        print(f"::error::{l}".replace("%", "%25").replace("\r", "%0D"), file=sys.stderr)
    for l in advis[:10]:
        print(f"::warning::{l}".replace("%", "%25").replace("\r", "%0D"), file=sys.stderr)
    for l in failed[:10]:
        print(f"::warning::gcc diff-gate could not recompile — {l}"
              .replace("%", "%25").replace("\r", "%0D"), file=sys.stderr)

    if not gated and not advis and not failed:
        print("### 🚦 gcc diff-gate: clean on changed lines")
        return 0
    if gated:
        verb = "on lines this PR changed" if ENFORCE else "would fail the job (advisory: ENFORCE=false)"
        print(f"### ❌ gcc diff-gate — {len(gated)} {verb}")
        print("```")
        print("\n".join(gated[:100]))
        print("```")
        print("_Fix the finding, or suppress it with a GCC diagnostic pragma where intentional / refactor._")
    if advis:
        print(f"### 🚦 gcc diff-gate advisory — {len(advis)} findings")
        print("```")
        print("\n".join(advis[:100]))
        print("```")
    if failed:
        print(f"### ⚠️ gcc diff-gate: {len(failed)} file(s) failed to recompile — coverage incomplete")
        print("```")
        print("\n".join(failed[:100]))
        print("```")
        print("_A nonzero compiler exit means these files were NOT analyzed (an unrecognized -W flag, "
              "a missing generated header, or a killed compiler) — the result above is partial. This is "
              "a mechanism warning, not a code finding, so it never reds the job on its own._")
    # In advisory mode the ❌ block above still renders, but we never red the job.
    # `failed` alone never fails the gate (fail-open) — only a GATE finding under ENFORCE does.
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
