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
warnings enabled (non-fatal: the DB's own -Werror=<class> promotions are stripped and -Os is
applied when OPT is set — see recompile_cmd), then keep only findings whose line the PR changed.
A PR can then fail on a class that fires on a line it changed, unless the finding was already
in the file before the PR: the base version of each changed file is compiled the same way, and a
finding whose tag and message the base already had at least as often is not counted (see
base_findings / preexisting). An edited line that calls a function the file already called
without a prototype therefore stays quiet; a new undeclared function does not. Limits: the base
is compiled against the PR's headers (a PR that removes a prototype from a header is not
flagged); a file the PR adds, or whose base gcc cannot finish, is judged line-scoped only (the
summary names the latter); a PR that fixes one finding and adds another with the same message
(no identifier in it, e.g. "control reaches end of non-void function") is not flagged; and a
message naming something the PR renamed, or an argument position the PR shifted, looks new.
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
  OPT                optimization level for the recompile only (e.g. '-Os' to match
                     production and wake middle-end warnings). Empty -> keep the DB's -O.
  REPO_DIR           dir the changed files + git history live in (default '.'; the HAL sets
                     this to '../rdk-wifi-hal' since its DB lives in the cloned OneWifi cwd)
  INLINE_JSON        optional path; when set, also write a review_poster.py candidate
                     envelope (source 'gcc-gate') of the gate/advisory findings so they can
                     be posted as inline PR review comments (Commit 5). Empty/unset -> no file.
Exit: 1 iff a GATE class fired on a changed line (and ENFORCE); else 0. Always writes a
markdown summary to stdout. Identical file ships in OneWifi and the HAL — the INLINE_JSON
support must be re-ported verbatim when this file is synced to the HAL.
"""
import bisect
import collections
import contextlib
import json
import os
import re
import subprocess
import sys

BASE = os.environ.get("BASE", "").strip()
GATE = os.environ.get("GATE_WARNINGS", "").split()
ADVISORY = os.environ.get("ADVISORY_WARNINGS", "").split()
# Rollout toggle: when false, a GATE-class finding still renders (the same ❌ error
# block as when enforced) but the job is NOT failed (exit 0). Lets the mechanism run on real PRs as an
# advisory before it can red anyone. Default 'true' so a missing env stays strict
# (the gate's identity). The workflow sets it to 'false' during the advisory window.
ENFORCE = os.environ.get("ENFORCE", "true").strip().lower() not in ("false", "0", "no", "off", "")
# Where the changed files + git history live. '.' for OneWifi (DB is in its own cwd);
# '../rdk-wifi-hal' for the HAL (its DB is built in the cloned OneWifi cwd, cross-dir).
REPO_DIR = os.environ.get("REPO_DIR", ".").strip() or "."
DB = "compile_commands.json"
# Optimization level for the RECOMPILE ONLY (not the real build). Production bpi/rpi
# compile at -Os, but CI's compile DB is -O0, so every middle-end (post-optimization)
# warning is dormant: -Wstringop-*, -Warray-bounds, -Wmaybe-uninitialized, -Wdangling-
# pointer, -Wuse-after-free. Setting OPT=-Os in the workflow wakes them on the changed
# files at production's exact level, without touching the build product or the silent
# baseline the build-summary relies on. Empty (the default) keeps the DB's own -O.
OPT = os.environ.get("OPT", "").strip()
# Compilers for the recompile (head and base alike, so their findings compare), e.g. 'gcc-14' /
# 'g++-14'. Empty keeps the compile DB's own compiler. Set them together with any list entry
# that only gcc 14 knows (-Wreturn-mismatch, -Wdeclaration-missing-parameter-type,
# -Wcalloc-transposed-args): gcc 13 rejects those, and every file would fail to recompile.
GATE_CC = os.environ.get("GATE_CC", "").strip()
GATE_CXX = os.environ.get("GATE_CXX", "").strip()
# Ubuntu's gcc defines _FORTIFY_SOURCE when optimizing: an overflowing memcpy/strcpy then warns
# inside string_fortified.h, a header line no changed-line filter matches. Undefined, the same
# overflow is reported on the .c call line ([-Wstringop-overflow=] / [-Warray-bounds=]).
NO_FORTIFY = ["-U_FORTIFY_SOURCE"]
# When set, write inline-review candidates here (Commit 5). Same envelope
# review_poster.py reads; source 'gcc-gate' gives it top posting priority.
INLINE_JSON = os.environ.get("INLINE_JSON", "").strip()

# Map each candidate -Wflag to its [-Wflag] diagnostic tag; classify a warning line by tag.
GATE_TAGS = {f"[{w}]" for w in GATE}
ADVISORY_TAGS = {f"[{w}]" for w in ADVISORY}
ALL_FLAGS = GATE + ADVISORY
# C++ TU extensions. gcc rejects a few -W flags for C++ ("valid for C/ObjC but not for
# C++") — harmless (g++ warns and continues, exit 0) but noisy; drop them on C++ TUs.
CXX_EXT = (".cpp", ".cc", ".cxx")
# Flags gcc accepts for C only. Kept explicit (not probed) so a reader sees which
# classes protect C sources; verified on gcc 13.3.0 and g++ 14.2.0.
C_ONLY = {
    "-Wint-conversion", "-Wimplicit-function-declaration", "-Wimplicit-int",
    "-Wincompatible-pointer-types", "-Wpointer-sign", "-Wdiscarded-qualifiers",
    "-Wreturn-mismatch", "-Wdeclaration-missing-parameter-type",
    "-Wjump-misses-init",
}
LINE_RE = re.compile(r"\.(?:c|cc|cpp|cxx):(\d+):")
# A finding's message and tag (the key matched between the base and head compiles; line numbers
# shift). gcc tags a warning that takes a level with a trailing '=' ([-Warray-bounds=],
# [-Wdangling-pointer=], [-Wstringop-overflow=]); 'tag' is the bare flag name.
KEY_RE = re.compile(r": (?:warning|error): (?P<msg>.*) \[(?P<tag>-W[a-z0-9-]+)=?\]$")
# gcc's spelling hint changes when a PR adds a similar name; not part of the finding.
HINT_RE = re.compile(r"; did you mean [‘'][^’']*[’']\?")
# Parse a normalized `disp` line (path already stripped) into inline-comment fields.
INLINE_RE = re.compile(r"^(?P<path>[^:]+):(?P<line>\d+):\d+: warning: (?P<msg>.*) \[(?P<tag>-W[a-z0-9-]+)=?\]$")


def write_inline(status, comments, dropped=0):
    """Write the review_poster.py candidate envelope to INLINE_JSON (no-op if unset).

    status 'skipped' (no DB/BASE, or a mechanism error) writes an empty comment
    list and 'partial' (a changed file failed to recompile) keeps the findings it
    has; the poster reads either as "incomplete" and so disables stale-comment
    deletion for the slot — never as "all clean, delete everything" (fail-open).
    A never-raising best-effort write: a failure here must not red the gate.
    """
    if not INLINE_JSON:
        return
    try:
        out_dir = os.path.dirname(INLINE_JSON)
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
        with open(INLINE_JSON, "w") as fh:
            json.dump({"source": "gcc-gate", "status": status,
                       "dropped": dropped, "comments": comments}, fh)
    except Exception as exc:  # pragma: no cover - best-effort I/O
        print(f"::warning::gcc diff-gate could not write INLINE_JSON {INLINE_JSON}: {exc}",
              file=sys.stderr)


def build_inline(gated, advis):
    """Turn the deduped gate/advisory display lines into inline candidates.

    One comment per (path, line, tag, msg): gcc repeats a finding at several
    columns on macro expansion, so dedupe on those four fields (dropping the
    column); deduping here keeps the counts honest (the poster also drops exact
    repeats). A line that does not parse is counted as 'dropped' (surfaced in the
    poster's summary), never silently lost.
    """
    inline, seen, dropped = [], set(), 0
    for sev, icon, lst in (("error", "❌", gated), ("warning", "❗", advis)):
        for disp in lst:
            hit = INLINE_RE.match(disp)
            if not hit:
                dropped += 1
                continue
            key = (hit["path"], int(hit["line"]), hit["tag"], hit["msg"])
            if key in seen:
                continue
            seen.add(key)
            inline.append({
                "path": hit["path"],
                "line": int(hit["line"]),
                "side": "RIGHT",
                "body": f"{icon} **gcc** `{hit['tag']}` ({sev}) — {hit['msg']}",
            })
    return inline, dropped


def recompile_cmd(args, path):
    """The per-file recompile command for one changed TU.

    `args` is the DB command already minus -c/-o (from db_args). This recompile only
    COLLECTS warnings, so no diagnostic may abort it. Two mechanisms are needed:

      * STRIP every -Werror* token from args. The DB carries per-class -Werror=<class>
        promotions (incl. the HAL's -Werror=maybe-uninitialized / -array-bounds that -Os newly
        trips). A bare -Wno-error does NOT undo a per-class -Werror=<class> (verified
        gcc 13.3.0: `-Werror=return-type -Wno-error` still errors), so drop them outright.
      * KEEP a per-class -Wno-error=<class> for every candidate. On gcc-14 the classes
        int-conversion / implicit-function-declaration / implicit-int /
        incompatible-pointer-types are errors BY DEFAULT (no -Werror= involved), so the
        strip above does not cover them — the explicit -Wno-error= does.

    A genuine error (missing header, killed compiler) is not a -Werror promotion and
    still exits nonzero -> the caller's failed[] path. -Os is added when OPT is set;
    the C-only flags are dropped for C++ TUs (g++ rejects them); GATE_CC / GATE_CXX
    replace the DB's compiler (args[0]); _FORTIFY_SOURCE is undefined (NO_FORTIFY).
    """
    is_cxx = path.endswith(CXX_EXT)
    flags = [flag for flag in ALL_FLAGS if not (is_cxx and flag in C_ONLY)]
    no_error = [f"-Wno-error={flag[2:]}" for flag in flags]
    opt = [OPT] if OPT else []
    compiler = (GATE_CXX if is_cxx else GATE_CC) or args[0]
    kept = [compiler] + [arg for arg in args[1:] if not arg.startswith("-Werror")]
    return kept + opt + NO_FORTIFY + ["-c", "-o", os.devnull] + flags + no_error


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
    """New-side line ranges this PR changed in f (zero-context hunks).

    Returns a list of (start, end) inclusive intervals instead of a per-line
    set, so memory is bounded by hunk count, not total changed-line count.
    """
    diff = subprocess.run(
        ["git", "-C", REPO_DIR, "diff", "-U0", "--diff-filter=ACM", base, "HEAD", "--", f],
        capture_output=True, text=True, check=True,
    ).stdout
    intervals = []
    for m in re.finditer(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@", diff, re.M):
        start = int(m.group(1))
        count = int(m.group(2)) if m.group(2) else 1
        if count > 0:
            intervals.append((start, start + count - 1))
    intervals.sort()  # git emits hunks in order; sorted is what _in_intervals relies on
    return intervals


def _in_intervals(line, intervals):
    """True if line is inside one of the sorted, non-overlapping (start, end) intervals.

    Binary search (O(log hunks) per diagnostic), so a fragmented diff with many
    warnings does not cost O(hunks x diagnostics).
    """
    i = bisect.bisect_right(intervals, (line, float("inf"))) - 1
    return i >= 0 and intervals[i][0] <= line <= intervals[i][1]


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


def finding(line):
    """(line number, (tag, message)) of a tagged diagnostic in a .c/.cpp file, else None."""
    num = LINE_RE.search(line)
    hit = KEY_RE.search(line)
    if not num or not hit:
        return None
    return int(num.group(1)), (hit["tag"], HINT_RE.sub("", hit["msg"]))


def base_findings(base, name, cwd, args):
    """(findings of `name` as it was at base, problem). findings None -> judge line-scoped only.

    The base text is written next to the source (same directory and extension, so quoted
    includes and the C/C++ split behave the same) and compiled like the head, against the
    PR's headers. A base with ordinary errors (a struct member the PR renamed) still reports
    every front-end class, so its findings are kept. Only a compile gcc stopped early
    ("compilation terminated.", e.g. a header the PR removed), a killed compiler or a temp-file
    failure leaves no base; `problem` then says why, for the summary. A file the PR adds has
    no base and no problem.
    """
    show = subprocess.run(["git", "-C", REPO_DIR, "show", f"{base}:{name}"], capture_output=True)
    if show.returncode != 0:
        return None, None
    src = next((arg for arg in reversed(args) if arg == name or arg.endswith("/" + name)), None)
    if src is None:
        return None, "not found in its compile command"
    path = os.path.join(cwd, src)
    tmp = os.path.join(os.path.dirname(path), ".gcc-gate-base-" + os.path.basename(path))
    try:
        with open(tmp, "wb") as fh:
            fh.write(show.stdout)
        cmd = recompile_cmd([tmp if arg == src else arg for arg in args], name)
        proc = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, errors="replace")
    except OSError as exc:
        return None, f"could not be compiled ({exc.strerror or exc})"
    finally:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
    if proc.returncode < 0 or "compilation terminated." in proc.stderr:
        return None, "stopped compiling early"
    return [hit for hit in map(finding, proc.stderr.splitlines()) if hit], None


def preexisting(head, base):
    """Keys the PR did not add: the head file has no more findings with the key than the base had.

    Counted per distinct (line, key), so one finding repeated at several columns counts once.
    Coarse on purpose: a key the PR adds one more of (a second VLA named 'buf') counts all of
    its changed-line findings, since which one is new cannot be told apart.
    """
    if base is None:
        return set()
    head_n = collections.Counter(key for _line, key in set(head))
    base_n = collections.Counter(key for _line, key in set(base))
    return {key for key, count in head_n.items() if count <= base_n[key]}


def main():
    if not BASE or not os.path.exists(DB):
        print("#### 🚦 gcc diff-gate: no compile DB or PR base — skipped")
        write_inline("skipped", [])
        return 0
    base = effective_base()
    db = json.load(open(DB))
    gated, advis, failed = [], [], []
    known = []     # changed-line findings the file already had before the PR (not counted)
    unjudged = []  # files whose base could not be compiled (judged on changed lines only)
    for f in changed_files(base):
        info = db_args(db, f)
        if not info:
            continue  # not built (not in DB) -> can't judge, skip (same as clang-tidy)
        cwd, args = info
        want = changed_lines(base, f)
        if not want:
            continue
        cmd = recompile_cmd(args, f)
        r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, errors="replace")
        hits = [(hit, line) for line in r.stderr.splitlines() if (hit := finding(line))]
        tags = GATE_TAGS | ADVISORY_TAGS
        mine = [(hit, line) for hit, line in hits if _in_intervals(hit[0], want) and f"[{hit[1][0]}]" in tags]
        old = set()
        if mine:  # compile the base only when there is something to compare
            base_hits, problem = base_findings(base, f, cwd, args)
            if problem:
                unjudged.append(f"`{f}`: its base {problem}")
            old = preexisting([hit for hit, _line in hits], base_hits)
        for (_lineno, key), line in mine:
            tag = f"[{key[0]}]"
            # Strip to the LAST repo dir in the path token: the runner checks out to
            # .../work/OneWifi/OneWifi/easymesh_project/OneWifi/source/..., so a
            # non-greedy '.*?' would stop at the first 'OneWifi/' and leave a broken,
            # non-repo-relative path. '[^ ]*' stays within the path token (can't eat
            # into the message text) yet backtracks to the last match. Mirrors the
            # sed idiom in makefile.yml's build/tidy summaries.
            disp = re.sub(r"^[^ ]*/(?:OneWifi|rdk-wifi-hal)/+", "", line)
            if key in old:
                known.append(disp)
            elif tag in GATE_TAGS:
                gated.append(disp)
            elif tag in ADVISORY_TAGS:
                advis.append(disp)
        if r.returncode != 0:
            # Every -Werror promotion is stripped from the DB args and each candidate
            # class is also demoted with -Wno-error=, so a well-formed recompile of an
            # already-built file exits 0. A nonzero code is a
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

    # Inline-review candidates (Commit 5). Written on every non-skip path — including
    # the clean case (empty list) so the poster removes any now-stale gcc comments.
    # 'partial' when a file failed to recompile or a finding could not be converted:
    # the set is incomplete, so the poster must not delete comments as if fixed.
    inline, inline_dropped = build_inline(gated, advis)
    write_inline("partial" if failed or inline_dropped else "ok", inline, inline_dropped)

    # GitHub annotations (top-of-check box).
    for l in gated[:10]:
        print(f"::error::{l}".replace("%", "%25").replace("\r", "%0D"), file=sys.stderr)
    for l in advis[:10]:
        print(f"::warning::{l}".replace("%", "%25").replace("\r", "%0D"), file=sys.stderr)
    for l in failed[:10]:
        print(f"::warning::gcc diff-gate could not recompile — {l}"
              .replace("%", "%25").replace("\r", "%0D"), file=sys.stderr)

    # Maintainer overview only: never inline, never gated. The dropped findings themselves go
    # to the job log, where the ENFORCE rollout can check them.
    known = sorted(set(known))
    for shown in known:
        print(f"gcc diff-gate: already in the file before this PR: {shown}", file=sys.stderr)
    notes = []
    if known:
        notes.append(f"_{len(known)} finding(s) on edited lines were already in the file before "
                     "this PR; not counted (listed in the job log)._")
    if unjudged:
        notes.append("_Judged on changed lines only, without comparing to the file before this PR: "
                     + "; ".join(unjudged[:10]) + "._")
    note = "\n".join(notes)
    if not gated and not advis and not failed:
        print("#### 🚦 gcc diff-gate: clean on changed lines")
        if note:
            print(note)
        return 0
    if gated:
        # Same wording with ENFORCE on or off: these are real errors in changed code,
        # whether or not the job is red for them yet.
        print(f"#### ❌ gcc diff-gate — {len(gated)} error(s) on lines this PR changed")
        print("```")
        print("\n".join(gated[:100]))
        print("```")
        print("_Fix the finding, or suppress it with a GCC diagnostic pragma where intentional / refactor._")
    if advis:
        print(f"#### ❗ gcc diff-gate warnings — {len(advis)} on changed lines")
        print("```")
        print("\n".join(advis[:100]))
        print("```")
    if failed:
        print(f"#### ⚠️ gcc diff-gate: {len(failed)} file(s) failed to recompile — coverage incomplete")
        print("```")
        print("\n".join(failed[:100]))
        print("```")
        print("_A nonzero compiler exit means these files were NOT analyzed (an unrecognized -W flag, "
              "a missing generated header, or a killed compiler) — the result above is partial._")
    if note:
        print(note)
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
        print("#### 🚦 gcc diff-gate: skipped (mechanism error) — failing open")
        print(f"::warning::gcc diff-gate mechanism error: {exc}", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        # A mechanism error must not read as "all clean" to the poster either.
        write_inline("skipped", [])
        sys.exit(0)
