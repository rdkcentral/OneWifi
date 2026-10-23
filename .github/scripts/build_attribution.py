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
"""Build failure attribution: did this PR break the build? Never fails the build itself.

When a leg's build step fails, say whether this PR caused it or whether an unpinned dependency
moved or develop was already broken, so the failure is actionable. Two tiers; any mechanism error
leaves an "attribution skipped" line and exits 0 (the build step already failed the job):

  Tier 1 (every leg), per error path: a sibling tree the PR cannot edit (rdk-wifi-hal,
  rdk-wifi-libhostap, unified-wifi-mesh, ...) -> environment; a OneWifi file the PR changed -> pr;
  anything else -> ambiguous. A PR that changed a header turns environment into ambiguous (a
  header edit can break a sibling that includes it). Link errors: pr when the symbol appears in
  the PR diff, else environment-likely.

  Tier 2 (only where a compile DB exists: the bpi leg) decides. It takes the failing objects from
  make's `*** [x.o] Error N` lines, not from gcc's error paths (in the drift case the error sits
  in a sibling header reached through a OneWifi .c), matches each to its compile DB entry by its
  -o argument, reverts the PR in the working tree (git apply -R of the PR diff) and recompiles
  each on base sources: still failing -> environment, compiling -> pr. The tree is restored
  afterwards (git apply forward, then a `git status` check); a mismatch is reported.

effective_base() and db_args() follow gcc_diff_gate.py's (this file also ships in the HAL on its
own): keep them in sync.

Env:
  BASE         PR base sha (github.event.pull_request.base.sha).
  HAVE_DB      'true' only on a leg that produced compile_commands.json (bpi). Tier 2 keys on this,
               never on the file existing: a stale DB on another leg would recompile with the
               wrong flags and give a confident wrong verdict.
  REPO_DIR     the repo the PR changes (default '.').
  ERRORS_FILE  normalized error lines from the build summary (default ci-out/build-errors.txt).
  BUILD_LOG    the make/compiler log (default build.log); tier 2 reads the failed targets there.
  OUT          markdown output (default ci-out/build-attribution.md), also printed to stdout.
Always exits 0.
"""
import json
import os
import re
import subprocess
import sys
import tempfile

BASE = os.environ.get("BASE", "").strip()
HAVE_DB = os.environ.get("HAVE_DB", "").strip().lower() in ("true", "1", "yes", "on")
REPO_DIR = os.environ.get("REPO_DIR", ".").strip() or "."
ERRORS_FILE = os.environ.get("ERRORS_FILE", "ci-out/build-errors.txt").strip()
BUILD_LOG = os.environ.get("BUILD_LOG", "build.log").strip()
OUT = os.environ.get("OUT", "ci-out/build-attribution.md").strip()
DB = "compile_commands.json"
HEADING = "#### 🧭 "
MAX_ROWS = 12

# Sibling trees the PR cannot edit, as the build summary's path normalization shows them:
# rdk-wifi-hal / rdk-wifi-libhostap head the path; the others (unified-wifi-mesh, halinterface,
# ...) keep the checkout-root prefix "OneWifi/easymesh_project/<tree>/".
SIBLING_PREFIXES = ("rdk-wifi-hal/", "rdk-wifi-libhostap/", "OneWifi/easymesh_project/")
MAKE_TARGET_RE = re.compile(r"\*\*\* \[(?:.*[:\s])?([^\s\]]+\.o)\] Error \d+")
UNDEF_REF_RE = re.compile(r"undefined reference to [`']([^`']+)'")
ERROR_PATH_RE = re.compile(r"^(\S+?):\d+(?::\d+)?: (?:error|fatal error):")
SHOWN_RE = re.compile(r"^\S*/(OneWifi|rdk-wifi-hal|rdk-wifi-libhostap)/+")


def run_git(args):
    """git in REPO_DIR; one seam so tests can stub every git call."""
    return subprocess.run(["git", "-C", REPO_DIR, *args], capture_output=True, text=True,
                          errors="replace")


def run_cmd(cmd, cwd):
    """One recompile; a seam so tests can drive the result without a compiler."""
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, errors="replace")


def effective_base():
    """HEAD^1 on a merge ref whose first parent BASE leads into, else BASE (as gcc_diff_gate.py)."""
    if run_git(["rev-parse", "--verify", "--quiet", "HEAD^2"]).returncode != 0:
        return BASE
    if run_git(["merge-base", "--is-ancestor", BASE, "HEAD^1"]).returncode != 0:
        return BASE
    return "HEAD^1"


def db_args(db, path):
    """(directory, arguments minus -c and -o <out>) of the DB entry for path, or None.

    Path-boundary match, as gcc_diff_gate.py: a root-level 'foo.c' never matches '/src/notfoo.c'."""
    entry = next((item for item in db if item["file"] == path or item["file"].endswith("/" + path)),
                 None)
    if not entry:
        return None
    out, skip = [], False
    for arg in entry.get("arguments", []):
        if skip:
            skip = False
        elif arg == "-o":
            skip = True
        elif arg != "-c":
            out.append(arg)
    return entry["directory"], out


def entry_for_object(db, obj):
    """The DB entry whose -o output is obj (path boundary). make names failed targets
    (`source/foo.o`), not sources, so this matches the -o argument, not entry['file']."""
    for item in db:
        args = item.get("arguments", [])
        outputs = [args[idx + 1] for idx in range(len(args) - 1) if args[idx] == "-o"]
        if any(out == obj or out.endswith("/" + obj) for out in outputs):
            return item
    return None


def judge_tu(cwd, args, source):
    """Verdict for one failing file, with the PR reverted. Gone after the revert: the PR added
    (or renamed) it -> pr. Otherwise recompile: still failing -> environment, compiling -> pr."""
    src = source if os.path.isabs(source) else os.path.join(cwd, source)
    if not os.path.exists(src):
        return "pr"
    return "environment" if run_cmd(args + ["-c", "-o", os.devnull], cwd).returncode else "pr"


def read_text(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return ""


def classify_path(path, changed, header_changed):
    """One error path -> 'pr' | 'environment' | 'ambiguous' (tier 1).

    changed holds repo-relative paths (`git diff --name-only`); a OneWifi display path is
    `OneWifi/<path>`, and a sibling's starts `OneWifi/easymesh_project/`."""
    rel = path[len("OneWifi/"):] if path.startswith("OneWifi/") else None
    if rel is not None and not rel.startswith("easymesh_project/") and rel in changed:
        return "pr"
    if path.startswith(SIBLING_PREFIXES) or not path.startswith("OneWifi/"):
        return "ambiguous" if header_changed else "environment"
    return "ambiguous"   # a OneWifi file the PR did not change


def unique(items):
    return list(dict.fromkeys(items))


def tier1(err_lines, changed, header_changed, diff_text):
    """[(path or symbol, class)] for each distinct error path and undefined symbol."""
    paths = unique(hit.group(1) for hit in map(ERROR_PATH_RE.match, err_lines) if hit)
    rows = [(path, classify_path(path, changed, header_changed)) for path in paths]
    for sym in unique(hit.group(1) for hit in map(UNDEF_REF_RE.search, err_lines) if hit):
        found = re.search(r"\b" + re.escape(sym) + r"\b", diff_text)
        rows.append((f"undefined reference: {sym}", "pr" if found else "environment-likely"))
    return rows


def parse_make_targets(log_text):
    """The .o targets make reported as failed, first seen first (not `[all] Error N` lines).
    Tolerates GNU make 4's `[makefile:line: target]` form."""
    return unique(hit.group(1) for hit in MAKE_TARGET_RE.finditer(log_text))


def recompile_on_base(db, targets, diff_base):
    """Tier 2: ({target: 'pr' | 'environment' | 'unknown'}, note). Reverts the PR diff, judges
    each failing file, re-applies the diff and checks the tree matches what it was before."""
    verdicts, resolved = {}, []
    for target in targets:
        entry = entry_for_object(db, target)
        info = db_args(db, entry["file"]) if entry else None
        if info:
            resolved.append((target, *info, entry["file"]))
        else:
            verdicts[target] = "unknown"   # not in the compile DB: cannot judge it
    if not resolved:
        return verdicts, "no failing file matched the compile DB"
    snapshot = run_git(["status", "--porcelain"]).stdout
    patch = run_git(["diff", "--binary", diff_base, "HEAD"]).stdout
    if not patch.strip():
        return verdicts, "empty PR diff, nothing to revert"
    fd, patch_path = tempfile.mkstemp(suffix=".patch", dir=os.environ.get("RUNNER_TEMP") or None)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(patch)
        if run_git(["apply", "-R", patch_path]).returncode != 0:
            return verdicts, "could not revert the PR diff (git apply -R failed), tier 2 skipped"
        try:
            for target, cwd, args, source in resolved:
                verdicts[target] = judge_tu(cwd, args, source)
        finally:
            restored = (run_git(["apply", patch_path]).returncode == 0
                        and run_git(["status", "--porcelain"]).stdout == snapshot)
    finally:
        os.unlink(patch_path)
    return verdicts, "" if restored else "WARNING: the PR tree was not cleanly restored after tier 2"


def shown(path):
    """A path as the build summary shows it: from the repo directory on, without '//'."""
    return re.sub(r"/{2,}", "/", SHOWN_RE.sub(r"\1/", path))


def trees_of(rows):
    trees = set()
    for path, _cls in rows:
        if path.startswith(("rdk-wifi-hal/", "rdk-wifi-libhostap/")):
            trees.add(path.split("/")[0])
        elif path.startswith("OneWifi/easymesh_project/"):
            trees.add(path.split("/")[2])   # e.g. unified-wifi-mesh
        elif path.startswith("OneWifi/"):
            trees.add("OneWifi")
    return trees


def render(rows, verdicts, note, trees):
    """(markdown block under a #### heading, one-line notice)."""
    env_tus = sorted(target for target, verdict in verdicts.items() if verdict == "environment")
    pr_tus = sorted(target for target, verdict in verdicts.items() if verdict == "pr")
    unknown = sum(verdict == "unknown" for verdict in verdicts.values())
    if env_tus and not pr_tus and not note.startswith("WARNING"):
        caveat = f" ({unknown} not in the compile DB, not judged)" if unknown else ""
        md = [f"{HEADING}Not caused by this PR",
              f"{len(env_tus)} failing file(s) fail on the PR base too{caveat}: a dependency moved "
              "or develop was already broken.",
              f"Trees: {', '.join(sorted(trees)) or 'the failing tree(s)'}. Check whether develop "
              "is red or an unpinned input moved (unified-wifi-mesh, rdk-wifi-hal, halinterface, "
              "trower-base64): that needs a pin bump or an upstream fix, not a change to this PR."]
        return md, "Red build not caused by this PR: the failing files fail on the PR base too."
    if pr_tus and not env_tus:
        # A partial revert can only leave PR content in place, which still fails (environment),
        # so it cannot make up this verdict; a restore WARNING is shown, not held against it.
        md = [f"{HEADING}Caused by this PR",
              f"The errors in {', '.join(map(shown, pr_tus))} go away when this PR's changes are "
              "reverted."]
        if note:
            md.append(f"_{note}_")
        return md, "Red build caused by this PR: the errors go away when it is reverted."
    md = [f"{HEADING}Build failure: cause unclear",
          "Mixed results, no compile DB on this leg, or the check could not run."]
    if note:
        md.append(f"_{note}_")
    if rows:
        md += ["", "Per error path (a guess from the path alone):"]
        md += [f"- `{path}`: {cls}" for path, cls in rows[:MAX_ROWS]]
    return md, "Red build: cause unclear."


def main():
    if not BASE:
        return 0
    diff_base = effective_base()
    err_lines = read_text(ERRORS_FILE).splitlines()
    diff = run_git(["diff", "--name-only", diff_base, "HEAD"])
    changed = set(diff.stdout.splitlines()) if diff.returncode == 0 else set()
    header_changed = any(path.endswith((".h", ".hpp", ".hh")) for path in changed)
    rows = tier1(err_lines, changed, header_changed, run_git(["diff", diff_base, "HEAD"]).stdout)
    verdicts, note = {}, ""
    if HAVE_DB and os.path.exists(DB):
        try:
            with open(DB, encoding="utf-8") as fh:
                db = json.load(fh)
            verdicts, note = recompile_on_base(db, parse_make_targets(read_text(BUILD_LOG)), diff_base)
        except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
            note = f"tier 2 skipped (mechanism error: {exc})"
    md, notice = render(rows, verdicts, note, trees_of(rows))
    text = "\n".join(md) + "\n"
    try:
        os.makedirs(os.path.dirname(OUT) or ".", exist_ok=True)
        with open(OUT, "w", encoding="utf-8") as fh:
            fh.write(text)
    except OSError as exc:
        print(f"::warning::build attribution could not write {OUT}: {exc}", file=sys.stderr)
    print(f"::notice::{notice}", file=sys.stderr)
    print(text, end="")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:   # never fail the build over attribution
        print(f"{HEADING}Build failure attribution skipped (mechanism error)")
        print(f"::warning::build attribution mechanism error: {exc}", file=sys.stderr)
        sys.exit(0)
