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
"""Source-coverage nudge on the files a PR adds; never fails the build.

OneWifi has two hand-maintained build descriptions: the autotools tree (`configure.ac` and the
`Makefile.am` files, `*_SOURCES = ...`) and the standalone `build/linux/{bpi,rpi}/makefile` that
CI and the bpi/rpi yocto recipes compile. They drift, and the drift that bites is a source that
autotools builds but no CI leg compiles: CI stays green while never compiling the file.

This flags exactly that for the files a PR ADDS: a `.c/.cpp/.cc` in some `*_SOURCES` but in
neither leg's compile list, in a directory a leg already compiles from (a new file in a directory
no leg compiles is a platform area, left alone). It is textual: the OneWifi sources are listed
explicitly in both leg makefiles (no wildcard covers `source/`), so no build is needed. It cannot
tell an intentional platform exclusion (XB-only, feature-gated) from a forgotten entry, so it
only reports: a `::warning` per file and a summary section in OUT.

Usage:  source_coverage.py <added-files.txt>   (the PR's added paths, one per line)
Env:    REPO_ROOT ('.'), OUT ('ci-out/source-coverage.md', written only on a finding).
"""

import os
import re
import subprocess
import sys

TOP_SRCDIR = "$(top_srcdir)/"
SRC_EXT = (".c", ".cpp", ".cc")

# OneWifi's own sources in the leg makefiles are ALWAYS $(ONE_WIFI_HOME)/source|lib/…
# (verified: 64 such .c per leg, no wildcard under source/). Requiring that exact
# prefix ignores sibling-repo trees ($(WIFI_CCSP_COMMON_LIB)/source/…, hostap, HAL)
# whose paths would otherwise collide on a bare `source/…` suffix.
LEG_SRC_RE = re.compile(
    r"\$\(ONE_WIFI_HOME\)/((?:source|lib)/[A-Za-z0-9_./-]+\.(?:c|cpp|cc))\b"
)
SOURCES_RE = re.compile(r"^\s*[A-Za-z0-9_]+_SOURCES\s*\+?=(.*)$")


def _read(path):
    with open(path, encoding="utf-8", errors="replace") as fh:
        return fh.read()


def _join_continuations(text):
    """Fold Make/automake line continuations (`\\` at EOL) into single lines."""
    return re.sub(r"\\\n", " ", text)


def normalize_am_token(tok, am_dir):
    """A Makefile.am _SOURCES token → repo-relative source path, or None.

    Handles `$(top_srcdir)/source/db/wifi_db.c` (→ source/db/wifi_db.c) and a bare
    `wifi_mgr.c` (→ <am_dir>/wifi_mgr.c). Tokens with any other unresolved make
    variable or automake substitution are skipped (can't place them textually)."""
    if tok.startswith(TOP_SRCDIR):
        tok = tok[len(TOP_SRCDIR):]
    if "$(" in tok or "@" in tok:
        return None
    if not tok.endswith(SRC_EXT):
        return None
    if "/" in tok:
        return os.path.normpath(tok)
    return os.path.normpath(os.path.join(am_dir, tok))


def parse_makefile_am_sources(root, am_paths):
    """Set of repo-relative .c/.cpp/.cc paths named in any *_SOURCES across the
    given Makefile.am files. Automake conditionals (`if X`) are intentionally
    ignored: a file under any conditional is still a source autotools knows."""
    srcs = set()
    for am in am_paths:
        am_dir = os.path.dirname(am)
        text = _join_continuations(_read(os.path.join(root, am)))
        for line in text.splitlines():
            match = SOURCES_RE.match(line)
            if not match:
                continue
            for tok in match.group(1).split():
                path = normalize_am_token(tok, am_dir)
                if path:
                    srcs.add(path)
    return srcs


def parse_leg_compiled(root, mk_paths):
    """Set of repo-relative OneWifi .c/.cpp/.cc paths compiled by the given
    build/linux leg makefiles (only $(ONE_WIFI_HOME)/source|lib/… entries)."""
    compiled = set()
    for mk in mk_paths:
        full = os.path.join(root, mk)
        if not os.path.isfile(full):
            continue
        for match in LEG_SRC_RE.finditer(_read(full)):
            compiled.add(os.path.normpath(match.group(1)))
    return compiled


def find_am_files(root):
    """Repo-relative paths of every Makefile.am under root.

    Prefer `git ls-files` (TRACKED files only): on the runner `make setup` clones
    dependencies (unified-wifi-mesh, submodules, …) INTO the tree, and their
    Makefile.am must not leak into the source set — same reasoning as the tidy
    step's `^rdk-wifi-libhostap/` skip. Fall back to an os.walk for a non-git tree
    (the unit-test tmp dirs)."""
    try:
        res = subprocess.run(
            ["git", "-C", root, "ls-files", "-z"],
            capture_output=True, text=True, check=True, timeout=30,
        )
        return [path for path in res.stdout.split("\0")
                if path and os.path.basename(path) == "Makefile.am"]
    except (OSError, subprocess.SubprocessError):
        walked = []
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [name for name in dirnames if name != ".git"]
            if "Makefile.am" in filenames:
                walked.append(os.path.relpath(
                    os.path.join(dirpath, "Makefile.am"), root))
        return walked


def find_drift(added, am_set, leg_set):
    """PR-added sources that autotools lists but no leg compiles, restricted to
    directories a leg already compiles from (see the module docstring). Sorted."""
    leg_dirs = {os.path.dirname(path) for path in leg_set}
    out = []
    for raw in added:
        path = os.path.normpath(raw.strip()) if raw.strip() else ""
        if not path.endswith(SRC_EXT):
            continue
        if path in am_set and path not in leg_set and os.path.dirname(path) in leg_dirs:
            out.append(path)
    return sorted(set(out))


def render_md(findings):
    """The summary section (its own ### heading), or '' when clean."""
    if not findings:
        return ""
    lines = [
        "### 🧭 Source coverage",
        "",
        "❗ This PR adds source file(s) that a `Makefile.am` builds but neither the **bpi** "
        "nor the **rpi** leg compiles, so CI never compiles them. Add each to "
        "`build/linux/bpi/makefile` (and `rpi/makefile`), unless it is platform-specific "
        "(XB-only, feature-gated).",
        "",
    ]
    lines += [f"- `{path}`" for path in findings]
    lines.append("")
    return "\n".join(lines)


def main(argv):
    root = os.environ.get("REPO_ROOT", ".")
    out_path = os.environ.get("OUT", "ci-out/source-coverage.md")
    added = []
    if len(argv) > 1 and argv[1]:
        try:
            added = _read(argv[1]).splitlines()
        except OSError:
            added = []

    am_set = parse_makefile_am_sources(root, find_am_files(root))
    leg_set = parse_leg_compiled(
        root, ["build/linux/bpi/makefile", "build/linux/rpi/makefile"]
    )
    findings = find_drift(added, am_set, leg_set)

    if not findings:
        print("source-coverage: OK — every added source that autotools lists is "
              "compiled by a CI leg (or is not a tracked source).")
        return 0

    # Check annotations point at the file in the Files tab without adding review threads.
    for path in findings:
        print(f"::warning file={path},line=1::{path} is built by a Makefile.am but no CI leg "
              f"compiles it: add it to build/linux/bpi/makefile (and rpi), unless it is "
              f"platform-specific (XB-only, feature-gated).")
    # The summary section, folded into the ci-summary comment by the stage-2 job.
    try:
        os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as fh:
            fh.write(render_md(findings))
    except OSError as exc:
        print(f"source-coverage: could not write {out_path}: {exc}")
    print(f"source-coverage: {len(findings)} added source(s) no CI leg compiles:")
    for path in findings:
        print(f"  - {path}")
    return 0  # never fails the build


if __name__ == "__main__":
    sys.exit(main(sys.argv))
