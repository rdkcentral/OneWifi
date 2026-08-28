# OneWifi / rdk-wifi-hal CI-gate system

This describes the CI-gate design shared by two repos: `rdkcentral/OneWifi` and `rdk-wifi-hal`.
Both ship the same scripts and composite actions, so learning one teaches you the other.

**Purpose:** catch formatting problems, newly-introduced compiler warnings, and static-analysis
issues on a pull request — without redoing the pre-existing warning/finding backlog in either
tree. It is built to judge *new* code, not old code.

This doc gives the mental model in ~15 minutes. For exact flag lists, promotion order, and the
"why", see `~/ci-tightening-roadmap.md` (not in this repo).

## 1. Build legs

`.github/workflows/makefile.yml` ("Build Check") builds a 3-leg matrix on every PR into `develop`:

| leg | id | compile DB? | diff-scoped checks? | notes |
|---|---|---|---|---|
| Banana Pi R4 (MLO) | `bpi` | yes, via `bear` | clang-tidy + gcc diff-gate | the deep, authoritative leg |
| Raspberry Pi | `rpi` | no | no | same clean-baseline build, lighter checks |
| Platform Mock (unittests) | `mock` | no | no | unittest leg, no warning gate at all |

`bpi` and `rpi` both `include build/linux/makefile.common`, so both get the same clean-baseline
`-Werror` promotions (§3). Only `bpi` also runs `bear` to produce `compile_commands.json`, which
clang-tidy and the gcc diff-gate need — that's why those two checks are `bpi`-only. `mock`'s
makefile does not include `makefile.common` at all, so it carries no warning gate, and it's
excluded from the `ci-summary-*` artifact upload, so nothing from `mock` is ever posted to the PR.

**`bpi` is the leg to trust for warning/static-analysis signal; `rpi` only confirms the clean
baseline still builds; `mock` is unittests only.**

## 2. Cross-repo build + the knobs that decouple it

The HAL has no build makefile of its own. Its CI clones OneWifi (which owns
`build/linux/{bpi,rpi}/makefile`) and builds the HAL PR *inside* that cloned tree:

```
rdk-wifi-hal CI run
  checkout rdk-wifi-hal PR --> easymesh_project/rdk-wifi-hal
  clone OneWifi (develop)  --> easymesh_project/OneWifi
  clone unified-wifi-mesh  --> easymesh_project/unified-wifi-mesh
  make -C easymesh_project/OneWifi ...   (builds all three trees together)
```

So a naive "add a warning class" change in OneWifi would silently affect HAL CI too, and vice
versa. This is avoided with **path-scoped `-Werror` variables** in `build/linux/makefile.common`,
instead of one global `CFLAGS` warning list:

- `RDK_HAL_WERROR` — applied only to `$(WIFI_RDK_HAL)/%.o` objects. Lives in the OneWifi tree but
  gates HAL objects in **both** repos' CI (whole-file, not diff-scoped, hence a "fix HAL before
  promoting" ordering rule).
- `ONE_WIFI_WERROR` — the promoted-to-error list for OneWifi's own objects only. `ONE_WIFI_WARN`
  is the broader umbrella (`-Wall -Wextra` + `$(ONE_WIFI_WERROR)` + `-Wno-*` suppressions) applied
  to OneWifi's own object lists.
- hostap's own tree compiles under a blanket `-w` — a global `-Werror=` would be silenced there
  and would gate every other tree by accident, which is why promotions live in these scoped
  variables instead.

The diff-scoped gcc gate script, `.github/scripts/gcc_diff_gate.py`, is **identical in both
repos**. It reads a `REPO_DIR` env var for where the changed files + git history live: `.` in
OneWifi (compile DB is in its own checkout), `../rdk-wifi-hal` in the HAL job (compile DB is built
in the cloned OneWifi cwd, but the diff must run against the HAL checkout). Net effect: **the HAL
adds its own enforcement by pointing shared tooling at itself — OneWifi's pipeline needs no change
for this to work.**

## 3. The four check types

**a) Formatter (clang-format)** — advisory, PR-changed-lines only. `clang-format.yml` runs
`git-clang-format` over the PR's changed C/C++ lines and records a diff; `diff_to_suggestions.py` turns
it into GitHub review `suggestion` blocks, dropping any suggestion outside the PR's actual changed
lines (git-clang-format can reformat adjacent lines it didn't need to). It currently only posts
suggestions — the `exit 1` that would fail the job is present but commented out, so this does
**not** block merge today.

**b) Tree-wide clean-baseline enforcement** — mixed gate/report, whole tree. The build runs with a
Yocto-derived baseline (`-Wall -Wextra` plus explicit `-Wno-*` suppressions for known backlog
classes). Which classes are hard errors is controlled by `RDK_HAL_WERROR` / `ONE_WIFI_WERROR` (§2)
— deliberately not enumerated here, since the list is meant to keep growing as backlogs get
cleaned. Anything not yet promoted still prints in `build-summary.md`, so a genuinely new warning
class is visible before it's made fatal. The Yocto set is the baseline, and tightening it over
time is the intent.

**c) clang-tidy** — two-tier, changed-lines scoped, `bpi` only. Governed by `.clang-tidy`:
`WarningsAsErrors` checks (a short `bugprone-*` list verified at zero occurrences across both
trees) print `error:` and fail the job; the rest of the enabled `bugprone-*` checks print
`warning:` and are advisory only. `clang-diagnostic-*` is filtered out entirely, so it can never
gate. Findings are scoped to lines the PR changed, so a pre-existing finding on an untouched line
never fails a PR. The HAL layers its own extra checks (`HAL_EXTRA_WAE` / `HAL_EXTRA_CHECKS`, in
the HAL's `makefile.yml`) on top of this shared config, for checks clean in the HAL but not yet in
OneWifi.

**d) Diff-scoped extra gcc warnings ("the gcc diff-gate")** — changed-lines only, `bpi` only.
`gcc_diff_gate.py` recompiles each PR-changed `.c`/`.cpp` from `compile_commands.json` with extra
candidate `-W` flags (non-fatal), keeping only findings on lines the PR touched — so a class with
a tree-wide backlog can still gate *new* code, without a tree-wide `-Werror` that would red every
unrelated PR. Per the workflow's env: `GATE_WARNINGS="-Wvla -Wreturn-type"` (would fail the job),
`ADVISORY_WARNINGS="-Wunused-but-set-variable -Wunused-value -Wunused-label"` (report only). The
whole mechanism is currently in its rollout window (`ENFORCE: 'false'`): the "would fail" block
renders, but the job is not actually reddened by it yet.

## 4. Two-stage design (why, and how)

Posting to a PR needs `pull-requests: write`. Building a PR's code means running a fork author's
makefiles/scripts. Doing both in one job is a classic "pwn-request." So the system splits in two:

```
 PR pushed / updated
        |
        v
 STAGE 1 (pull_request, untrusted PR code, NO write token)
   clang-format.yml -> clang-format.diff, changed-lines.txt, pr-meta.env
   makefile.yml      -> build-summary.md, tidy-summary.md,
                         gcc-gate-summary.md, pr-meta.env
        | (artifacts only)
        v
 STAGE 2 (workflow_run, trusted base-repo context, write token)
   pr-comments.yml
     - checks out the BASE repo only, never PR code
     - downloads stage-1 artifacts as passive data, validates, posts
        |
        v
   inline suggestions / sticky PR comments
```

Stage 1 is `makefile.yml` and `clang-format.yml`, triggered on `pull_request`, both
`permissions: contents: read`. They only build things and upload artifacts; they never touch the PR.

Stage 2 is `pr-comments.yml`, on `workflow_run` for those two workflows. `workflow_run` always
executes the copy of the workflow (and any local composite actions) from the **base repo's default
branch**, regardless of what the PR changed — so a PR can't smuggle a malicious `pr-comments.yml`
in to run with the write token. It holds `pull-requests: write` (plus `issues: write`, for the
sticky-comment recreate flow's delete step), checks out only the base repo, and reads stage-1
artifacts purely as data.

Every stage-2 job routes its trust decision through `.github/actions/pr-context`: it downloads the
named stage-1 artifact, strictly parses (never `source`s) `pr-meta.env`, binds the recorded PR
number back to the triggering run's head repo/branch (unforgeable), and checks whether the PR head
still matches the recorded sha (`fresh`), so a superseded run doesn't post stale content. The two
sticky-comment jobs share `.github/actions/sticky-comment`, which upserts one comment per marker
(a hidden HTML tag), with an optional "recreate" mode (delete + repost) so the comment resurfaces
at the bottom of the PR timeline instead of staying pinned in place.

## 5. Artifacts

**Stage 1 → stage 2:**
- `clang-format-suggestions`: `clang-format.diff`, `changed-lines.txt`, `pr-meta.env`
- `ci-summary-<leg>` (per `bpi`/`rpi`): `build-summary.md`, `pr-meta.env`, plus (`bpi` only)
  `tidy-summary.md` and `gcc-gate-summary.md`

**Posted back to the PR:**
- inline review `suggestion` comments from the formatter (its own review, dismissed and reposted
  fresh each run, not a sticky comment)
- one sticky "Build summary" comment aggregating every uploaded leg
- one sticky comment folding `tidy-summary.md` + `gcc-gate-summary.md` together (that fold is
  already done; folding the build-summary comment in too is a listed extension)

## 6. Caching

The patched hostap source tree is expensive to rebuild (upstream clone + patch-apply), so it's
cached with `actions/cache@v5` for both `bpi` and `rpi`, in both repos. The cache **key** combines
a hash of the local setup files (`setup.sh`, plus the patch list on `bpi`) with the current tip of
the relevant upstream patch source (`git ls-remote`, or a GitHub API tree-SHA on `bpi`) — so a
real upstream patch change invalidates the key, forcing a rebuild that repopulates the cache. It
is deliberately exact-key-only (no `restore-keys` fallback): a routine miss just means "rebuild
it," never a silently stale hit (the one network-outage exception is in §8). OneWifi's build also caches apt dependencies
(`actions/cache@v5`, key `<os>-apt-<hashFiles apt-packages>`, *with* `restore-keys`) — much
smaller, and a stale hit there is harmless, unlike hostap. See `~/ci-tightening-roadmap.md`,
"Build caching (part 7)" for the full mechanism and the 10 GB/repo budget discussion.

## 7. Dependencies — the pin manifest

Every external repo this build clones is listed in **one place**: the `env:` block at the top of
`makefile.yml` (the "Dependency pins" section). Pinned repos have a SHA; unpinned repos are
commented out with their default branch noted. To bump a dependency, change the SHA in that block.

`setup.sh` reads pins via env vars (`${PIN_HOSTAP_2_11:-<hardcoded>}`) so local `make setup`
still works without the workflow — the hardcoded fallback matches the manifest. The ucode pin is
consumed directly by the install step in `makefile.yml`.

| Repo | Pin var | Pinned? | Consumed by |
|---|---|---|---|
| `jow-/ucode` | `PIN_UCODE` | Yes | `makefile.yml` install step |
| `git.w1.fi/hostap` (2.11, bpi) | `PIN_HOSTAP_2_11` | Yes | `bpi/setup.sh` |
| `git.w1.fi/hostap` (2.10, rpi) | `PIN_HOSTAP_2_10` | Yes | `rpi/setup.sh` |
| `mediatek/meta-filogic` | `PIN_META_FILOGIC` | Yes | `bpi/setup.sh` |
| `rdkcentral/unified-wifi-mesh` | — | No (develop tip) | `makefile.yml` clone step |
| `rdkcentral/rdk-wifi-hal` | — | No (develop tip) | `setup.sh` |
| `rdkcentral/rdkb-halif-wifi` | — | No (develop tip) | `setup.sh` |
| `xmidt-org/trower-base64` | — | No (main tip) | `setup.sh` |
| `rdkcentral/meta-cmf-bananapi` | — | No (default tip) | `bpi/setup.sh` |
| `rdkcentral/hostap-patches` | — | No (default tip) | `rpi/setup.sh` |

**Why pin:** an unpinned input can red CI overnight with zero code change (see the ucode FFI
incident, 2026-08-27). Pin the rest as their next bump surfaces a natural SHA to lock.

## 8. Edge cases & failure modes
Where things get weird. The pipeline leans advisory, so most of these resolve to "warn, don't
red" — a plumbing hiccup should not falsely block a PR.

- **Out-of-diff review `422`.** If the PR is rebased or squash-merged between stage 1 and stage 2,
  a formatter suggestion can target a line no longer in the diff, and GitHub rejects the whole
  review with `422`. Treated as advisory: a `::warning::` (distinguishing the benign rebase/merge
  race from a genuine bad-payload/converter bug) and `exit 0` — never a red. See `pr-comments.yml`.
- **Too many suggestions.** Large reviews trip GitHub rate limits; `MAX_COMMENTS` (25) caps the
  post and the overflow is deferred to the next run with a note. A `404` on the POST is usually
  that rate limit, and stays fatal — the signal to lower the cap.
- **Cache key unresolvable (outage).** If the hostap cache-key step can't reach GitHub it falls
  back to a literal `unresolved` segment; a hit on that bucket can serve a stale tree (logged as a
  `::warning::`). The one non-exact path in the otherwise exact-key cache (§6).
- **Sticky-comment recreate race.** The one item here that *isn't* handled gracefully:
  concurrent stage-2 runs for the same PR can leave duplicate, unreconciled marker comments. A real
  gap to close, not an accepted edge — tracked under known gaps (§9).
- **Fork PRs / superseded runs.** `workflow_run.pull_requests` is empty for fork PRs, so stage 2
  keys concurrency and the trust bind on `head_repository.full_name` + `head_branch` instead. And
  if the PR head advances past what stage 1 measured, `pr-context`'s `fresh` check is false and
  stage 2 skips posting, so a stale run never overwrites fresh content.
- **Hostile or oversized inputs.** `changed-lines.txt` is built over untrusted PR code, so its
  ranges are kept as intervals with a record cap — a crafted `file.c:1-1000000000` can't exhaust
  the trusted job's memory. Likewise the gcc diff-gate fails open (skip + `::warning::`, `exit 0`)
  on a malformed compile DB or a recompile that won't run, rather than emitting a false gate result.

## 9. Extensions / known gaps
(P1/P2 unless noted; see the roadmap's housekeeping section for the full list.)

- Promote individual advisory diff-scoped warning classes to gating, one at a time, once quiet on
  real PRs (the `ENFORCE` rollout in §3d).
- Extend caching: `ccache` is the biggest remaining lever; a `ucode` cache is also proposed but
  needs `ucode`'s clone pinned to a SHA first (currently unpinned, so there's no stable key).
- Heavier analyzers (`gcc -fanalyzer`, more `clang-analyzer-core.*` checks) are candidates, kept
  diff-scoped only — too noisy tree-wide.
- Consolidate the several PR comments into one. The gcc-gate → clang-tidy fold is already done;
  folding the build-summary comment in too is next, deferred until the gcc diff-gate exits its
  advisory rollout.
- gcc-14 watch: CI runs on `ubuntu-24.04` (gcc 13.x), so nothing breaks today; a future move to
  gcc 14 is worth revisiting since newer gcc releases have sometimes promoted optional warnings to
  default errors — not yet audited against this tree specifically.
- Rebase/adapt this system onto `develop` as the various proposal branches land — this doc
  describes the merged end-state, not any one branch's current diff.
- **Known gap — sticky-comment recreate race (P4).** "Recreate" mode's delete-then-repost isn't
  atomic across concurrent stage-2 runs, so rapid pushes to one PR can leave duplicate marker
  comments with nothing to reconcile them. Worth fixing (a lock, a reconcile pass, or an
  edit-in-place-only mode), not just documenting.

## 10. If you change the build layout — the path-coupling checklist
Almost every path assumption in this pipeline **fails silently, as a false-negative**: a mis-scoped
filter does not error, it just quietly stops matching the files it used to, so the gate goes
*quiet* rather than red. A layout change therefore rarely announces itself — nobody notices until a
reviewer (or a tool like Copilot) spots a file the gate should have caught. The `startswith("build/")`
filter that hid `build/linux/compat/coverage_stubs.c` from the gcc diff-gate — and the sibling
`"hostap"` substring that hid the HAL's `wifi_hal_hostapd.c` — were exactly this failure mode.
Before you rename a tree, move sources, or restructure the checkout, walk this list.

**The one safety net, and what it does *not* cover.** Both diff-scoped gates skip any changed file
that is not in `compile_commands.json` (`db_args()` returns `None`; clang-tidy falls back to default
flags and self-aborts), so they degrade safely for files that simply are not built. That does **not**
protect against a mis-scoped *exclusion*, which drops a file that *is* built. The exclusion filters
are the fragile part — treat every one as load-bearing.

**If you rename or relocate a sibling tree** (`rdk-wifi-hal`, `rdk-wifi-libhostap`,
`unified-wifi-mesh`, `halinterface`, `trower-base64`) **or the `easymesh_project/` container:**
- `build/linux/{bpi,rpi}/makefile` — the relative include paths (`$(BASE_DIR)/../rdk-wifi-hal`,
  `../rdk-wifi-libhostap`, …). The one place that **fails loudly** (a compile error), not silently.
- `build/linux/{bpi,rpi}/setup.sh` — the sibling `git clone … <dir>` targets and their
  `[ ! -d <dir> ]` guards.
- `.github/workflows/makefile.yml` — the checkout `path:` + `mv … easymesh_project/<repo>` assembly,
  and each step's `working-directory:`.
- The **changed-files exclusion** — `gcc_diff_gate.py` `changed_files()` and the clang-tidy `CHANGED`
  grep both key on the literal marker `rdk-wifi-libhostap/`. Rename that tree and vendored sources
  stop being excluded; give a first-party dir a name that now matches the marker and it gets
  wrongly excluded. *Silent.*
- The **build-summary warns filter** — OneWifi excludes `rdk-wifi-hal|rdk-wifi-libhostap|unified-wifi-mesh`,
  the HAL excludes `OneWifi|rdk-wifi-libhostap|unified-wifi-mesh` — i.e. "the *other* trees, by
  name." *Silent.* Mind the runner-root trap: the checkout root is `/work/<repo>/<repo>/…`, so a
  repo's own name appears in *every* build-log path — a positive substring match on your own repo
  name would match everything (this exact mistake once no-op'd the HAL filter).
- The **display path-strip** (`s#[^ ]*/(OneWifi|rdk-wifi-hal|…)/#` in `makefile.yml`, and the
  `re.sub(r"^[^ ]*/(?:OneWifi|rdk-wifi-hal)/+", …)` in `gcc_diff_gate.py`) — cosmetic only, but it
  emits broken, non-repo-relative paths into the PR comments if a repo dir name changes.

**If you change where the compile DB lives, or a step's `working-directory`:**
- `REPO_DIR` (gcc diff-gate env) — `.` when the DB sits in the same checkout as the diff (OneWifi),
  `../rdk-wifi-hal` when the DB is built in a *cloned* cwd but the diff must run against a different
  checkout (the HAL). This single knob is what lets the *identical* script enforce against whichever
  tree owns the PR; if the DB/checkout split moves, this is what has to track it.
- clang-tidy's `-p .` and the gate's `DB = "compile_commands.json"` both assume the step's cwd holds
  the DB. `db_args()` matches a git-diff path to a DB entry by path-boundary suffix
  (`endswith("/" + f)`), so it survives a change in the *absolute* runner-root prefix — but if two
  trees ever share a trailing sub-path, `next()` takes the first match.

**If you add or move a first-party source under `build/`** (another compat shim or stub): nothing to
update — it is gated the moment it is tracked and in the DB, which is the whole point of the recent
fix. This is listed only to make the inverse explicit: **do not** reintroduce a `build/`-prefix
exclusion to "skip build stuff." To exclude a genuinely generated tracked source, exclude that
*specific* path and comment why.

**If you move HAL objects or change their object-path prefix:** `build/linux/makefile.common` scopes
`RDK_HAL_WERROR` to `$(WIFI_RDK_HAL)/%.o` (and `ONE_WIFI_WARN` to OneWifi's own object lists). The
scoping is by object path — move the objects and the scoped `-Werror` silently stops applying to
them, quietly demoting whole warning classes back to non-fatal. *Silent.*

**Rule of thumb:** after any layout change, grep `.github/` and `build/linux/` for the *old*
directory name and for `easymesh_project` — every hit is a coupling to re-verify. And because these
fail quiet, confirm the fix by watching a real PR's gate actually *fire* on a known-bad changed
line, not just by seeing the job go green.

---

*Sources: the workflow YAML and scripts under `.github/` in this repo and in the HAL repo, plus
`~/ci-tightening-roadmap.md`. Some details here (line-scoped clang-tidy, the hostap cache step,
the gcc→clang-tidy comment fold, sticky-comment recreate mode) are ahead of any single branch
currently checked into this repo — this doc describes the intended merged design.*