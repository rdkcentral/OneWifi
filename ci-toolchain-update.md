# Toolchain update notes (gcc 14 / 15, clang-tidy 20)

The to-do list for when the compiler moves. Measured 2026-10-20 on the bpi compile DB (OneWifi
develop a6acf829, rdk-wifi-hal develop 626c1f6, hostap 2.11 at the pin, patched). CI itself is
described in `ci-README.md`.

## 1. Why this exists
- Yocto 5.0 (scarthgap): gcc 13.2, LLVM 18.1, the same majors as CI today. No compiler break
  expected.
- Yocto 6.0 (wrynose): gcc 15.2, LLVM 22.1: C23 by default, plus gcc 14's new default errors.
  Production builds use bare -Werror (Yocto flag capture, 2026-08), so every new warning class
  that fires is a build break. #1448 already fixed three `()` declarations for wrynose.
- GitHub runner: ubuntu-24.04 has gcc 12/13/14 and clang-tidy 16/17/18. ubuntu-26.04's lowest
  clang-tidy is 20.1.8, so moving the runner forces clang-tidy 20 (section 5).
- CI builds with gcc 13; the diff-scoped gcc gate recompiles changed files with gcc 14
  (`ci-README.md` 3d), so a PR that adds a gcc-14 error class (e.g. `-Wreturn-mismatch`) is
  flagged on its changed lines today.

## 2. Production flags measured
Yocto capture: -Os -Wall -Wextra -Werror and -Wno- for deprecated-declarations,
discarded-qualifiers, enum-conversion, format-overflow, format-truncation,
implicit-function-declaration, pointer-sign, sign-compare, stringop-truncation,
tautological-compare, type-limits, unused-parameter.

Production OneWifi Makefile.am files set `-Wall -Werror` (source/core, platform, utils, webconfig);
the 2026-08 capture is from an XB10 build (_XB10_PRODUCT_REQ_, _COSA_BCM_ARM_). The measurement
below compiles the bpi CI file set with those flags (minus -Werror, so every site is counted).
Caveat: bpi is not XB10. With the same flags bpi already shows ~140 OneWifi warnings on gcc 13
that production evidently does not compile (66 -Wunused-variable, 17 -Wunused-result,
15 -Wunused-function, ...: code behind other platform #ifdefs). Read the table as "which classes
appear when the compiler moves" (the deltas), not as production counts.

## 3. gcc 13 (scarthgap, CI) to 14 and 15 (wrynose): bpi file set, OneWifi
Sites = distinct (file, line). rdk-wifi-hal (15 TUs): no change across 13/14/15.

| class | gcc 13 | gcc 14 | gcc 15 | 15 + -std=gnu17 | under -Werror |
|---|---|---|---|---|---|
| -Wincompatible-pointer-types | 14 warn | 14 ERROR | 14 ERROR | 14 ERROR | already an error with -Werror; a hard error otherwise |
| -Wint-conversion | 1 warn | 1 ERROR | 1 ERROR | 1 ERROR | same |
| -Wreturn-type / -Wreturn-mismatch | 9 warn | 4 warn + 5 ERROR | same | same | same (gcc 14 moved the 5 to -Wreturn-mismatch) |
| -Wcalloc-transposed-args (new in gcc 14) | - | 1 | 1 | 1 | new break: source/apps/whix/wifi_whix.c:1308 |
| C23: `f()` means `f(void)` | - | - | 6 ERROR (4 files) | 0 | new break: getTotalNumberVAPs() x3, getNumberRadios() x1 called with an argument (wifi_ctrl_rbus_handlers.c:4794, apps/levl/wifi_levl.c:2142/2191/2218); wifi_misc_init in platform/linux/misc.c:65 + platform/common/common.c:38 |
| -Wunterminated-string-initialization (from gcc 15) | - | - | 1 | 1 | new break: lib/common/util.c:269 |
| -Wstringop-overread | 1 | 1 | 0 | 1 | - |
| -Wimplicit-function-declaration | silenced (-Wno-) | silenced: the -Wno- also turns the gcc 14 error off | silenced | silenced | stays silenced; 431 sites hidden (the diff gate reports new ones) |

Files that stop compiling: gcc 13: 0; gcc 14: 4 (wifi_em.c, misc.c, wifi_decoder.c,
he_bus_json_decode.c); gcc 15: 7 (+ wifi_ctrl_rbus_handlers.c, common.c, wifi_levl.c);
gcc 15 with -std=gnu17: 4.

## 4. CI build (makefile.common flags) on gcc 14
Breaks 4 of 380 C files: 5 -Wreturn-mismatch in OneWifi (apps/em/wifi_em.c 1357/2970/2980/2988,
platform/linux/misc.c 57) and 2 implicit declarations in the patched hostap (ap/ieee802_1x.c 809
greylist_get_cmmac, radius/radius_client.c 565 hostapd_drv_radius_fallback_failover; the patches
come from meta-cmf-bananapi / meta-filogic). -fpermissive compiles everything.

## 5. clang-tidy 18 to 20
A drop-in on our config: 0 new findings, 37 fewer false positives (bugprone-sizeof-expression on
pointer arrays, lib/datapipeline), --verify-config clean. With every bugprone-* and
clang-analyzer-* check on: +10, of which unix.BlockInCriticalSection (3) is worth a look.
The 8 checks `bugprone-*` newly enables all report 0.

## 6. Escape hatches and their cost
- `-std=gnu17` in the recipe CFLAGS: removes the C23 part of section 3 in one line.
- `-fpermissive` / `-Wno-error=<class>`: turns gcc 14 permerrors back into warnings, and hides
  the bug classes they catch.

## 7. How to re-measure
1. A clean bpi tree with a compile DB: `make -f build/linux/bpi/makefile setup`, then
   `bear --output compile_commands.json -- make -f build/linux/bpi/makefile all`.
2. The new compilers without root: `apt-get download` gcc-14 (with cpp-14, gcc-14-base,
   libgcc-14-dev) or clang-tidy-20 (with libclang-common-20-dev) and `dpkg -x` into a prefix;
   gcc 15 from an ubuntu:26.04 container that mounts the tree read-only.
3. Recompile every DB entry with each compiler (same arguments, -Werror dropped, then again with
   the production flags of section 2 instead of the DB's -W flags) and count distinct
   (file, line, warning class) per compiler; diff the counts.
