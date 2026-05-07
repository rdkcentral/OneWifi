# OneWifi Code Review

**Repository:** `rdkcentral/OneWifi`  
**Review Date:** 2026-05-07  
**Scope:** Core control engine, manager, utilities, and data-plane modules

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Architecture Summary](#2-architecture-summary)
3. [Module-by-Module Review](#3-module-by-module-review)
   - 3.1 [source/core/wifi_ctrl.c](#31-sourcecorewifi_ctrlc)
   - 3.2 [source/core/wifi_mgr.c](#32-sourcecorewifi_mgrc)
   - 3.3 [source/core/wifi_data_plane.c](#33-sourcecorewifi_data_planec)
   - 3.4 [source/core/wifi_events.c](#34-sourcecorewifi_eventsc)
   - 3.5 [source/utils/wifi_util.c / wifi_util.h](#35-sourceutilswifi_utilc--wifi_utilh)
   - 3.6 [source/utils/scheduler.c / scheduler.h](#36-sourceutilsschedulerc--schedulerh)
   - 3.7 [source/utils/collection.c / collection.h](#37-sourceutilscollectionc--collectionh)
   - 3.8 [source/utils/wifi_validator.c](#38-sourceutilswifi_validatorc)
   - 3.9 [include/wifi_base.h / wifi_ctrl.h / wifi_mgr.h](#39-includewifi_baseh--wifi_ctrlh--wifi_mgrh)
4. [Security Findings](#4-security-findings)
5. [Memory Management Findings](#5-memory-management-findings)
6. [Concurrency & Thread-Safety Findings](#6-concurrency--thread-safety-findings)
7. [Error Handling Findings](#7-error-handling-findings)
8. [Code Quality Observations](#8-code-quality-observations)
9. [Positive Highlights](#9-positive-highlights)
10. [Summary & Recommendations](#10-summary--recommendations)

---

## 1. Project Overview

OneWifi is the RDK-B WiFi management component. It provides centralised control of WiFi parameters, statistics, telemetry, client steering, and mesh networking across Gateway and Extender devices. It bridges high-level configuration interfaces (TR-181 / JSON WebConfig) with hardware via a WiFi Hardware Abstraction Layer (HAL).

**Key responsibilities:**
- Radio and VAP lifecycle management
- Event-driven control loop (queue-based)
- DFS channel management and self-healing
- EasyMesh / Multi-AP support (including WiFi 7 MLO)
- Application framework for analytics, blaster, CSI, steering, CAC

---

## 2. Architecture Summary

```
External (TR-181 / WebConfig / RBus)
        │
        ▼
  wifi_mgr_t  ──── global singleton state
        │
        ├── wifi_ctrl_t  ──── event queue, scheduler, service map
        │       │
        │       ├── Queue loop  (ctrl_queue_loop)
        │       ├── Scheduler   (source/utils/scheduler.*)
        │       └── VAP services (vap_svc_t array)
        │
        ├── wifi_db_t   ──── OVSDB-backed persistent storage
        └── wifi_dml_t  ──── TR-181 DML interface
                │
                ▼
          WiFi HAL (platform-specific)
```

- **Single global instance** (`g_wifi_mgr` in `wifi_mgr.c`) exposed via accessor functions.
- **Event loop** in `ctrl_queue_loop()` pops events from a mutex-protected queue, dispatches to handlers, then forwards to the apps manager.
- **Scheduler** runs periodic and one-shot timer tasks on the same thread as the event loop (driven by `pthread_cond_timedwait` timeouts).
- **Data structures**: custom queue and flat hash map in `source/utils/collection.c`.

---

## 3. Module-by-Module Review

### 3.1 `source/core/wifi_ctrl.c`

**Purpose:** Core control logic — radio management, VAP lifecycle, selfheal, DFS, startup sequencing.

#### Issues Found

| # | Severity | Location | Description |
|---|----------|----------|-------------|
| C1 | 🔴 High | `get_Uptime()` (line 421–437) | Uses `system()` to run `/bin/cat /proc/uptime > <file>` — command injection risk and unnecessary; `/proc/uptime` can be read directly with `fopen`. |
| C2 | 🔴 High | `start_radios()` (line 506–509) | `dfs_channel_data` is allocated with `malloc` but the return value is not checked before `memset` / field assignments. A NULL dereference can occur on OOM. |
| C3 | 🟡 Medium | `start_extender_vaps()` (line 775–783) | `ext_svc` returned by `get_svc_by_type()` is used immediately without a NULL check. If no extender service is registered, this segfaults. |
| C4 | 🟡 Medium | `start_gateway_vaps()` (line 785–824) | `priv_svc`, `pub_svc`, and `mesh_gw_svc` are dereferenced without NULL checks after `get_svc_by_type()`. |
| C5 | 🟡 Medium | `stop_gateway_vaps()` / `stop_extender_vaps()` (lines 826–850) | Same NULL-check gap for service pointers. |
| C6 | 🟡 Medium | `selfheal_event_publish_time()` (line 183–200) | Uses `fgets` without checking the return value before calling `strchr`. Uses `atoi` twice (line 199) — call once and cache the result; `atoi` also silently returns 0 on parse failure with no error indication. |
| C7 | 🟠 Low | `sta_selfheal_handing()` (line 257) | Uses `static` local variables (`radio_reset_triggered`, `disconnected_time`, `connection_timeout`) making the function non-reentrant. State cannot be reset cleanly without going through the normal code path, and it is invisible to callers. |
| C8 | 🟠 Low | `ctrl_queue_loop()` (line 360) | Comment `// TODO: event 4 flood` indicates unresolved investigation. |
| C9 | 🟠 Low | `get_Uptime()` (line 426) | `snprintf` result is not checked. If the file path exceeds `BUF_SIZE`, the command is silently truncated. |

#### Code Snippet — `get_Uptime` security issue

```c
// CURRENT (problematic)
snprintf(cmd, sizeof(cmd), "/bin/cat /proc/uptime > %s", FILE_SYSTEM_UPTIME);
system(cmd);
fp = fopen(FILE_SYSTEM_UPTIME, "r");

// RECOMMENDED — read /proc/uptime directly; no shell needed
fp = fopen("/proc/uptime", "r");
if (fp != NULL) {
    if (fscanf(fp, "%u", &upSecs) != 1) { ... }
    fclose(fp);
}
```

---

### 3.2 `source/core/wifi_mgr.c`

**Purpose:** Global WiFi manager singleton initialisation, HAL init, radio/VAP config bootstrap.

#### Issues Found

| # | Severity | Location | Description |
|---|----------|----------|-------------|
| M1 | 🔴 High | `is_supported_gateway_device()` (line 186) | Uses `popen("cat /etc/device.properties \| grep MODEL_NUM \| cut -f 2 -d\"=\"", ...)` — this spawns three processes through a shell. The `device.properties` file should be read directly. |
| M2 | 🟡 Medium | `init_global_radio_config()` (line 158) | When `hash_map_create()` fails for `associated_devices_map`, the function logs but continues; the `associated_devices_lock` mutex allocated just above is already initialised and the entry is still used — the caller may later lock/unlock an allocated mutex for a VAP with a NULL device map. |
| M3 | 🟡 Medium | `bus_get_vap_init_parameter()` (line 629–749) | Contains an infinite `sleep(1)` polling loop for device mode (lines 655–662) with no overall timeout, which could block initialisation indefinitely under certain hardware states. |
| M4 | 🟠 Low | Duplicate `#include <stdlib.h>` (lines 22 and 34) | Minor: `stdlib.h` is included twice. |

---

### 3.3 `source/core/wifi_data_plane.c`

**Purpose:** Data plane event/packet dispatch (802.1x, auth frames, assoc frames).

#### Issues Found

| # | Severity | Location | Description |
|---|----------|----------|-------------|
| D1 | 🟠 Low | `process_event_timeout()` (line 55) | Commented-out call `//process_easy_connect_event_timeout(...)` inside a `#if` guard suggests dead or unfinished DPP code. Should either be removed or tracked as a known limitation. |
| D2 | 🟠 Low | `process_timeout()` (line 42) | No NULL guard on `g_data_plane_module` fields before calling sub-module timeout functions. |

---

### 3.4 `source/core/wifi_events.c`

**Purpose:** Event type/subtype to string conversion; event lifecycle helpers.

#### Issues Found

| # | Severity | Location | Description |
|---|----------|----------|-------------|
| E1 | 🟠 Low | `wifi_event_type_to_string()` and `wifi_event_subtype_to_string()` | The `DOC2S` macro is defined twice (once per function). Consider using a single shared definition or an `x-macro` pattern. |
| E2 | 🟠 Low | Both string functions | `default:` calls `wifi_util_error_print` for an unknown event. For `wifi_event_subtype_to_string`, unknown subtypes are expected as the enum is large — an error log every time may be too noisy; consider `dbg` level. |

---

### 3.5 `source/utils/wifi_util.c` / `wifi_util.h`

**Purpose:** Cross-cutting utilities: logging, MAC helpers, channel validation, platform property lookup.

#### Issues Found

| # | Severity | Location | Description |
|---|----------|----------|-------------|
| U1 | 🟡 Medium | `wifi_util.h` macros `VERIFY_NULL`, `VERIFY_NULL_WITH_RETURN_INT` | Return semantics differ (`void`, `NULL`, `RETURN_ERR`) but there is no `VERIFY_NULL_WITH_RETURN_BOOL` variant, leading callers to use `VERIFY_NULL_WITH_RETURN_INT` for boolean-returning functions (which returns `RETURN_ERR` = -1, not `false`). |
| U2 | 🟠 Low | Macro `GET_VAP_INDEX_PROPERTY` / `GET_VAP_NAME_PROPERTY` (line 52–54) | Use GNU statement expressions (`({...})`). This is a GCC extension and will not compile with strict ISO C compilers. Document this requirement or replace with inline functions. |
| U3 | 🟠 Low | `TOTAL_VAPS` / `TOTAL_INTERFACES` macros (lines 56–73) | Wrap `do { ... } while(0)` with a surrounding `{}` block; the trailing `;` after `}` inside the macro is redundant and may trigger warnings on some compilers. |

---

### 3.6 `source/utils/scheduler.c` / `scheduler.h`

**Purpose:** Priority-based timer task scheduler (high/low priority queues) executed on the control-loop thread.

#### Issues Found

| # | Severity | Location | Description |
|---|----------|----------|-------------|
| S1 | 🟡 Medium | `scheduler.h` API | `scheduler_add_timer_task` takes an `int *id` out-parameter but there is no documented guarantee about what value it holds on failure. Several callers pass `NULL` for `id` (e.g., `scheduler_add_timer_task(ctrl->sched, FALSE, NULL, ...)`) — the implementation should explicitly handle a NULL `id` pointer. |
| S2 | 🟠 Low | High/low priority queues | The scheduler runs entirely on the control-loop thread (no dedicated thread). Long-running callbacks will block the entire event queue. This is an architectural note rather than a bug, but should be documented. |

---

### 3.7 `source/utils/collection.c` / `collection.h`

**Purpose:** Queue and flat (unsorted linked list) hash map.

#### Issues Found

| # | Severity | Location | Description |
|---|----------|----------|-------------|
| COL1 | 🔴 High | `hash_map_t` implementation | The "hash map" is a flat linked list. Lookup is O(n). For small maps this is acceptable, but `associated_devices_map` (one per VAP) and `acl_map` can grow large in high-client-count environments. Performance may degrade significantly. |
| COL2 | 🟡 Medium | `hash_map_put` | No check for duplicate keys is visible in the header. If callers insert the same key twice, the behaviour (overwrite vs. duplicate) should be documented. |
| COL3 | 🟠 Low | `HASH_MAP_MAX_KEY_SIZE 100` | The constant name implies a hash map but it is actually a string-length limit. Rename to `HASH_MAP_MAX_KEY_LEN` for clarity. |

---

### 3.8 `source/utils/wifi_validator.c`

**Purpose:** Validates WebConfig/passpoint JSON subdocument parameters.

#### Issues Found

| # | Severity | Location | Description |
|---|----------|----------|-------------|
| V1 | 🟠 Low | Macro `ONE_WIFI_CHANGES` (line 45) | This macro is defined but only used to mark sections for re-review (`//This Macro ONE_WIFI_CHANGES, used to modify the validator changes. Re-check is required...`). Leaving such markers in production code is a maintenance risk. All marked sections should be reviewed and the macro removed. |
| V2 | 🟠 Low | `validate_param_string` / `validate_param_integer` macros | These macros `return RETURN_ERR` — they can only be used inside functions that return `int`. Using them inside a `void` function would be a silent compile error. Consider guarding with `static_assert` or converting to inline functions. |

---

### 3.9 `include/wifi_base.h` / `wifi_ctrl.h` / `wifi_mgr.h`

**Purpose:** Core data model definitions and global accessor declarations.

#### Issues Found

| # | Severity | Location | Description |
|---|----------|----------|-------------|
| H1 | 🟠 Low | `wifi_mgr.h` line 64 | `wifi_mgr_t *get_wifimgr_obj()` is declared without `void` in the parameter list. In C, `f()` means "accepts any arguments"; use `f(void)` to declare a no-argument function. |
| H2 | 🟠 Low | `wifi_ctrl.h` | Many `#define` string constants for RBus paths (lines 58–80+). Consider grouping these into a dedicated header (e.g., `wifi_bus_defs.h`) to reduce clutter in `wifi_ctrl.h`. |

---

## 4. Security Findings

| ID | Severity | File | Line(s) | Description | Recommendation |
|----|----------|------|---------|-------------|----------------|
| SEC-1 | 🔴 **Critical** | `wifi_ctrl.c` | 426–427 | `system()` used to run `cat /proc/uptime` — unnecessary shell invocation that enlarges the attack surface. | Read `/proc/uptime` directly with `fopen`/`fscanf`. |
| SEC-2 | 🔴 **Critical** | `wifi_mgr.c` | 186–194 | `popen()` with a shell pipeline to read a device property file — unnecessary. | Parse `/etc/device.properties` directly in C. |
| SEC-3 | 🟡 Medium | `wifi_ctrl.c` | 199 | `atoi()` used on file content without length/bounds validation. A corrupt `/nvram/selfheal_event_publish_time` file with a very large number causes uncontrolled timer intervals. | Use `strtol` with range checks. |
| SEC-4 | 🟠 Low | `wifi_validator.c` | Multiple | JSON validation macros return early on missing fields but do not sanitise string lengths before use downstream. | Add length checks after validation. |

---

## 5. Memory Management Findings

| ID | Severity | File | Line(s) | Description | Recommendation |
|----|----------|------|---------|-------------|----------------|
| MEM-1 | 🔴 High | `wifi_ctrl.c` | 506–509 | `malloc(sizeof(dfs_channel_data_t))` result used without NULL check. | Add NULL check; free and return `RETURN_ERR` on failure. |
| MEM-2 | 🟡 Medium | `wifi_mgr.c` | 147–168 | On `hash_map_create()` failure, the function logs and continues. The previously allocated `associated_devices_lock` mutex is initialised but the overall VAP entry is partially constructed. | On any allocation failure, clean up previously allocated resources and return `RETURN_ERR`. |
| MEM-3 | 🟡 Medium | `wifi_ctrl.c` | 90–128 (`wifi_radio_set_enable`) | `temp_wifi_radio_oper_param` is freed correctly on the success/early-error paths, but if `wifi_hal_setRadioOperatingParameters` fails mid-loop, the function continues iterating and `ret` is overwritten. The last radio's error is reported; intermediate errors are lost. | Accumulate errors or break on first failure as per intended semantics. |
| MEM-4 | 🟠 Low | `collection.h` | — | `hash_map_cleanup` vs `hash_map_destroy` distinction is unclear in the header. Callers may free the map data without freeing the map itself, or vice versa. | Add documentation to the header clarifying ownership semantics. |

---

## 6. Concurrency & Thread-Safety Findings

| ID | Severity | File | Line(s) | Description | Recommendation |
|----|----------|------|---------|-------------|----------------|
| THR-1 | 🔴 High | `wifi_ctrl.c` | 264–265 | `static bool radio_reset_triggered` and `static unsigned int disconnected_time` in `sta_selfheal_handing()` — static locals that are mutated across calls. If this function is ever called from multiple threads, there is a data race. | Move state into the caller's context struct (`wifi_ctrl_t`) or add mutex protection. |
| THR-2 | 🟡 Medium | `wifi_ctrl.c` | 405–407 | `init_wifi_global_config()` uses a `static bool wifi_global_param_init` without mutex protection. If called concurrently from two threads, double-initialisation is possible. | Use `pthread_once` or guard with a mutex. |
| THR-3 | 🟡 Medium | `wifi_ctrl.c` | 307–403 | In `ctrl_queue_loop()`, the queue lock is released before dispatching each event (line 340) and reacquired after (line 377). During this window, the event pointer is live but unprotected. `destroy_wifi_event()` is called at line 374 outside the lock — ensure no other thread can touch the same event pointer. | Document the ownership transfer explicitly; consider an event reference-count model. |
| THR-4 | 🟠 Low | `wifi_mgr.c` | 42 | `g_wifi_mgr` and `g_misc` are module-level globals initialised at process start. Ensure no path calls accessor functions before `init_wifi_mgr()` completes. | Add an `assert(g_wifi_mgr_initialized)` gate in accessor functions during debug builds. |

---

## 7. Error Handling Findings

| ID | Severity | File | Line(s) | Description | Recommendation |
|----|----------|------|---------|-------------|----------------|
| ERR-1 | 🟡 Medium | `wifi_ctrl.c` | 775–783 | `start_extender_vaps()` calls `ext_svc->start_fn(...)` without checking whether `ext_svc` is NULL. `get_svc_by_type()` can return NULL if no matching service is registered. | Always NULL-check service pointer before invoking function pointers. |
| ERR-2 | 🟡 Medium | `wifi_ctrl.c` | 785–824 | Same pattern in `start_gateway_vaps()` — three service pointers used without NULL checks. | Same as ERR-1. |
| ERR-3 | 🟡 Medium | `wifi_ctrl.c` | 696–703 | `bus_get_vap_init_parameter()` has an unbounded retry loop for device mode on `EASY_MESH_NODE` builds (lines 655–662) and a 5-retry loop for bus data fetch (lines 696–703). The function silently returns on timeout without setting `*ret_val` to a safe default. | Document the timeout behaviour; set `*ret_val` to a safe default before returning. |
| ERR-4 | 🟠 Low | `wifi_ctrl.c` | 427 | `system()` return value is not checked. If the shell command fails, the subsequent `fopen` will either open a stale file or fail; either way the uptime read is silently wrong. | (Moot if SEC-1 is fixed; otherwise check return value.) |
| ERR-5 | 🟠 Low | `wifi_ctrl.c` | 193–194 | `fgets` return value is not checked in `selfheal_event_publish_time()`. | Check return before passing buffer to `strchr`. |

---

## 8. Code Quality Observations

### 8.1 Inconsistent Coding Style

- Some files use `UINT` (a typedef) while others use `unsigned int` or `uint8_t` for the same semantic. Align to the project's [CODE_STYLE.md](CODE_STYLE.md) guidance.
- Trailing whitespace and inconsistent indentation (tabs vs. spaces) in `wifi_ctrl.c` around lines 282–283.
- Copyright header format differs slightly between files (some end with `******************/`, others with a longer line of `*`s followed by `/`).

### 8.2 Magic Numbers

Several numeric constants appear inline without named definitions:

| Location | Magic Number | Suggested Constant |
|----------|--------------|--------------------|
| `wifi_ctrl.c:275` | `STA_CONN_RETRY_TIMEOUT` | already defined — good |
| `wifi_ctrl.c:519` | `60 * 1000` (DFS switch delay) | `#define DFS_CHANNEL_SWITCH_DELAY_MS (60 * 1000)` |
| `wifi_ctrl.c:532` | `60 * 1000` (NOP start delay) | same as above |
| `wifi_ctrl.c:442` | inline channel list `{36, 40, 44, 48, …}` | already in an array — acceptable |
| `wifi_ctrl_queue_handlers.c:38` | `40000` (scan interval) | already has a comment but no `#define` — add one |

### 8.3 Dead / Commented-Out Code

- `wifi_data_plane.c:62`: `//process_easy_connect_event_timeout(event->u.dpp_ctx, ...)` — commented since "ONE_WIFI" migration. Remove or restore.
- `wifi_ctrl_queue_handlers.c:360`: `// TODO: event 4 flood` — stale TODO.
- `wifi_validator.c:45`: `#define ONE_WIFI_CHANGES` — used only as a marker, not functional.

### 8.4 Use of `atoi`

`atoi` is used in `selfheal_event_publish_time()` (line 199, called twice on the same string). Prefer `strtol` which allows range checking and detection of conversion errors.

### 8.5 `popen` / `system` Usage

Beyond the security concerns above, there are additional `popen` usages in `wifi_mgr.c` (`is_supported_gateway_device`). All such usages should be audited and replaced with direct file/ioctl reads wherever possible, both for security and performance reasons.

### 8.6 Missing `(void)` in Function Declarations

`wifi_mgr.h` line 64: `wifi_mgr_t *get_wifimgr_obj()` — in C, empty parentheses mean "unspecified arguments", not "no arguments". All such declarations should use `(void)`.

---

## 9. Positive Highlights

- **Consistent error logging:** `wifi_util_error_print` / `wifi_util_dbg_print` with `__func__` and `__LINE__` are used throughout, making debugging straightforward.
- **Resource cleanup in `deinit_wifi_ctrl`:** Queues, scheduler, mutexes, and condition variables are all destroyed in one place with proper NULL guards.
- **Scheduler design:** The two-priority queue scheduler is clean and well-documented in `scheduler.h` with API descriptions for every function.
- **Macro safety:** Most NULL-check macros use `do { ... } while(0)` to prevent dangling-else issues.
- **Mutex-protected associated device map:** Per-VAP `associated_devices_lock` is heap-allocated (so copies of the struct do not share lock state), with explicit lock/unlock around all accesses — a well-thought-out pattern.
- **Event-driven architecture:** The clear separation between event production (HAL, bus, DML) and consumption (ctrl queue loop) makes the control flow traceable and testable.
- **Modular application framework:** The apps manager pattern allows new applications to be added without modifying core control logic.

---

## 10. Summary & Recommendations

### Critical (fix before merging to main/release)

1. **SEC-1 / SEC-2** — Replace `system()` and `popen()` shell invocations with direct file operations.
2. **MEM-1** — Add NULL check after `malloc(sizeof(dfs_channel_data_t))` in `start_radios()`.
3. **ERR-1 / ERR-2** — NULL-check all service pointers returned by `get_svc_by_type()` before dereferencing.

### High Priority (fix in next sprint)

4. **THR-1** — Move static local state in `sta_selfheal_handing()` into `wifi_ctrl_t`.
5. **THR-2** — Protect `init_wifi_global_config` idempotency check with `pthread_once`.
6. **COL1** — Evaluate replacing the flat-list hash map with a proper hash table for high-client-count VAP device maps (`associated_devices_map`, `acl_map`).

### Medium Priority (code quality)

7. **M3 / ERR-3** — Add overall timeout and safe default to `bus_get_vap_init_parameter()` polling loops.
8. **SEC-3** — Replace `atoi` with `strtol` + range validation in `selfheal_event_publish_time()`.
9. **H1** — Add `void` to all empty-parameter function declarations.
10. **MEM-2** — Fix partial-initialisation scenario in `init_global_radio_config()` on hash_map allocation failure.

### Low Priority / Code Health

11. Remove or resolve all stale `TODO` comments and commented-out code (`ONE_WIFI_CHANGES`, DPP dead code, event 4 flood TODO).
12. Add `#define` constants for all bare numeric literals representing time intervals or limits.
13. Fix duplicate `#include <stdlib.h>` in `wifi_mgr.c`.
14. Align copyright header format across all files.
15. Audit all remaining `popen`/`system` calls outside the two identified above.

---

*Generated by code review of rdkcentral/OneWifi — source tree as of 2026-05-07.*
