/************************************************************************************
  If not stated otherwise in this file or this component's LICENSE file the
  following copyright and licenses apply:

  Copyright 2026 RDK Management

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
 **************************************************************************/
/*
 * CI coverage-build compatibility header.
 *
 * safec_lib_common.h (the RDK "safeclib" bounds-checked string/mem API) is
 * supplied by CcspCommonLibrary on real RDK builds. A handful of OneWifi apps
 * (whix, harvester, blaster, ...) include it and use sprintf_s / strcat_s.
 * The linux mock/coverage build does not link safeclib, so this header maps the
 * small subset actually used onto the C standard library with matching return
 * semantics (count/EOK, negative-or-non-EOK on error).
 *
 * This file is NOT upstream and must never be pushed; it lives under
 * build/linux/compat and is only on the include path for the coverage builds.
 */

#ifndef SAFEC_LIB_COMMON_FAKE_H
#define SAFEC_LIB_COMMON_FAKE_H

#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>

#ifndef EOK
#define EOK 0
#endif

typedef int    errno_t;
typedef size_t rsize_t;

/* Real safeclib logs on non-EOK; for coverage we just consume the code. */
#ifndef ERR_CHK
#define ERR_CHK(rc) ((void)(rc))
#endif

/* sprintf_s: returns number of characters written (>=0), negative on error,
 * mirroring safeclib so callers' `if (rc < EOK)` error checks behave.
 * Truncation (output would exceed dmax-1 chars) is an ERROR in real safeclib,
 * which clears dest and returns a negative constraint code (-ESNOSPC) - not the
 * would-be length. vsnprintf instead returns that positive would-be length on
 * truncation, which slips through callers' `rc < EOK` checks and would mask a
 * bug that fails on a real RDK build. Convert it to the safeclib error form. */
static inline int sprintf_s(char *dest, rsize_t dmax, const char *fmt, ...)
{
    va_list ap;
    int rc;
    if (dest == NULL || fmt == NULL || dmax == 0) {
        return -1;
    }
    va_start(ap, fmt);
    rc = vsnprintf(dest, dmax, fmt, ap);
    va_end(ap);
    if (rc < 0 || (rsize_t)rc >= dmax) {
        /* encoding error or truncation: mirror safeclib - clear dest, fail. */
        dest[0] = '\0';
        return -1;
    }
    return rc;
}

static inline errno_t strcpy_s(char *dest, rsize_t dmax, const char *src)
{
    if (dest == NULL || src == NULL || dmax == 0) {
        return -1;
    }
    if (strlen(src) >= dmax) {
        dest[0] = '\0';
        return -1;
    }
    strcpy(dest, src);
    return EOK;
}

static inline errno_t strncpy_s(char *dest, rsize_t dmax, const char *src, rsize_t n)
{
    rsize_t slen;
    if (dest == NULL || src == NULL || dmax == 0) {
        return -1;
    }
    /* effective copy length is min(strlen(src), n); if it leaves no room for the
     * terminator (>= dmax) that is a truncation - mirror safeclib: clear + fail,
     * do NOT silently clamp and return EOK (which would mask real-build bugs). */
    slen = strnlen(src, n);
    if (slen >= dmax) {
        dest[0] = '\0';
        return -1;
    }
    strncpy(dest, src, slen);
    dest[slen] = '\0';
    return EOK;
}

static inline errno_t strcat_s(char *dest, rsize_t dmax, const char *src)
{
    size_t dlen;
    if (dest == NULL || src == NULL || dmax == 0) {
        return -1;
    }
    dlen = strnlen(dest, dmax);
    if (dlen + strlen(src) >= dmax) {
        return -1;
    }
    strcat(dest, src);
    return EOK;
}

static inline errno_t memcpy_s(void *dest, rsize_t dmax, const void *src, rsize_t n)
{
    if (dest == NULL || src == NULL || n > dmax) {
        return -1;
    }
    memcpy(dest, src, n);
    return EOK;
}

static inline errno_t memset_s(void *dest, rsize_t dmax, int value, rsize_t n)
{
    if (dest == NULL || n > dmax) {
        return -1;
    }
    memset(dest, value, n);
    return EOK;
}

#endif /* SAFEC_LIB_COMMON_FAKE_H */
