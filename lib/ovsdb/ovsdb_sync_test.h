/*
Copyright (c) 2015, Plume Design Inc. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
   1. Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
   2. Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
   3. Neither the name of the Plume Design Inc. nor the
      names of its contributors may be used to endorse or promote products
      derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL Plume Design Inc. BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#ifndef OVSDB_SYNC_TEST_H
#define OVSDB_SYNC_TEST_H

/*
 * This header is intentionally guarded by UNIT_TEST.  It exposes internal
 * symbols that are needed by unit tests but must not be part of the public
 * or production ABI.
 *
 * Both ovsdb_sync.c (built with -DUNIT_TEST) and the test translation unit
 * include this header, so the compiler verifies that the prototype matches
 * the actual definition.
 */
#ifdef UNIT_TEST

#include <jansson.h>

/**
 * Returns a newly-allocated JSON string with all sensitive field values
 * replaced by "[REDACTED]".  The caller must free() the returned string.
 * Returns NULL if jsdata is NULL or if memory allocation fails.
 *
 * Exported only when compiled with -DUNIT_TEST; static in production builds.
 */
char *ovsdb_sanitize_json_for_logging(json_t *jsdata);

#endif /* UNIT_TEST */

#endif /* OVSDB_SYNC_TEST_H */
