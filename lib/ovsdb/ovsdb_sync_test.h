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

#ifndef OVSDB_SYNC_TEST_H_INCLUDED
#define OVSDB_SYNC_TEST_H_INCLUDED

#include <jansson.h>

/**
 * @brief Sanitize JSON data for safe logging by redacting sensitive fields.
 *
 * This function creates a deep copy of the input JSON and replaces values
 * of known sensitive keys (psk, password, token, etc.) with "[REDACTED]".
 * The caller is responsible for freeing the returned string.
 *
 * @param jsdata The JSON object to sanitize (not modified)
 * @return A newly allocated string with sanitized JSON, or NULL on error.
 *         Caller must free() the returned string.
 *
 * @note This function is only exposed when compiled with -DUNIT_TEST.
 *       In production builds, it remains static to ovsdb_sync.c.
 */
char* ovsdb_sanitize_json_for_logging(json_t *jsdata);

#endif /* OVSDB_SYNC_TEST_H_INCLUDED */
