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

#ifndef OVSDB_CACHE_H_INCLUDED
#define OVSDB_CACHE_H_INCLUDED

#ifdef __cplusplus
extern "C" {
#endif

#include <stdarg.h>
#include <stdbool.h>
#include <jansson.h>

#include "ovsdb.h"
#include "ovsdb_update.h"
#include "schema.h"
#include "ds.h"
#include "json_util.h"
#include "ovsdb_table.h"

// ovsdb cache api

#define ONEWIFI_DECL_CACHE_CALLBACK_CAST(TABLE)                         \
    static inline ovsdb_cache_callback_t* onewifi_cache_cb_cast_##TABLE(\
            void (*cb)(ovsdb_update_monitor_t *self,            \
                struct schema_##TABLE *old,                     \
                struct schema_##TABLE *record,                  \
                ovsdb_cache_row_t *row)) {                      \
        return (ovsdb_cache_callback_t*)(void*)cb;              \
    }

SCHEMA_LISTX(ONEWIFI_DECL_CACHE_CALLBACK_CAST)

#define ONEWIFI_OVSDB_CACHE_MONITOR(DB_FD, TABLE, IGN_VER) \
    onewifi_ovsdb_cache_monitor(DB_FD, &table_ ## TABLE, onewifi_cache_cb_cast_##TABLE(callback_ ## TABLE), IGN_VER)

#define ONEWIFI_OVSDB_CACHE_MONITOR_F(DB_FD, TABLE, FILTER) \
    onewifi_ovsdb_cache_monitor_filter(DB_FD, &table_ ## TABLE, callback_ ## TABLE, FILTER)

bool onewifi_ovsdb_cache_monitor(int ovsdb_fd, ovsdb_table_t *table, ovsdb_cache_callback_t *callback, bool ignore_version);
bool onewifi_ovsdb_cache_monitor_filter(int ovsdb_fd, ovsdb_table_t *table,
        ovsdb_cache_callback_t *callback, char **filter);
void onewifi_ovsdb_cache_dump_table(ovsdb_table_t *table, char *str);
void onewifi_ovsdb_cache_update_cb(ovsdb_update_monitor_t *self);
ovsdb_cache_row_t* onewifi_ovsdb_cache_find_row_by_uuid(ovsdb_table_t *table, const char *uuid);
ovsdb_cache_row_t* onewifi_ovsdb_cache_find_row_by_key(ovsdb_table_t *table, const char *key);
ovsdb_cache_row_t* onewifi_ovsdb_cache_find_row_by_key2(ovsdb_table_t *table, const char *key2);
void* onewifi_ovsdb_cache_find_by_uuid(ovsdb_table_t *table, const char *uuid);
void* onewifi_ovsdb_cache_find_by_key(ovsdb_table_t *table, const char *key);
void* onewifi_ovsdb_cache_find_by_key2(ovsdb_table_t *table, const char *key2);
void* onewifi_ovsdb_cache_get_by_uuid(ovsdb_table_t *table, const char *uuid, void *record);
void* onewifi_ovsdb_cache_get_by_key(ovsdb_table_t *table, const char *key, void *record);
void* onewifi_ovsdb_cache_get_by_key2(ovsdb_table_t *table, const char *key2, void *record);
int onewifi_ovsdb_cache_upsert(ovsdb_table_t *table, void *record);
int onewifi_ovsdb_cache_upsert_get_uuid(ovsdb_table_t *table, void *record, ovs_uuid_t *uuid);
int onewifi_ovsdb_cache_pre_fetch(ovsdb_table_t *table, char *key);

#ifdef __cplusplus
}
#endif

#endif /* OVSDB_CACHE_H_INCLUDED */
