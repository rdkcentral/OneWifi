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

/*
 * ===========================================================================
 *  Support module for handling OVS update requests
 * ===========================================================================
 */
#define MODULE_ID LOG_MODULE_ID_OVSDB

#include "log.h"
#include "util.h"
#include "json_util.h"
#include "ovsdb.h"
#include "ovsdb_update.h"

/*
 * ===========================================================================
 *  OVSDB Update response parser
 * ===========================================================================
 */

/*
 * Start parsing an OVS update request -- jupdate.
 *
 * NOTE, the first element is retrieved by calling ovsdb_update_next()!
 */
bool onewifi_ovsdb_update_parse_start(ovsdb_update_parse_t *self, json_t *jtable)
{
    if (!json_is_object(jtable))
    {
        LOG(ERR, "UPDATE: Update notification is not an object.");
        return false;
    }

    self->up_jtable = jtable;
    self->up_itable = NULL;

    return true;
}

/**
 * Move to the next update request
 */
bool onewifi_ovsdb_update_parse_next(ovsdb_update_parse_t *self)
{
    if (self->up_itable != NULL)
    {
        goto parse_next;
    }

    self->up_itable = json_object_iter(self->up_jtable);
    /*
     * Iterate over tables, tables are in the following format
     * { "TABLE": { ... }, "TABLE": { .... } }
     */
    while (self->up_itable != NULL)
    {
        /*
         * Parse rows, which are in the following format:
         *
         * "TABLE" :
         * {
         *      "UUID":
         *      {
         *          "old": { ... },     On delete or modify
         *          "new": { ... }      Not on delete
         *      }
         * },
         * "TABLE" :
         * ...
         */
        self->up_jrow = json_object_iter_value(self->up_itable);
        if (!json_is_object(self->up_jrow))
        {
            LOG(ERR, "UPDATE: Row is not an object.");
            return false;
        }

        self->up_irow = json_object_iter(self->up_jrow);
        while (self->up_irow != NULL)
        {
            /* UUID is the key of the table */
            self->up_uuid = json_object_iter_key(self->up_irow);

            json_t *jdata = json_object_iter_value(self->up_irow);
            if (!json_is_object(jdata))
            {
                LOG(ERR, "UPDATE: Row data is not an object!");
                return false;
            }

            /*
             * The data object is in the following format:
             *
             * "UUID" :
             * {
             *      "old": { ...we ignore this part... },
             *      "new": { ...new data that we want to insert or empty on delete... }
             * }
             */

            /* No need to error check, if up_jdata is NULL it means that the row was deleted */
            self->up_jnew = json_object_get(jdata, "new");
            /* Same as above ... */
            self->up_jold = json_object_get(jdata, "old");

            /* Yield at current position */
            return true;
parse_next:

            /* Move to next row */
            self->up_irow = json_object_iter_next(self->up_jrow, self->up_irow);
        }

        /* Move to next element */
        self->up_itable = json_object_iter_next(self->up_jtable, self->up_itable);
    }

    return false;
}

/*
 * ===========================================================================
 *  OVSDB Update Monitor
 * ===========================================================================
 */

static ovsdb_update_process_t   onewifi_ovsdb_update_monitor_call_cbk;
static json_rpc_response_t      onewifi_ovsdb_update_monitor_resp_cbk;
static void                     onewifi_ovsdb_update_monitor_process(ovsdb_update_monitor_t *self, json_t *js);
static void                     ovsdb_update_monitor_error(ovsdb_update_monitor_t *self);

/*
 * onewifi_ovsdb_update_monitor(_ex) -- Start monitoring an OVS table. For each update to the table, call the
 * callback function.
 *
 * Parameters:
 *
 *      self        -- context
 *      callback    -- the update function handler, this will be called for every update
 *      mon_table   -- the table to be monitored
 *      mon_flags   -- monitor flags if 0, OTM_ALL is assumed
 *      colc        -- number of columns in colv array, can be 0
 *      colv        -- array of selected columns to be monitored, can be NULL if colc is also 0
 *
 * The problem with OVS updates is that "initial" requests are actual respones
 * to the monitor RPC requests, while insert/modify/delete update notifications
 * are JSON RPC calls from OVS to us! In order to handle all 4 types, we must
 * handle both the monitor RPC response and update RPC call!
 */
bool onewifi_ovsdb_update_monitor_ex(int ovsdb_fd,
        ovsdb_update_monitor_t *self,
        ovsdb_update_cbk_t *callback,
        char *mon_table,
        int mon_flags,
        int colc,
        char *colv[])
{
    /* Initialize the ovsdb_update_t structure */
    memset(self, 0, sizeof(*self));
    self->mon_cb = callback;

    /* Regiter update handler */
    int monid = onewifi_ovsdb_register_update_cb(
            onewifi_ovsdb_update_monitor_call_cbk,
            self);

    if (!onewifi_ovsdb_monit_call_argv(ovsdb_fd,
            onewifi_ovsdb_update_monitor_resp_cbk,
            self,
            monid,
            mon_table,
            mon_flags,
            colc,
            colv))
    {
        LOG(ERR, "UPDATE: Error sending monitor request.");
        return false;
    }
    LOG(INFO, "OVSDB monitor %s", mon_table);

    return true;
}

/*
 * Shorthand wrapper around ovsb_update_monitor_ex() -- see that function for explanation of parameters.
 */
bool onewifi_ovsdb_update_monitor(int ovsdb_fd,
        ovsdb_update_monitor_t *self,
        ovsdb_update_cbk_t *callback,
        char *table,
        int monit_flags)
{
    return onewifi_ovsdb_update_monitor_ex(ovsdb_fd, self, callback, table, monit_flags, 0, NULL);
}

/*
 * This is the callback for onewifi_ovsdb_register_update_cb()
 */
void onewifi_ovsdb_update_monitor_call_cbk(int id, json_t *js, void *data)
{
    (void)id;

    const char  *method;
    json_t      *jparams;
    json_t      *jtable;

    ovsdb_update_monitor_t *self = data;

    /* Check if the "method" is really "update" */
    method = json_string_value(json_object_get(js, "method"));
    if (method == NULL)
    {
        LOG(ERR, "UPDATE: No \"method\" field in JSON-RPC call.");
        goto error;
    }


    if (strcmp(method, "update") != 0)
    {
        LOG(ERR, "UPDATE: Method is not \"update\": method=%s", method);
        goto error;
    }

    /* Inspect the "parameters" field */
    jparams = json_object_get(js, "params");
    if (jparams == NULL)
    {
        LOG(ERR, "UPDATE: No \"params\" field in JSON.");
        goto error;
    }

    /* The params array is in the following format: [ value, {} ] */
    if (json_array_size(jparams) != 2)
    {
        LOG(ERR, "UPDATE: Incorrect format for \"params\".");
        goto error;
    }

    /* Initialize the object iterator for the 2nd argument in the list */
    jtable = json_array_get(jparams, 1);

    onewifi_ovsdb_update_monitor_process(self, jtable);
    return;

error:
    ovsdb_update_monitor_error(self);
}

/*
 * This function is used as the callback for ovsdb_monit_call()
 */
void onewifi_ovsdb_update_monitor_resp_cbk(int id, bool is_error, json_t *js, void *data)
{
    (void)id;

    ovsdb_update_monitor_t *self = data;

    /* Pass down any errors we might have received */
    if (is_error)
    {
        LOG(ERR, "UPDATE: Response JSON-RPC returned error (rpc_id = %d).", id);
        ovsdb_update_monitor_error(self);
        return;
    }

    /* Process the message */
    onewifi_ovsdb_update_monitor_process(self, js);
}

/*
 * Process an update request
 */
void onewifi_ovsdb_update_monitor_process(ovsdb_update_monitor_t *self, json_t *js)
{
    ovsdb_update_parse_t parse;
    MEMZERO(parse);

    /* Start parsing the message */
    if (!onewifi_ovsdb_update_parse_start(&parse, js))
    {
        LOG(ERR, "UPDATE: Error parsing OVSDB uppdate notification.");
        ovsdb_update_monitor_error(self);
        return;
    }

    while (onewifi_ovsdb_update_parse_next(&parse))
    {
        self->mon_type      = OVSDB_UPDATE_ERROR;
        self->mon_table     = onewifi_ovsdb_update_parse_get_table(&parse);
        self->mon_uuid      = onewifi_ovsdb_update_parse_get_uuid(&parse);
        self->mon_json_new  = onewifi_ovsdb_update_parse_get_new(&parse);
        self->mon_json_old  = onewifi_ovsdb_update_parse_get_old(&parse);

        /* Figure out the type of the event */
        if (self->mon_json_old == NULL && self->mon_json_new != NULL)
        {
            self->mon_type = OVSDB_UPDATE_NEW;
        }
        else if (self->mon_json_old != NULL && self->mon_json_new != NULL)
        {
            self->mon_type = OVSDB_UPDATE_MODIFY;
        }
        else if (self->mon_json_old != NULL && self->mon_json_new == NULL)
        {
            self->mon_type = OVSDB_UPDATE_DEL;
        }

        /*
         * Somebody thought it would be a good idea to skip on the _uuid fields,
         * as we already have it as the key. Our parser was modified to handle this
         * special case. However, in order to avoid copying the uuid to the structure
         * each time, we insert it here. This way the parser will take care of it
         * for us.
         */
        json_t *juuid = json_array();
        if (juuid == NULL)
        {
            LOG(ERR, "UPDATE: Error creating array for UUID.");
            continue;
        }

        do
        {
            /*
             * The UUID is an array, where the first element is the "uuid" string and the second element
             * is the actual uuid.
             */
            if (json_array_append_new(juuid, json_string("uuid")) != 0)
            {
                LOG(ERR, "UPDATE: Error appending string \"uuid\"");
                break;
            }

            if (json_array_append_new(juuid, json_string(self->mon_uuid)) != 0)
            {
                LOG(ERR, "UPDATE: Error appending UUID.");
                break;
            }

            if (self->mon_json_new != NULL)
            {
                if (json_object_set(self->mon_json_new, "_uuid", juuid) != 0)
                {
                    LOG(ERR, "UPDATE: Error appending UUID to NEW.");
                    break;
                }
            }

            if (self->mon_json_old != NULL)
            {
                if (json_object_set(self->mon_json_old, "_uuid", juuid) != 0)
                {
                    LOG(ERR, "UPDATE: Error appending UUID to OLD.");
                    break;
                }
            }

            self->mon_cb(self);
        }
        while (false);

        json_decref(juuid);
    }
}


void ovsdb_update_monitor_error(ovsdb_update_monitor_t *self)
{
    self->mon_type = OVSDB_UPDATE_ERROR;
    self->mon_table = NULL;
    self->mon_uuid = NULL;
    self->mon_json_new = NULL;
    self->mon_json_old = NULL;

    self->mon_cb(self);
}

// return true if a field has changed in an update
bool onewifi_ovsdb_update_changed(ovsdb_update_monitor_t *self, char *field)
{
    bool changed = false;
    char *tname = "UNK";
    json_t *j_old;
    json_t *j_new;
    char v_old[256] = "";
    char v_new[256] = "";
    switch (self->mon_type)
    {
        // on NEW and DEL mark as changed
        case OVSDB_UPDATE_NEW:
            tname = "NEW";
            changed = true;
            break;
        case OVSDB_UPDATE_DEL:
            tname = "DEL";
            changed = true;
            break;
        case OVSDB_UPDATE_MODIFY:
            // on MODIFY mark as changed if it exists in old
            // ovsdb will always send old values for fields that changed
            tname = "MOD";
            j_old = json_object_get(self->mon_json_old, field);
            if (j_old != NULL)
            {
                changed = true;
                j_new = json_object_get(self->mon_json_new, field);
                json_gets(j_old, v_old, sizeof(v_old), JSON_ENCODE_ANY | JSON_COMPACT);
                json_gets(j_new, v_new, sizeof(v_new), JSON_ENCODE_ANY | JSON_COMPACT);
            }
            break;
        case OVSDB_UPDATE_ERROR:
            tname = "ERR";
        default:
            break;
    }
    if (changed)
    {
        LOG(TRACE, "update '%s' changed: %s '%s.%s' '%s' => '%s'",
                tname, str_bool(changed),
                self->mon_table, field,
                v_old, v_new);
    }
    else
    {
        LOG(TRACE, "update '%s' changed: %s '%s.%s'",
                tname, str_bool(changed),
                self->mon_table, field);
    }
    return changed;
}

char* onewifi_ovsdb_update_type_to_str(ovsdb_update_type_t update_type)
{
    switch (update_type) {
        case OVSDB_UPDATE_DEL:
            return "remove";
        case OVSDB_UPDATE_NEW:
            return "insert";
        case OVSDB_UPDATE_MODIFY:
            return "modify";
        default:
            LOGE("Invalid ovsdb type enum %d", update_type);
            break;
    }
    return NULL;
}
