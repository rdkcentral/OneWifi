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

/* =========================================================================
 * Synchronous access to OVSDB - use as alternative to the ASYNC calls when
 * we need simpler access methods.
 * ========================================================================= */

#include <stdint.h>
#include <unistd.h>
#include <jansson.h>
#include <string.h>
#include <errno.h>

#include "os_socket.h"
#include "log.h"
#include "json_util.h"

#include "ovsdb.h"
#include "ovsdb_priv.h"

/* Generate JSON parsers using PJS */
#include "ovsdb_jsonrpc.pjs.h"
#include "pjs_gen_c.h"
#include "wifi_util.h"
#include "wifi_ctrl.h"


/* OVSDB response buffers can be HUGE */
static char ovsdb_write_buf[256*1024];

#define PERSISTENT_DB_BACKUP      "/opt/secure/wifi/rdkb-wifi.db"
#define PERSISTENT_DB_BACKUP_TMP  PERSISTENT_DB_BACKUP".tmp"
#define UNSECURE_DB               "/nvram/wifi/rdkb-wifi.db"

#define BACKUP_SNAPSHOT_CMD       "ovsdb-client backup " OVSDB_DEF_DB " > " PERSISTENT_DB_BACKUP_TMP
#define BACKUP_SNAPSHOT_CHECK_CMD "ovsdb-tool db-version " PERSISTENT_DB_BACKUP_TMP
#define BACKUP_SAVE_CMD           "mv " PERSISTENT_DB_BACKUP_TMP " " PERSISTENT_DB_BACKUP
#define BACKUP_CHECK_CMD          "ovsdb-tool db-version " PERSISTENT_DB_BACKUP
#define UNSECURE_DB_SAVE_CMD      "cp " PERSISTENT_DB_BACKUP " " UNSECURE_DB
#define UNSECURE_DB_CHECK_CMD     "ovsdb-tool db-version " UNSECURE_DB

/**
 * Callback for json_dump_callback() -- called from ovsb_write_s()
 *
 * Per Jansson documentation, this function shall return -1 on error or 0 on
 * success
 */
int ovsdb_sync_write_fn(const char *buf, size_t sz, void *self)
{
    int     ovs_fd = (long)self;
    ssize_t rc;

    rc = write(ovs_fd, buf, sz);
    if (rc <= 0)
    {
        LOGE("Synchronous write() to OVSDB failed: %s", strerror(errno));
        return -1;
    }

    return 0;
}

static bool exec_cmd(const char *cmd)
{
    if (!cmd || !cmd[0]) {
        LOGE("%s: No command provided", __func__);
        return false;
    }

    int status = system(cmd);
    if (status == 0) {
        return true;
    }
    else if (WIFEXITED(status)) {
        LOGE("%s: Command '%s' exited with status=%d", __func__, cmd, WEXITSTATUS(status));
        wifidb_print("%s:%d Command '%s' exited with status=%d\n", __func__, __LINE__, cmd,
            WEXITSTATUS(status));
    }
    else {
        LOGE("%s: Command '%s' failed or interrupted", __func__, cmd);
        wifidb_print("%s:%d Command '%s' failed, errno=%d (%s)\n", __func__, __LINE__, cmd, errno,
            strerror(errno));
    }

    return false;
}

static bool is_ovsdb_changed(const json_t *jsdata)
{
    bool status = true;
    size_t list_size;

    json_t *trans_obj = json_object_get(jsdata, "params");
    if (!json_is_array(trans_obj) || !(list_size = json_array_size(trans_obj)))
    {
        wifidb_print("%s: Wrong param object\n", __func__);
        return status;
    }

    status = false;
    for (int i = 0; i < (int)list_size; i++)
    {
        json_t *js = json_array_get(trans_obj, i);
        if (!json_is_object(js))
            continue;

        json_t *trans_type = json_object_get(js, "op");
        if (json_is_string(trans_type))
        {
            const char *oper_type = json_string_value(trans_type);
            if (strcmp(oper_type, "select") != 0)
            {
                status = true;
                break;
            }
        }
    }

    return status;
}

static pthread_mutex_t backup_lock;
static bool ovsdb_backup()
{
    bool status = false;

    if (!is_db_consolidated()) {
        LOGE("%s: Database consolidation is not supported", __func__);
        return status;
    }

    pthread_mutex_lock(&backup_lock);
    /*  This command cannot be applied directly for writing to nvram DB,
        because the command is heavy and the fail (e.g. reboot) may happen
        in the middle of command run. So to avoid persistent DB corruction,
        need to write to the temporary file on the same filesystem first,
        then use mv to a persistent DB file, which is less probably be interrupted
     */
    status = exec_cmd(BACKUP_SNAPSHOT_CMD) &&
        exec_cmd(BACKUP_SNAPSHOT_CHECK_CMD) &&
        exec_cmd(BACKUP_SAVE_CMD) &&
        exec_cmd(BACKUP_CHECK_CMD) &&
        exec_cmd(UNSECURE_DB_SAVE_CMD) &&
        exec_cmd(UNSECURE_DB_CHECK_CMD);

    pthread_mutex_unlock(&backup_lock);

    return status;
}

static pthread_mutex_t ovsdb_lock;
/**
 * Synchronous write to OVSDB -- similar to ovsdb_write() except it doesn't require a callback
 *
 * This function opens a new connection to OVSDB for each request. In the future, if needed, this
 * can be changed to use a timer to close the connection after a period of inactivity.
 */

json_t *ovsdb_write_s(char *ovsdb_sock_path, json_t *jsdata)
{
    int     ovs_fd = -1;
    json_t *retval = NULL;

    wifi_db_t *g_wifidb;
    g_wifidb = (wifi_db_t *)get_wifidb_obj();

    pthread_mutex_lock(&ovsdb_lock);
    if (g_wifidb->wifidb_wfd < 0) {
        /* Initiate new connection to OVSDB if current connection is inactive*/
        g_wifidb->wifidb_wfd = onewifi_ovsdb_conn(ovsdb_sock_path);
        if (g_wifidb->wifidb_wfd < 0)
        {
            LOGE("SYNC: Error initiating connection to OVSDB.");
            wifidb_print("SYNC: Error initiating connection to OVSDB.\r\n");
            goto error;
        }
    }
    ovs_fd = g_wifidb->wifidb_wfd;

    LOGD("SYNC: Writing sync operation: %s", json_dumps_static(jsdata, 0));
    if (json_dump_callback(jsdata, ovsdb_sync_write_fn, (void *)(intptr_t)ovs_fd, JSON_COMPACT) != 0)
    {
        LOGE("SYNC: Error during sync write to OVSDB: %s", strerror(errno));
        wifidb_print("Input(writing) operation to socket jsdata: %s\r\n", json_dumps_static(jsdata, 0));
        wifidb_print("SYNC: Error during sync write to OVSDB: %s\r\n", strerror(errno));
        goto error;
    }

    /*
        Each db transaction has 5 operation types:
        OTR_INSERT, OTR_SELECT, OTR_UPDATE, OTR_MUTATE, OTR_DELETE.
        The first is to get the table for the dedicated condition under the transaction.
        Other types aim to modify remote db.
        We must track it and perform the backup operations only for the db modifiers.
        Currently, the system uses OPER_SELECT massively to get current states and configs
        for each VAP's.
        This provokes a continuous backup even if the db wasn't changed.
    */
    if (is_ovsdb_changed(jsdata))
    {
        wifidb_print("Write done --- syncing database\n");
        if (is_db_backup_required())
        {
            bool backup_success = ovsdb_backup();
            wifidb_print("Backup database %s\n", backup_success ? "succeeded" : "failed");
        }
        else
        {
            wifidb_print("Backup database is not required\n");
        }
    }

    /* Read a response and return */
    size_t buflen = 0;
    ssize_t nr;

    while (buflen < sizeof(ovsdb_write_buf) - 1)
    {
        nr = read(ovs_fd, &ovsdb_write_buf[buflen], sizeof(ovsdb_write_buf) - 1 - buflen);
        if (nr <= 0)
        {
            /* Treat errors and short reads the same -- error while reading response. */
            LOGE("Sync: Short read or EOF while waiting for JSON response.");
            wifidb_print("Sync: Short read or EOF while waiting for JSON response.\r\n");
            goto error;
        }

        buflen += nr;

        ovsdb_write_buf[buflen] = '\0';

        char *res = json_split(ovsdb_write_buf);
        if (res == JSON_SPLIT_ERROR)
        {
            LOGE("Sync: Error parsing JSON-RPC response: %s\n", ovsdb_write_buf);
            wifidb_print("Sync: Error parsing JSON-RPC response: %s\r\n", ovsdb_write_buf);
            goto error;
        }

        if (res != NULL)
        {
            if (strlen(res))
                LOGW("Sync: trailing garbage found: '%s'", res);
            *res = 0;
            /* Success */
            break;
        }
    }
    json_error_t err;
    retval = json_loads(ovsdb_write_buf, 0, &err);
    if (retval == NULL)
    {
        LOGE("Sync: Error parsing OVSDB response (%s):\n%s", err.text, ovsdb_write_buf);
        wifidb_print("Sync: Error parsing OVSDB response (%s):\n%s\r\n", err.text, ovsdb_write_buf);
    }

error:
    pthread_mutex_unlock(&ovsdb_lock);
    return retval;
}

/**
 * Issue a synchronous request to OVSDB
 */
json_t *onewifi_ovsdb_method_send_s(const char *ovsdb_sock_path,
        ovsdb_mt_t mt,
        json_t * jparams)
{

    int     rpc_id = 0;
    char    *method = NULL;
    json_t  *js = NULL;
    json_t  *jres = NULL;
    json_t  *retval = NULL;

    switch (mt)
    {
        case MT_ECHO:
            method = "echo";
            break;

        case MT_MONITOR:
            method = "monitor";
            break;

        case MT_TRANS:
            method = "transact";
            break;

        default:
            LOG(ERR, "unknown method");
            json_decref(jparams);
            return false;
    }

    js = json_object();

    if (0 < json_object_set_new(js, "method", json_string(method)))
    {
        LOGE("Error adding method key.");
    }

    if (0 < json_object_set_new(js, "params", jparams))
    {
        LOGE("Error adding params array.");
        json_decref(jparams);
    }

    rpc_id = onewifi_ovsdb_jsonrpc_id_new();
    if (0 < json_object_set_new(js, "id", json_integer(rpc_id)))
    {
        LOGE("Error adding id key.");
    }

    jres = ovsdb_write_s((char *)ovsdb_sock_path, js);
    if (jres == NULL)
    {
        LOGE("Sync: Error sending OVSDB JSON-RPC request.");
        goto error;
    }

    struct rpc_response res;
    pjs_errmsg_t err;
    if (!rpc_response_from_json(&res, jres, false, err))
    {
        LOGE("Sync: Error parsing OVSDB response: %s", err);
        goto error;
    }

    if (res.id != rpc_id)
    {
        LOGE("Sync: JSON-RPC id mismatch: %d != %d", res.id, rpc_id);
        goto error;
    }

    if (res.error_exists)
    {
        LOGE("Sync: Error processing JSON-RPC response: code:%d message:%s\n",
                res.error.code,
                res.error.message);
        goto error;
    }

    /* Everything OK, return the result object */
    retval = json_object_get(jres, "result");

    /* Grab a reference to the retval object */
    json_incref(retval);

error:
    if (js != NULL) json_decref(js);
    if (jres != NULL) json_decref(jres);

    return retval;
}

/*
 * onewifi_ovsdb_tran_call_s() -- synchronous replacement for onewifi_ovsdb_tran_call()
 *
 * Returns:
 *      NULL - on error
 *      result - Returns the JSON-RPC result object
 *
 * Note:
 *  This function returns NULL only if the transport layer fails!
 *
 *  If the JSON RPC server returns an error, it *WILL RETURN A VALID RESPONSE*. The error message indication
 *  and message is contained within the JSON message.
 */
json_t *onewifi_ovsdb_tran_call_s(const char *ovsdb_sock_path,
        const char * table,
        ovsdb_tro_t oper,
        json_t * where,
        json_t * row)
{
    return onewifi_ovsdb_method_send_s(ovsdb_sock_path, MT_TRANS, ovsdb_tran_multi(NULL, NULL, table, oper, where, row));
}

/*
 * This function uses onewifi_ovsdb_method_send_s() to send a
 * transaction created with onewifi_ovsdb_tran_insert_with_parent()
 */
bool onewifi_ovsdb_insert_with_parent_s(const char *ovsdb_sock_path,
								char * table,
                                json_t * row,
                                char * parent_table,
                                json_t * parent_where,
                                char * parent_column)
{
    json_t *tran = onewifi_ovsdb_tran_insert_with_parent(ovsdb_sock_path,
                                            table,
                                            row,
                                            parent_table,
                                            parent_where,
                                            parent_column);

    json_t *resp = onewifi_ovsdb_method_send_s(ovsdb_sock_path, MT_TRANS, tran);

    json_decref(resp);
    return true;
}


/*
 * This function builds a uuid list from where clause,
 * then uses onewifi_ovsdb_method_send_s() to send a * transaction
 * created with onewifi_ovsdb_tran_delete_with_parent()
 */
json_t* onewifi_ovsdb_delete_with_parent_res_s(const char *ovsdb_sock_path,
								const char * table,
                                json_t *where,
                                const char * parent_table,
                                json_t * parent_where,
                                const char * parent_column)
{
    json_t *result;
    json_t *uuids;
    json_t *uuid;
    json_t *rows;
    json_t *tran;
    json_t *resp;
    json_t *row;
    size_t index;

    result = onewifi_ovsdb_tran_call_s(ovsdb_sock_path, table, OTR_SELECT, where, NULL);
    if (!result) {
        json_decref(parent_where);
        return false;
    }

    rows = json_object_get(json_array_get(result, 0), "rows");
    if (!rows || json_array_size(rows) < 1) {
        json_decref(result);
        json_decref(parent_where);
        return false;
    }

    uuids = json_array();
    json_array_foreach(rows, index, row) {
        if (!(uuid = json_object_get(row, "_uuid"))) {
            continue;
        }

        json_array_append(uuids, uuid); // Inc ref...
    }
    json_decref(result);

    tran = onewifi_ovsdb_tran_delete_with_parent(ovsdb_sock_path,
										table,
                                         uuids,
                                         parent_table,
                                         parent_where,
                                         parent_column);

    resp = onewifi_ovsdb_method_send_s(ovsdb_sock_path, MT_TRANS, tran);

    return resp;
}


bool onewifi_ovsdb_delete_with_parent_s(const char *ovsdb_sock_path,
								char * table,
                                json_t *where,
                                char * parent_table,
                                json_t * parent_where,
                                char * parent_column)
{
    json_t *resp;

    resp = onewifi_ovsdb_delete_with_parent_res_s(ovsdb_sock_path, table,
            where, parent_table, parent_where, parent_column);

    json_decref(resp);
    return true;
}
