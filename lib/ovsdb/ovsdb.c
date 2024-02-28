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

#include <stdarg.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <netinet/in.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <jansson.h>

#include <ev.h>

#include "ds_tree.h"
#include "log.h"
#include "os.h"
#include "os_socket.h"
#include "ovsdb.h"
#include "json_util.h"

/*****************************************************************************/

#define MODULE_ID LOG_MODULE_ID_OVSDB

#define MAX_BUFFER_SIZE     (256*1024)
#define CHUNK_SIZE          (8*1024)
// typically ovs messages are below 4k, occasionally they are 6k, rarely more than 8k

#define OVSDB_SLEEP_TIME             1
#define OVSDB_WAIT_TIME              30   /* in s (0 = infinity) */

/*****************************************************************************/

/*global to avoid any potential issues with stack */
//struct ev_io wovsdb;
//const char *ovsdb_comment = NULL;

//int json_rpc_fd = -1;

//it's should be embedded in monitor transact
static int json_update_monitor_id = 0;

/* JSON-RPC handler list */
static ds_key_cmp_t rpc_response_handler_cmp;
ds_tree_t json_rpc_handler_list = DS_TREE_INIT(rpc_response_handler_cmp, struct rpc_response_handler, rrh_node);

/* JSON-RPC update handler list */
static ds_key_cmp_t rpc_update_handler_cmp;
ds_tree_t json_rpc_update_handler_list = DS_TREE_INIT(rpc_update_handler_cmp, struct rpc_response_handler, rrh_node);

/******************************************************************************
 *  PROTECTED declarations
 *****************************************************************************/

static bool onewifi_ovsdb_process_recv(json_t *js);
static bool onewifi_ovsdb_process_event(json_t *js);
static bool onewifi_ovsdb_process_result(json_t *id, json_t *js);
static bool onewifi_ovsdb_process_error(json_t *id, json_t *js);
static bool onewifi_ovsdb_process_update(json_t *jsup);
static bool onewifi_ovsdb_rpc_callback(int id, bool is_error, json_t *jsmsg);

static void onewifi_cb_ovsdb_read(struct ev_loop *loop, struct ev_io *watcher, int revents);
static bool onewifi_cb_ovsdb_read_json(char *buffer);

/******************************************************************************
 *  PROTECTED definitions
 *****************************************************************************/

/* on-connection callback */
static void onewifi_cb_ovsdb_read(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
    ssize_t nr = 0;
    size_t ovs_buffer_size = 3*CHUNK_SIZE; /* 24kb */
    char *ovs_buffer = NULL;

    if (EV_ERROR & revents) {
        LOG(ERR,"%s:got invalid event\n",__func__);
        return;
    }

    ovs_buffer = (char *)calloc(1,ovs_buffer_size);
    if(!ovs_buffer) {
        LOG(ERR,"%s:Error in calloc\n",__func__);
        return;
    }

    // Receive message from client socket
    nr = recv(watcher->fd, ovs_buffer, ovs_buffer_size, 0);

    if((nr > 0) && ((size_t )nr == ovs_buffer_size)) {
        LOG(ERR,"%s:Recv Buffer is not sufficient ,received bytes=%zu\n",__func__,nr);
        free(ovs_buffer);
        return;
    }
    else if (nr == 0) {
        LOG(INFO, "%s:OVSDB read: EOF -- closing connection\n",__func__);
        goto error;
    }
    else if (nr < 0) {
        LOG(ERR, "%s:OVSDB read: error -- closing connection.\n",__func__);
        goto error;
    }

    ovs_buffer[nr] = '\0';
    if (!onewifi_cb_ovsdb_read_json(ovs_buffer))
    {
        LOG(WARNING, "%s:OVSDB read: Error parsing JSON.",__func__);
    }

    free(ovs_buffer);
    return;

error:
    /*
     * Restart the connection and clear the buffer on errors
     */
    // peer closed, stop watching, close socket
    free(ovs_buffer);
    ev_io_stop(loop, watcher);
    close(watcher->fd);
#if 0
    /* try to restart connection */
    int retry = 0;
    while (retry < 3)
    {
        bool ret = onewifi_ovsdb_init_loop(sock_path, loop);
        if ((ret == false) && (retry >= 2) && (nr == 0))
        {
            if (!strcmp(ovsdb_comment, "DM"))
            {
                /* ovsdb-server crashed -> execute the restart script */
                LOGEM("Can't connect to ovsdb-server -> restarting managers");
                target_managers_restart();
            }
        }
        sleep(1);
        retry++;
    }
#endif
    return;
}

static bool onewifi_cb_ovsdb_read_json(char *buf)
{
    char *next;
    json_error_t jerror;

    json_t *js = NULL;
    char *str = buf;

    while ((next = json_split(str)) != NULL)
    {
        if (next == JSON_SPLIT_ERROR)
        {
            LOG(ERR, "OVSDB RECV: Error parsing input string.::json=%s", buf);
            return false;
        }

        /*
         * Note that "next" points to the end of the message, which might be the beginning of the next message. Pad it with \0, but
         * remember the character that we overwrote. We will patch it back once we're json_dumps() has finished.
         */
        char save = *next;
        *next = '\0';

        LOG(DEBUG, "JSON RECV: %s\n", str);
        /*
         * Convert string to json_t
         */
        js = json_loads(str, 0, &jerror);
        if (js == NULL)
        {
            LOG(ERR, "OVSB RECV: Error processing JSON message.::json=%s", str);
            return false;
        }

        /* Patch it back */
        *next = save;

        if (!onewifi_ovsdb_process_recv(js))
        {
            char *msg;

            msg = json_dumps(js, JSON_COMPACT);
            LOG(ERR, "JSON-RPC: Error processing message.::json=%s", msg);
            json_free(msg);
        }

        json_decref(js);

        /* Move buffer to the next one */
        str = next;
    }

    /* Shift the buffer */
    memmove(buf, str, strlen(str) + 1);

    return true;
}

/**
 * Dispatch message JSON-RPC
 */
bool onewifi_ovsdb_process_recv(json_t *jsrpc)
{
    json_t *jsid;
    json_t *jst;

   /*
     * 3 options remaining for this message:
     *      - synchronous method call (not supported);
     *      - synchronous method result
     *      - synchronous method error
     */

    /* 1) Check if it's a method */
    jst = json_object_get(jsrpc, "method");
    if (jst != NULL && !json_is_null(jst))
    {
        const char * method;
        method = json_string_value(jst);
        if (!strcmp(method, "update")) {
            return onewifi_ovsdb_process_update(jsrpc);
        } else  {
            LOG(ERR, "Received unsupported SYNCHRONOUS method request.::method=%s", json_string_value(jst));
            return false;
        }
    }

    /* Check if we have an id */
    jsid = json_object_get(jsrpc, "id");
    if (jsid == NULL || json_is_null(jsid))
    {
        /* We dont have an ID, at this point this must be an EVENT */
        return onewifi_ovsdb_process_event(jsrpc);
    }

    /* 2) Check if we have a result response */
    jst = json_object_get(jsrpc, "result");
    if (jst != NULL && !json_is_null(jst))
    {
        /* Result message */
        return onewifi_ovsdb_process_result(jsid, jst);
    }

    /* 3) CHeck if we have an error response */
    jst = json_object_get(jsrpc, "error");
    if (jst != NULL && !json_is_null(jst))
    {
       /* Error message */
        return onewifi_ovsdb_process_error(jsid, jst);
    }

    /* Nothing looks familiar, lets drop it */
    LOG(ERR, "Received unsupported JSON-RPC message, discarding.");
    return false;
}

/**
 * Process signle JSON-RPC "event" message (asynchronous method call)
 */
bool onewifi_ovsdb_process_event(json_t *js)
{
    (void)js;
    return false;
}

/**
 * Process single JSON-RPC "result" message
 */
bool onewifi_ovsdb_process_result(json_t *jsid, json_t *jsresult)
{
    int id;

    /* The current implementation supports only integer IDs */
    if (!json_is_integer(jsid))
    {
        LOG(ERR, "Received non-integer id in JSON-RPC.");
        return false;
    }

    id = json_integer_value(jsid);

    /*
     * Lookup result handler
     */
    return onewifi_ovsdb_rpc_callback(id, false, jsresult);
}

/**
 * Process single JSON-RPC "error" message
 */
bool onewifi_ovsdb_process_error(json_t *jsid, json_t *jserror)
{
    int id;

    /* The current implementation supports only integer IDs */
    if (!json_is_integer(jsid))
    {
        LOG(ERR, "Received non-integer id in JSON-RPC.");
        return false;
    }

    id = json_integer_value(jsid);

    /*
     * Lookup result handler
     */
    return onewifi_ovsdb_rpc_callback(id, true, jserror);
}

int onewifi_ovsdb_register_update_cb(ovsdb_update_process_t *fn, void *data)
{
    struct rpc_update_handler *rh;

    rh = malloc(sizeof(struct rpc_update_handler));

    if (rh == NULL)
    {
        LOG(ERR, "JSON RPC: Unable to allocate update handler!");
        return -1;
    }

    ++json_update_monitor_id;

    /* Not thread-safe */
    rh->rrh_id = json_update_monitor_id;
    rh->rrh_callback = fn;
    rh->data = data;

    ds_tree_insert(&json_rpc_update_handler_list, rh, &rh->rrh_id);

    return json_update_monitor_id;
}

int onewifi_ovsdb_unregister_update_cb(int mon_id)
{
    struct rpc_update_handler *rh;

    rh = ds_tree_find(&json_rpc_update_handler_list, &mon_id);

    ds_tree_remove(&json_rpc_update_handler_list, rh);

    return 0;
}

/**
 * Process single JSON-RPC "update" message
 */
static bool onewifi_ovsdb_process_update(json_t *jsup)
{
    int mon_id = 0;
    struct rpc_update_handler *rh;

    mon_id = json_integer_value(json_array_get(json_object_get(jsup,"params"),0));

    rh = ds_tree_find(&json_rpc_update_handler_list, &mon_id);
    if (rh == NULL)
    {
        LOG(NOTICE, "JSON-RPC Update: Callback not found for monitor.::mon_id=%d\n", mon_id);
        return false;
    }

    rh->rrh_callback(mon_id, jsup, rh->data);

    return true;
}

bool onewifi_ovsdb_rpc_callback(int id, bool is_error, json_t *jsmsg)
{
    struct rpc_response_handler *rh;

    rh = ds_tree_find(&json_rpc_handler_list, &id);
    if (rh == NULL)
    {
        LOG(NOTICE, "JSON-RPC: Callback not found for id.::mon_id=%d\n", id);
        return false;
    }

    /*
     * Filter out empty responses from jsmsg generated by "op":"comment" requests -- it would too much hassle
     * to handle the case where the comment might be present or not in every single response parser.
     */
    if (/*ovsdb_comment != NULL &&*/ json_is_array(jsmsg))
    {
        json_t *jscomm = json_array_get(jsmsg, 0);

        /* If js is an object and its empty, remove it */
        if (json_is_object(jscomm) && json_object_size(jscomm) == 0)
        {
            json_array_remove(jsmsg, 0);
        }
    }

    rh->rrh_callback(id, is_error, jsmsg, rh->data);

    /* Remove callback from the tree */
    ds_tree_remove(&json_rpc_handler_list, rh);
    free(rh);

    return true;
}

/**
 * Compassion function used by the tree data structure -- simple string compare of the method member
 */
static int rpc_response_handler_cmp(void *a, void *b)
{
    if (*(int *)a < *(int *)b) return -1;
    if (*(int *)a > *(int *)b) return 1;

    return 0;
}

/**
 * Compassion function used by the tree data structure -- simple string compare of the method member
 */
static int rpc_update_handler_cmp(void *a, void *b)
{
    if (*(int *)a < *(int *)b) return -1;
    if (*(int *)a > *(int *)b) return 1;

    return 0;
}

/******************************************************************************
 *  PUBLIC definitions
 *****************************************************************************/
bool onewifi_ovsdb_init_loop(int ovsdb_fd, struct ev_io *watcher, struct ev_loop *loop)
{
        
	ev_io_init(watcher, onewifi_cb_ovsdb_read, ovsdb_fd, EV_READ);
    ev_io_start(loop, watcher);

	return true;
}

#if 0
bool ovsdb_init(const char *sock_path, struct ev_loop *loop, const char *name)
{
    return onewifi_ovsdb_init_loop(sock_path, loop, name);
}

bool onewifi_ovsdb_init_loop(const char *sock_path, struct ev_loop *loop)
{
    bool success = false;

    if (loop == NULL) {
        loop = ev_default_loop(0);
    }

    json_rpc_fd = onewifi_ovsdb_conn(sock_path);

    if (json_rpc_fd > 0)
    {
        LOG(NOTICE, "OVSDB connection established");

        ev_io_init(&wovsdb, onewifi_cb_ovsdb_read, json_rpc_fd, EV_READ);
        ev_io_start(loop, &wovsdb);

        success = true;
    }
    else
    {
        LOG(ERR, "Error starting OVSDB client.::reason=%d", json_rpc_fd);
    }

#if 0
    if (name != NULL)
    {
        ovsdb_comment = name;
    }
#endif

    return success;
}

bool ovsdb_ready(const char *sock_path, struct ev_loop *loop)
{
    /* Wait for the OVSDB to initialize */
    int wait = OVSDB_WAIT_TIME;
    while (wait >= 0)
    {
        if (onewifi_ovsdb_init_loop(sock_path, loop)) {
            return true;
        }
        LOG(INFO, "OVSDB not ready. Need to Zzzz ...");

sleep:
        if (OVSDB_WAIT_TIME) {
            wait -= OVSDB_SLEEP_TIME;
        }

        sleep (OVSDB_SLEEP_TIME);
    };

    return false;
}
#endif

#if 0
bool ovsdb_stop(void)
{
    return ovsdb_stop_loop(NULL);
}

bool ovsdb_stop_loop(int fd, struct ev_loop *loop)
{
    if (loop == NULL) {
        loop = ev_default_loop(0);
    }

    ev_io_stop(loop, &wovsdb);

    close(fd);

    fd = -1;

    LOG(NOTICE, "Closing OVSDB connection.");

    return true;
}
#endif
