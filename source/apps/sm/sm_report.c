/************************************************************************************
  If not stated otherwise in this file or this component's LICENSE file the
  following copyright and licenses apply:

  Copyright 2023 RDK Management

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
#include "sm_report.h"
#include "scheduler.h"
#include "sm_utils.h"
#include "wifi_mgr.h"
#include <const.h>
#include "dppline.h"
#include <qm_conn.h>

#define SM_TO_QM_SEND_INTERVAL_SEC (5)
#define SM_SURVEY_REPORT_COUNTER_INTERVAL_SEC (24 * 60 * 60)

typedef struct {
    stats_cfg_id_t  stats_cfg_id;
    wifi_app_t      *app;
} sm_report_callback_arg_t;

sm_client_cache_t    sm_client_report_cache[MAX_NUM_RADIOS];
sm_survey_cache_t    sm_survey_report_cache[MAX_NUM_RADIOS];
sm_neighbor_cache_t  sm_neighbor_report_cache[MAX_NUM_RADIOS];

int send_qm_task_id = -1;
int reports_counter_task_id = -1;


static bool sm_mqtt_publish(long mlen, void *mbuf)
{
    qm_response_t res;
    bool ret;
    ret = qm_conn_send_stats(mbuf, mlen, &res);
    return ret;
}

static int report_tasks_clean_finished(struct scheduler *sched, hash_map_t *report_tasks_map)
{
    CHECK_NULL(sched);
    CHECK_NULL(report_tasks_map);

    stats_report_task_t *report_task = NULL;
    stats_report_task_t *tmp_report_task = NULL;

    report_task = hash_map_get_first(report_tasks_map);
    while (report_task) {
        tmp_report_task = report_task;
        report_task = hash_map_get_next(report_tasks_map, report_task);
        if (scheduler_timer_task_is_completed(sched, tmp_report_task->task_id)) {
            wifi_util_dbg_print(WIFI_SM, "%s:%d: timer task=%d is completed, remove from map\n",
                                __func__, __LINE__, tmp_report_task->task_id);
            scheduler_free_timer_task_arg(sched, tmp_report_task->task_id);
            tmp_report_task = hash_map_remove(report_tasks_map, tmp_report_task->stats_cfg_id);
            free(tmp_report_task);
        }
    }

    return RETURN_OK;
}


static int report_push_to_dpp_cb(void *args)
{
    int rc = RETURN_OK;
    int radio_index = 0;
    unsigned int *report_counter;
    sm_report_callback_arg_t *task_args = (sm_report_callback_arg_t *)args;
    wifi_radio_operationParam_t *radio_oper_param = NULL;
    stats_config_t *config = NULL;
    hash_map_t *app_config_map = NULL;
    struct scheduler *sched = NULL;
    hash_map_t *report_tasks_map = NULL;

    if (!task_args || !task_args->app) {
        wifi_util_dbg_print(WIFI_SM, "%s:%d: task_args is invalid\n", __func__, __LINE__);
        return TIMER_TASK_ERROR;
    }

    app_config_map = task_args->app->data.u.sm_data.sm_stats_config_map;
    if (!app_config_map) {
        wifi_util_dbg_print(WIFI_SM, "%s:%d: app_config_map is NULL\n", __func__, __LINE__);
        rc = RETURN_ERR;
        goto exit;
    }

    config = hash_map_get(app_config_map, task_args->stats_cfg_id);
    if (!config) {
        wifi_util_dbg_print(WIFI_SM, "%s:%d: cannot find config\n", __func__, __LINE__);
        rc = RETURN_ERR;
        goto exit;
    }

    rc = convert_freq_band_to_radio_index(config->radio_type, &radio_index);
    if (rc != RETURN_OK) {
        wifi_util_dbg_print(WIFI_SM, "%s:%d: failed to convert freq_band=%d to radio_index\n", __func__, __LINE__, config->radio_type);
        rc = RETURN_ERR;
        goto exit;
    }

    radio_oper_param = (wifi_radio_operationParam_t *)get_wifidb_radio_map(radio_index);
    if (!radio_oper_param) {
        wifi_util_dbg_print(WIFI_SM, "%s:%d: failed to get radio_oper_param\n", __func__, __LINE__);
        rc = RETURN_ERR;
        goto exit;
    }

    switch (config->stats_type) {
        case stats_type_client:
            rc = sm_client_report_push_to_dpp(&sm_client_report_cache[radio_index], config->radio_type, radio_oper_param->channel);
            break;
        case stats_type_survey:
            if (config->survey_type == survey_type_off_channel) {
                report_counter = &(task_args->app->data.u.sm_data.off_chan_report_counter[radio_index]);
            }
            else {
                report_counter = &(task_args->app->data.u.sm_data.on_chan_report_counter[radio_index]);
            }
            rc = sm_survey_report_push_to_dpp(&sm_survey_report_cache[radio_index], config->radio_type, config->survey_type,
                    config->report_type, report_counter);
            break;
        case stats_type_neighbor:
            rc = sm_neighbor_report_push_to_dpp(&sm_neighbor_report_cache[radio_index], config->radio_type, config->survey_type, config->report_type);
            break;
        default:
            break;
    }

    if (rc != RETURN_OK) {
        wifi_util_dbg_print(WIFI_SM, "%s:%d: failed to push report to dpp\n", __func__, __LINE__);
        rc = RETURN_ERR;
        goto exit;
    }

exit:
    report_tasks_map = task_args->app->data.u.sm_data.report_tasks_map;
    sched = task_args->app->ctrl->sched;
    report_tasks_clean_finished(sched, report_tasks_map);

    return rc == RETURN_OK ? TIMER_TASK_COMPLETE : TIMER_TASK_ERROR;
}


static inline void client_report_cache_init_all()
{
    for (size_t i = 0; i < ARRAY_SIZE(sm_client_report_cache); i++) {
        sm_client_cache_init(&sm_client_report_cache[i]);
    }
}


static inline void survey_report_cache_init_all()
{
    for (size_t i = 0; i < ARRAY_SIZE(sm_survey_report_cache); i++) {
        sm_survey_cache_init(&sm_survey_report_cache[i]);
    }
}


static inline void neighbor_report_cache_init_all()
{
    for (size_t i = 0; i < ARRAY_SIZE(sm_neighbor_report_cache); i++) {
        sm_neighbor_cache_init(&sm_neighbor_report_cache[i]);
    }
}


static inline void client_report_cache_free_all()
{
    for (size_t i = 0; i < ARRAY_SIZE(sm_client_report_cache); i++) {
        sm_client_cache_deinit(&sm_client_report_cache[i]);
    }
}


static inline void survey_report_cache_free_all()
{
    for (size_t i = 0; i < ARRAY_SIZE(sm_survey_report_cache); i++) {
        sm_survey_cache_deinit(&sm_survey_report_cache[i]);
    }
}


static inline void neighbor_report_cache_free_all()
{
    for (size_t i = 0; i < ARRAY_SIZE(sm_neighbor_report_cache); i++) {
        sm_neighbor_cache_deinit(&sm_neighbor_report_cache[i]);
    }
}


static int report_tasks_map_free(wifi_app_t *app)
{
    CHECK_NULL(app);
    CHECK_NULL(app->data.u.sm_data.report_tasks_map);

    stats_report_task_t *report_task = NULL, *tmp_report_task = NULL;
    char key[64] = {0};

    report_task = hash_map_get_first(app->data.u.sm_data.report_tasks_map);
    while (report_task != NULL) {
        /* remove timer */
        if (app->ctrl) {
            scheduler_cancel_timer_task(app->ctrl->sched, report_task->task_id);
            scheduler_free_timer_task_arg(app->ctrl->sched, report_task->task_id);
        }

        /* remove config entry from map */
        memset(key, 0, sizeof(key));
        snprintf(key, sizeof(key), "%s", report_task->stats_cfg_id);
        report_task = hash_map_get_next(app->data.u.sm_data.report_tasks_map, report_task);
        tmp_report_task = hash_map_remove(app->data.u.sm_data.report_tasks_map, key);
        free(tmp_report_task);
    }
    hash_map_destroy(app->data.u.sm_data.report_tasks_map);
    app->data.u.sm_data.report_tasks_map = NULL;

    return RETURN_OK;
}

/* Public API*/


int sm_report_send_to_qm_cb(void *args)
{
    int rc = TIMER_TASK_COMPLETE;
    uint32_t buf_len;
    static uint8_t sm_mqtt_buf[STATS_MQTT_BUF_SZ];

    if (dpp_get_queue_elements() <= 0) {
        return rc;
    }

    wifi_util_dbg_print(WIFI_SM, "%s:%d Total %d elements queued for transmission.\n",__func__, __LINE__, dpp_get_queue_elements());

    if (!qm_conn_get_status(NULL)) {
        wifi_util_error_print(WIFI_SM, "%s:%d Cannot connect to QM (QM not running?)\n",__func__, __LINE__);
        return rc;
    }

    while (dpp_get_queue_elements() > 0)
    {
        if (!dpp_get_report(sm_mqtt_buf, sizeof(sm_mqtt_buf), &buf_len))
        {
            wifi_util_error_print(WIFI_SM, "%s:%d DPP: Get report failed.\n",__func__, __LINE__);
            break;
        }

        if (buf_len <= 0)
        {
            continue;
        }

        wifi_util_dbg_print(WIFI_SM, "%s:%d buf_len = %d\n",__func__, __LINE__, buf_len);
        if (!sm_mqtt_publish(buf_len, sm_mqtt_buf))
        {
            wifi_util_error_print(WIFI_SM, "%s:%d Publish report failed.\n",__func__, __LINE__);
            break;
        }
    }
    return rc;
}


int sm_report_start_task(stats_type_t type, wifi_app_t *app, wifi_mon_stats_request_state_t state,
    const stats_config_t *config)
{
    switch (type) {
        case stats_type_neighbor:
        case stats_type_survey:
        case stats_type_client:
            return sm_report_config_task(app, state, config);
        default:
        break;
    }

    return RETURN_OK;
}


static int report_task_cleanup(stats_report_task_t *report_task, const stats_config_t *config)
{
    int rc = RETURN_OK;
    int radio_index = 0;

    CHECK_NULL(report_task);
    CHECK_NULL(config);

    switch (config->stats_type) {
        case stats_type_survey:
            rc = convert_freq_band_to_radio_index(config->radio_type, &radio_index);
            if (rc != RETURN_OK) {
                wifi_util_dbg_print(WIFI_SM, "%s:%d: failed to convert freq_band=%d to radio_index\n", __func__, __LINE__, config->radio_type);
                rc = RETURN_ERR;
                goto exit;
            }

            sm_survey_cache_free_after_reconf(radio_index, config->survey_type);
            break;
        default:
            break;
    }

exit:
    return rc;
}


int sm_report_config_task(wifi_app_t *app, wifi_mon_stats_request_state_t state, const stats_config_t *config)
{
    CHECK_NULL(app);
    CHECK_NULL(app->data.u.sm_data.report_tasks_map);
    CHECK_NULL(config);

    stats_report_task_t *report_task = NULL;
    sm_report_callback_arg_t *task_args = NULL;
    int rc = RETURN_OK;

    report_task = hash_map_get(app->data.u.sm_data.report_tasks_map, config->stats_cfg_id);
    if (report_task == NULL) {
        if (state == mon_stats_request_state_stop) {
            wifi_util_error_print(WIFI_SM, "%s:%d: task should be removed, but not found\n", __func__, __LINE__);
            return RETURN_ERR;
        }

        /* not found, create new task */
        report_task = calloc(1, sizeof(stats_report_task_t));
        if (report_task == NULL) {
            wifi_util_error_print(WIFI_SM, "%s:%d: failed to alloc report_task\n", __func__, __LINE__);
            goto exit_err;
        }
        task_args = calloc(1, sizeof(sm_report_callback_arg_t));
        if (task_args == NULL) {
            wifi_util_error_print(WIFI_SM, "%s:%d: failed to alloc task_args\n", __func__, __LINE__);
            goto exit_err;
        }

        task_args->app = app;
        memcpy(task_args->stats_cfg_id, config->stats_cfg_id, sizeof(task_args->stats_cfg_id));
        memcpy(report_task->stats_cfg_id, config->stats_cfg_id, sizeof(report_task->stats_cfg_id));

        rc = scheduler_add_timer_task(app->ctrl->sched, FALSE, &report_task->task_id,
            report_push_to_dpp_cb, (void *)task_args,
            config->reporting_interval * MSEC_IN_SEC, config->reporting_count, FALSE);

        if (rc != RETURN_OK) {
            wifi_util_error_print(WIFI_SM, "%s:%d: failed to add timer task\n", __func__, __LINE__);
            goto exit_err;
        }

        wifi_util_dbg_print(WIFI_SM, "%s:%d: added timer task %d with interval=%d, count=%d\n",
                            __func__, __LINE__, report_task->task_id, config->reporting_interval, config->reporting_count);
        hash_map_put(app->data.u.sm_data.report_tasks_map, strdup(config->stats_cfg_id), report_task);
    } else {
        report_task_cleanup(report_task, config);

        if (state == mon_stats_request_state_stop) {
            wifi_util_info_print(WIFI_SM, "%s:%d: removing task %d\n", __func__, __LINE__, report_task->task_id);
            scheduler_cancel_timer_task(app->ctrl->sched, report_task->task_id);
            hash_map_remove(app->data.u.sm_data.report_tasks_map, report_task->stats_cfg_id);
            scheduler_free_timer_task_arg(app->ctrl->sched, report_task->task_id);
            free(report_task);
        } else if (state == mon_stats_request_state_start) {
            /* found, need to reconfigure timer */
            wifi_util_info_print(WIFI_SM, "%s:%d: reconfiguring timer for task %d, interval=%d, count=%d\n",
                                  __func__, __LINE__, report_task->task_id,
                                  config->reporting_interval, config->reporting_count);
            scheduler_update_timer_task_repetitions(app->ctrl->sched, report_task->task_id, config->reporting_count);
            scheduler_update_timer_task_interval(app->ctrl->sched, report_task->task_id, config->reporting_interval * MSEC_IN_SEC);
        }
    }

    return RETURN_OK;

exit_err:
    free(report_task);
    free(task_args);
    return RETURN_ERR;
}


int sm_report_init(wifi_app_t *app)
{
    CHECK_NULL(app);

    int rc = RETURN_OK;

    client_report_cache_init_all();
    survey_report_cache_init_all();
    neighbor_report_cache_init_all();

    rc = scheduler_add_timer_task(app->ctrl->sched, FALSE, &send_qm_task_id, sm_report_send_to_qm_cb, NULL, SM_TO_QM_SEND_INTERVAL_SEC * MSEC_IN_SEC, 0, FALSE);
    if (rc != RETURN_OK) {
        wifi_util_error_print(WIFI_SM, "%s:%d: failed to add timer task for send to qm\n", __func__, __LINE__);
    }
    else {
        scheduler_add_timer_task(app->ctrl->sched, FALSE, &reports_counter_task_id, survey_report_counter_publish_cb, (void *)app, SM_SURVEY_REPORT_COUNTER_INTERVAL_SEC * MSEC_IN_SEC, 0, FALSE);
    }

    return rc;
}


int sm_report_deinit(wifi_app_t *app)
{
    if (app && app->ctrl) {
        if (send_qm_task_id >= 0) {
            scheduler_cancel_timer_task(app->ctrl->sched, send_qm_task_id);
        }
        if (reports_counter_task_id >= 0) {
            scheduler_cancel_timer_task(app->ctrl->sched, reports_counter_task_id);
        }
    }

    report_tasks_map_free(app);

    client_report_cache_free_all();
    survey_report_cache_free_all();
    neighbor_report_cache_free_all();
    return RETURN_OK;
}
