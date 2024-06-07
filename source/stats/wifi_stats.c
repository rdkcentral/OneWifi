/************************************************************************************
  If not stated otherwise in this file or this component's LICENSE file the
  following copyright and licenses apply:

  Copyright 2018 RDK Management

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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include "wifi_monitor.h"
#include "wifi_util.h"

#define WIFI_STATS_NUM 5

wifi_mon_stats_descriptor_t g_stats_descriptor[WIFI_STATS_NUM] = {
    {
        mon_stats_type_radio_channel_stats,
        validate_radio_channel_args,
        generate_radio_channel_clctr_stats_key,
        generate_radio_channel_provider_stats_key,
        execute_radio_channel_api,
        copy_radio_channel_stats_from_cache,
        update_radio_channels_collector_args,
        stop_radio_channel_neighbor_scheduler_tasks
    },
    {
        //neighbours stats and radio channel stats share the same collector
        mon_stats_type_neighbor_stats,
        validate_neighbor_ap_args,
        generate_radio_channel_clctr_stats_key,
        generate_radio_channel_provider_stats_key,
        execute_radio_channel_api,
        copy_neighbor_ap_stats_from_cache,
        update_radio_channels_collector_args,
        stop_radio_channel_neighbor_scheduler_tasks
    },
    {
        mon_stats_type_radio_diagnostic_stats,
        validate_radio_diagnostic_args,
        generate_radio_diagnostic_clctr_stats_key,
        generate_radio_diagnostic_provider_stats_key,
        execute_radio_diagnostic_stats_api,
        copy_radio_diagnostic_stats_from_cache,
        NULL,
        NULL
    },
    {
        mon_stats_type_associated_device_stats,
        validate_assoc_client_args,
        generate_assoc_client_clctr_stats_key,
        generate_assoc_client_provider_stats_key,
        execute_assoc_client_stats_api,
        copy_assoc_client_stats_from_cache,
        NULL,
        NULL
    },
    {
        mon_stats_type_radio_temperature,
        validate_radio_temperature_args,
        generate_radio_temperature_clctr_stats_key,
        generate_radio_temperature_provider_stats_key,
        execute_radio_temperature_stats_api,
        copy_radio_temperature_stats_from_cache,
        NULL,
        NULL
    }
};

wifi_mon_stats_descriptor_t *wifi_mon_get_stats_descriptor(wifi_mon_stats_type_t stats_type)
{
    int i = 0;

    for (i = 0; i < WIFI_STATS_NUM; i++) {
        if (g_stats_descriptor[i].stats_type == stats_type) {
            return &g_stats_descriptor[i];
        }
    }

    return NULL;
}

int stats_common_args_validation(wifi_mon_stats_config_t *config)
{
    if (config == NULL) {
        wifi_util_error_print(WIFI_MON, "%s:%d: input mon_stats_config is NULL\n", __func__,__LINE__);
        return RETURN_ERR;
    }

    if (config->interval_ms == 0) {
        wifi_util_error_print(WIFI_MON, "%s:%d: invalid interval_ms %d\n", __func__,__LINE__, config->interval_ms);
        return RETURN_ERR;
    }

    //Check for the incoming interval is valid
    if ((config->interval_ms % MONITOR_RUNNING_INTERVAL_IN_MILLISEC) != 0) {
        wifi_util_error_print(WIFI_MON, "%s:%d: interval %d is not multiple of monitor interval : %d\n", __func__,__LINE__, config->interval_ms, MONITOR_RUNNING_INTERVAL_IN_MILLISEC);
        return RETURN_ERR;
    }

    return RETURN_OK;
}
