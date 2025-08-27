/************************************************************************************
  If not stated otherwise in this file or this component's LICENSE file the
  following copyright and licenses apply:
  
  Copyright 2025 RDK Management
  
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

#include "wifi_em_utils.h"
#include "wifi_util.h"
#include "wifi_mgr.h"
#include <const.h>

#define NOISE_FLOOR (-95)

char* survey_type_to_str(survey_type_t survey_type)
{
    /* for (size_t i = 0; i < ARRAY_SIZE(scan_type_mapping); i++) {
        if (survey_type == scan_type_mapping[i].survey_type) {
            return scan_type_mapping[i].description;
        }
    } */
    wifi_util_error_print(WIFI_EM, "%s:%d failed to convert survey_type=%d\n",__func__, __LINE__, survey_type);
    return "unknown";
}

char* radio_index_to_radio_type_str(unsigned int radio_index)
{
    radio_type_t radio_type;

    //radio_type = radio_index_to_dpp_radio_type(radio_index);

    return radio_get_name_from_type(radio_type);
}

char* neighbor_scan_mode_to_str(wifi_neighborScanMode_t scan_mode)
{
    /* for (size_t i = 0; i < ARRAY_SIZE(scan_type_mapping); i++) {
        if (scan_mode == scan_type_mapping[i].scan_mode) {
            return scan_type_mapping[i].description;
        }
    } */
    wifi_util_error_print(WIFI_EM, "%s:%d failed to convert scan_mode=%d\n",__func__, __LINE__, scan_mode);
    return "unknown";
}

uint64_t get_real_ms()
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * MSEC_IN_SEC + ts.tv_nsec / NSEC_IN_MSEC;
}

uint64_t timeval_to_ms(struct timeval *ts)
{
    if (!ts) {
        return 0;
    }
    return (uint64_t)ts->tv_sec * MSEC_IN_SEC + ts->tv_usec / USEC_IN_MSEC;
}
