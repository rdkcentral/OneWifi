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

#ifndef SM_UTILS_H
#define SM_UTILS_H

#include "wifi_base.h"
#include "wifi_util.h"
#include "wifi_ctrl.h"

#include <wifi_hal_generic.h>
#include "ds_dlist.h"
#include "dpp_types.h"
#ifdef __cplusplus
extern "C" {
#endif

#define CHECK_NULL(X)          \
    do  {                      \
        if ((X) == NULL) {     \
            wifi_util_error_print(WIFI_APPS, "%s:%d: %s is NULL\n", __func__, __LINE__, #X); \
            return RETURN_ERR; \
        }                      \
    } while (0)


#ifndef MIN
#define MIN(a,b) \
    ({ __typeof__ (a) _a = (a); \
    __typeof__ (b) _b = (b); \
    _a < _b ? _a : _b; })
#endif

#ifndef MAX
#define MAX(a,b) \
    ({ __typeof__ (a) _a = (a); \
    __typeof__ (b) _b = (b); \
    _a > _b ? _a : _b; })
#endif


#define MSEC_IN_SEC  (1000ULL)
#define NSEC_IN_MSEC (1000000ULL)
#define USEC_IN_MSEC (1000ULL)


/* conversion */
radio_type_t freq_band_to_dpp_radio_type(wifi_freq_bands_t freq_band);
report_type_t reporting_type_to_dpp_report_type(reporting_type_t report_type);
radio_scan_type_t survey_type_to_dpp_scan_type(survey_type_t survey_type);
char* survey_type_to_str(survey_type_t survey_type);
char* neighbor_scan_mode_to_str(wifi_neighborScanMode_t scan_mode);
radio_chanwidth_t str_to_dpp_chan_width(char *str);
char* radio_index_to_radio_type_str(unsigned int radio_index);

/* ds_list utils */
size_t get_ds_dlist_len(ds_dlist_t *list);

/* time utils*/
uint64_t get_real_ms();
uint64_t timeval_to_ms(struct timeval *ts);

/* other */
int rssi_to_above_noise_floor(int rssi);
int get_ssid_from_vap_index(unsigned int vap_index, ssid_t ssid);


#ifdef __cplusplus
}
#endif

#endif // SM_UTILS_H
