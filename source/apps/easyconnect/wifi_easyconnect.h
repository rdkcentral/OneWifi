/************************************************************************************
  If not stated otherwise in this file or this component's LICENSE file the
  following copyright and licenses apply:

  Copyright 2024 RDK Management

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

#ifndef _WIFI_EASYCONNECT_H
#define _WIFI_EASYCONNECT_H

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#define WIFI_EASYCONNECT_RADIO_TABLE        "Device.WiFi.Radio.{i}"
#define WIFI_EASYCONNECT_RADIO_CCE_IND      "Device.WiFi.Radio.{i}.CCEInd"
#define WIFI_EASYCONNECT_BSS_INFO           "Device.WiFi.EC.BSSInfo"

typedef struct _easyconnect_data {
    bool subscriptions[MAX_NUM_RADIOS];
} easyconnect_data_t;

// EasyConnect relevant constructs

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // _WIFI_EASYCONNECT_H