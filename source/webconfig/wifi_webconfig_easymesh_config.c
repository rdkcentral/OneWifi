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
#include "collection.h"
#include "wifi_monitor.h"
#include "wifi_util.h"
#include "wifi_ctrl.h"

webconfig_subdoc_object_t   em_config_objects[3] = {
    { webconfig_subdoc_object_type_version, "Version" },
    { webconfig_subdoc_object_type_subdoc, "SubDocName" },
    { webconfig_subdoc_object_type_em_config, "WifiEMConfig" },
};

webconfig_error_t init_em_config_subdoc(webconfig_subdoc_t *doc)
{
    return webconfig_error_none;
}

webconfig_error_t access_check_em_config_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    return webconfig_error_none;
}

webconfig_error_t translate_from_em_config_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    return webconfig_error_none;
}

webconfig_error_t translate_to_em_config_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    if ((data->descriptor & webconfig_data_descriptor_translate_from_easymesh) == webconfig_data_descriptor_translate_from_easymesh) {
        if (config->proto_desc.translate_from(webconfig_subdoc_type_em_config, data) != webconfig_error_none) {
            if ((data->descriptor & webconfig_data_descriptor_translate_from_easymesh) == webconfig_data_descriptor_translate_from_easymesh) {
                return webconfig_error_translate_from_easymesh;
            }
        }
    } else {
        // no translation required
    }
    return webconfig_error_none;
}

webconfig_error_t encode_em_config_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    return webconfig_error_none;
}

webconfig_error_t decode_em_config_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{

    return webconfig_error_none;
}

