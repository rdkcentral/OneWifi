/*
 * If not stated otherwise in this file or this component's LICENSE file the
 * following copyright and licenses apply:
 *
 * Copyright 2019 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/

#ifdef ENABLE_SESHAT
#include "ssp_global.h"
#include "stdlib.h"
#include "ccsp_dm_api.h"
#include "harvester.h"
//#include "ccsp_harvesterLog_wrapper.h"
#include "webpa_interface.h"
#include "ccsp_WifiLog_wrapper.h"

/*----------------------------------------------------------------------------*/
/*                                   Macros                                   */
/*----------------------------------------------------------------------------*/
#define PARODUS_SERVICE    "Parodus"

/*----------------------------------------------------------------------------*/
/*                             Function Prototypes                            */
/*----------------------------------------------------------------------------*/
static void get_seshat_url(char **url);

/*----------------------------------------------------------------------------*/
/*                             External Functions                             */
/*----------------------------------------------------------------------------*/
void get_parodus_url(char **url)
{
    char *seshat_url = NULL;
    char *discovered_url = NULL;
    size_t discovered_url_size = 0;

    get_seshat_url(&seshat_url);
    if( NULL == seshat_url ) {
        CcspWifiTrace(("RDK_LOG_ERROR, seshat_url is not present in device.properties file\n"));
        return;
    }

    CcspWifiTrace(("RDK_LOG_INFO, seshat_url formed is %s\n", seshat_url));
    if( 0 == init_lib_seshat(seshat_url) ) {
        CcspWifiTrace(("RDK_LOG_INFO, seshatlib initialized! (url %s)\n", seshat_url));

        discovered_url = seshat_discover(PARODUS_SERVICE);
        if( NULL != discovered_url ) {
            discovered_url_size = strlen(discovered_url);
            *url = strndup(discovered_url, discovered_url_size);
            CcspWifiTrace(("RDK_LOG_INFO, seshatlib discovered url = %s, parodus url = %s\n", discovered_url, *url));
            free(discovered_url);
        } else {
            CcspWifiTrace(("RDK_LOG_ERROR, seshatlib registration error (url %s)!", discovered_url));
        }
    } else {
        CcspWifiTrace(("RDK_LOG_ERROR, seshatlib not initialized! (url %s)\n", seshat_url));
    }

    if( NULL == *url ) {
        CcspWifiTrace(("RDK_LOG_ERROR, parodus url (url %s) is not present in seshatlib (url %s)\n", *url, seshat_url));
    }
    CcspWifiTrace(("RDK_LOG_DEBUG, parodus url formed is %s\n", *url));

    shutdown_seshat_lib();
}

/*----------------------------------------------------------------------------*/
/*                             Internal functions                             */
/*----------------------------------------------------------------------------*/
/**
 * @brief Helper function to retrieve seshat URL.
 * 
 * @param[out] URL.
 *
 */
static void get_seshat_url(char **url)
{
    FILE *fp = fopen(DEVICE_PROPS_FILE, "r");

    if( NULL != fp ) {
        char str[255] = {'\0'};
        while( fscanf(fp,"%s", str) != EOF ) {
            char *value = NULL;
            if( value = strstr(str, "SESHAT_URL=") ) {
                value = value + strlen("SESHAT_URL=");
                *url = strdup(value);
                CcspWifiTrace(("RDK_LOG_INFO, seshat_url is %s\n", *url));
            }
        }
    } else {
        CcspWifiTrace(("RDK_LOG_ERROR, Failed to open device.properties file:%s\n", DEVICE_PROPS_FILE));
    }
    fclose(fp);
}
#endif

