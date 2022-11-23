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

#ifndef ENABLE_SESHAT
#include "ssp_global.h"
#include "stdlib.h"
#include "ccsp_dm_api.h"
#include "harvester.h"
//#include "ccsp_harvesterLog_wrapper.h"
#include "webpa_interface.h"
#include "ccsp_WifiLog_wrapper.h"

#define PARODUS_URL_DEFAULT      "tcp://127.0.0.1:6666"
/*----------------------------------------------------------------------------*/
/*                             External Functions                             */
/*----------------------------------------------------------------------------*/
void get_parodus_url(char **url)
{
    FILE *fp = fopen(DEVICE_PROPS_FILE, "r");

    if( fp !=NULL) {
        char str[255] = {'\0'};
        while (fgets(str, sizeof(str), fp) != NULL){
            char *value = NULL;
            if( NULL != (value = strstr(str, "PARODUS_URL=")) ) {
                value = value + strlen("PARODUS_URL=");
		value[strlen(value)-1] = '\0';
                *url = strdup(value);
                CcspTraceDebug(("RDK_LOG_DEBUG, parodus url is %s\n", *url));
		break;
            }
        }
	fclose(fp);
    } else {
        CcspTraceError(("RDK_LOG_ERROR, Failed to open device.properties file:%s\n", DEVICE_PROPS_FILE));
		CcspTraceDebug(("RDK_LOG_DEBUG,Adding default value for parodus_url\n"));
		*url = strdup(PARODUS_URL_DEFAULT);
    }

    if( NULL == *url ) {
        CcspTraceError(("RDK_LOG_ERROR, parodus url is not present in device.properties file, adding default parodus_url\n"));
		*url = strdup(PARODUS_URL_DEFAULT);
    }

    CcspTraceDebug(("RDK_LOG_DEBUG, parodus url formed is %s\n", *url));
}
#endif
