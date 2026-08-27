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
#include <stdbool.h>
#include "stdlib.h"
#include <sys/time.h>
#include "wifi_stubs.h"
#include <string.h>
#include "wifi_hal.h"

#ifdef ONEWIFI_RDKB_APP_SUPPORT
#include "safec_lib_common.h"

extern int t2_event_d(char *marker, int value);
extern int t2_event_s(char *marker, char *buff);
extern int v_secure_system(const char *command);
extern bool drop_root();
extern void gain_root_privilege();
extern char * getDeviceMac();
extern int onewifi_pktgen_uninit();
static int strcpy_func(char *dst, size_t max, const char *src) {
    int rc;
    rc = strcpy_s(dst, max, src);
    ERR_CHK(rc);
    return 0;
}
#else
static int t2_event_d(char *marker, int value)
{
    return 0;
}

static int t2_event_s(char *marker, char *buff)
{
    return 0;
}

static int v_secure_system(const char *command)
{
    return system(command);
}

static bool drop_root()
{
   return true;
}

static void gain_root_privilege()
{
}

static char* getDeviceMac()
{
   static char mac[] = "11:22:33:44:55:66";
   return mac;
}

static int onewifi_pktgen_uninit()
{
   return 0;
}

static int strcpy_func(char *dst, size_t max, const char *src)
{
    strncpy(dst, src, max);
    return 0;
}
#endif

wifi_stubs_descriptor_t stubs_desc = {
    t2_event_d,
    t2_event_s,
    v_secure_system,
    drop_root,
    gain_root_privilege,
    getDeviceMac,
    onewifi_pktgen_uninit,
    strcpy_func
};

wifi_stubs_descriptor_t *get_stubs_descriptor()
{
    return &stubs_desc;
}
