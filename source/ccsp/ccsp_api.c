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

#include <syslog.h>

/*For RDKB platforms invoking direct CcspCommonLibrary APIs  */
#include "ccsp.h"
#include "ccsp_trace.h"
#include "util.h"
#include "wifi_hal.h"
#include "wifi_util.h"
#include <stdarg.h>

extern void* bus_handle;
extern char g_Subsystem[32];

void init_ccsp()
{
    /* Placeholder for time being */
}

void CcspTraceEmergencyRdkb(char *format, ...)
{
    va_list args;
    va_start(args, format);
    char *buffer = vstrfmt(format, args);
    if (buffer) {
        CcspTraceEmergency((buffer));
        free(buffer);
    }
    va_end(args);
}

void CcspTraceAlertRdkb(char *format, ...)
{
    va_list args;
    va_start(args, format);
    char *buffer = vstrfmt(format, args);
    if (buffer) {
        CcspTraceAlert((buffer));
        free(buffer);
    }
    va_end(args);
}

void CcspTraceCriticalRdkb(char *format, ...)
{
    va_list args;
    va_start(args, format);
    char *buffer = vstrfmt(format, args);
    if (buffer) {
        CcspTraceCritical((buffer));
        free(buffer);
    }
    va_end(args);
}

void CcspTraceErrorRdkb(char *format, ...)
{
    va_list args;
    va_start(args, format);
    char *buffer = vstrfmt(format, args);
    if (buffer) {
        CcspTraceError((buffer));
        free(buffer);
    }
    va_end(args);
}

void CcspTraceWarningRdkb(char *format, ...)
{
    va_list args;
    va_start(args, format);
    char *buffer = vstrfmt(format, args);
    if (buffer) {
        CcspTraceWarning((buffer));
        free(buffer);
    }
    va_end(args);
}

void CcspTraceNoticeRdkb(char *format, ...)
{
    va_list args;
    va_start(args, format);
    char *buffer = vstrfmt(format, args);
    if (buffer) {
        CcspTraceNotice((buffer));
        free(buffer);
    }
    va_end(args);
}

void CcspTraceInfoRdkb(char *format, ...)
{
    va_list args;
    va_start(args, format);
    char *buffer = vstrfmt(format, args);
    if (buffer) {
        CcspTraceInfo((buffer));
        free(buffer);
    }
    va_end(args);
}

void CcspTraceDebugRdkb(char *format, ...)
{
    va_list args;
    va_start(args, format);
    char *buffer = vstrfmt(format, args);
    if (buffer) {
        CcspTraceDebug((buffer));
        free(buffer);
    }
    va_end(args);
}

char *psm_get_value_Rdkb(char *recName, char *strValue)
{
    int retry = 0;
    int ret_psm_get = RETURN_ERR;

    while (retry++ < 2) {
        ret_psm_get = PSM_Get_Record_Value2(bus_handle, g_Subsystem, recName, NULL, &strValue);
        if (ret_psm_get == RDKB_CCSP_SUCCESS) {
            wifi_util_dbg_print(WIFI_MGR, "%s:%d ret_psm_get success for %s and strValue is %s\n",
                __func__, __LINE__, recName, strValue);
            return strValue;
        } else if (ret_psm_get == CCSP_CR_ERR_INVALID_PARAM) {
            wifi_util_dbg_print(WIFI_MGR, "%s:%d PSM_Get_Record_Value2 (%s) returned error %d \n",
                __func__, __LINE__, recName, ret_psm_get);
            return NULL;
        } else {
            wifi_util_dbg_print(WIFI_MGR,
                "%s:%d PSM_Get_Record_Value2 param (%s) returned error %d"
                " retry in 10 seconds \n",
                __func__, __LINE__, recName, ret_psm_get);
            continue;
        }
    }

    return NULL;
}

int psm_set_value_Rdkb(char *recName, char *strValue)
{
    int retPsmSet;
    int ret = RETURN_ERR;

    wifi_util_dbg_print(WIFI_MGR, "%s:%d record_name:%s\n", __func__, __LINE__, recName);

    retPsmSet = PSM_Set_Record_Value2(bus_handle, g_Subsystem, recName, ccsp_rdkb_string, strValue);
    if (retPsmSet == RDKB_CCSP_SUCCESS) {
        wifi_util_dbg_print(WIFI_MGR, "%s:%d set bool value:%s\n", __func__, __LINE__, strValue);
        ret = RETURN_OK;
    } else {
        wifi_util_dbg_print(WIFI_MGR,
            "%s:%d PSM_Set_Record_Value2 returned error %d while"
            " setting bool param:%s\n",
            __func__, __LINE__, retPsmSet, strValue);
    }

    return ret;
}

int get_partner_id_Rdkb(char *partner_id)
{
    return ((getPartnerId(partner_id) == RDKB_CCSP_SUCCESS) ? RETURN_OK : RETURN_ERR);
}
