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

#ifndef CCSP_H
#define CCSP_H

#include <syslog.h>

#ifdef __cplusplus
extern "C"
{
#endif

#define RDKB_CCSP_SUCCESS               100
#define CCSP_CR_ERR_INVALID_PARAM       206

enum rdkb_dataType_e
{
    ccsp_rdkb_string = 0,
    ccsp_rdkb_int,
    ccsp_rdkb_unsignedInt,
    ccsp_rdkb_boolean,
    ccsp_rdkb_dateTime,
    ccsp_rdkb_base64,
    ccsp_rdkb_long,
    ccsp_rdkb_unsignedLong,
    ccsp_rdkb_float,
    ccsp_rdkb_double,
    ccsp_rdkb_byte,
    ccsp_rdkb_none,
};

typedef void (* wifi_ccsp_init_t) (void);
typedef void (* wifi_ccsp_trace_warning_t) (char *format, ...);
typedef void (* wifi_ccsp_trace_emergency_t) (char *format, ...);
typedef void (* wifi_ccsp_trace_critical_t) (char *format, ...);
typedef void (* wifi_ccsp_trace_error_t) (char *format, ...);
typedef void (* wifi_ccsp_trace_alert_t) (char *format, ...);
typedef void (* wifi_ccsp_trace_notice_t) (char *format, ...);
typedef void (* wifi_ccsp_trace_info_t) (char *format, ...);
typedef void (* wifi_ccsp_trace_debug_t) (char *format, ...);
typedef char * (* psm_get_value_t) (char *recName, char *strValue);
typedef int (* psm_set_value_t) (char *recName, char *strValue);
typedef int (* get_partner_id_t) (char *partner_id);

typedef struct {
    wifi_ccsp_init_t                  init_fn;
    wifi_ccsp_trace_warning_t         CcspTraceWarningRdkb_fn;
    wifi_ccsp_trace_emergency_t       CcspTraceEmergencyRdkb_fn;
    wifi_ccsp_trace_critical_t        CcspTraceCriticalRdkb_fn;
    wifi_ccsp_trace_error_t           CcspTraceErrorRdkb_fn;
    wifi_ccsp_trace_alert_t           CcspTraceAlertRdkb_fn;
    wifi_ccsp_trace_notice_t          CcspTraceNoticeRdkb_fn;
    wifi_ccsp_trace_info_t            CcspTraceInfoRdkb_fn;
    wifi_ccsp_trace_debug_t           CcspTraceDebugRdkb_fn;
    psm_get_value_t                   psm_get_value_fn;
    psm_set_value_t                   psm_set_value_fn;
    get_partner_id_t                  get_partner_id_fn;
} wifi_ccsp_desc_t;

typedef struct {
    wifi_ccsp_desc_t       desc;
} wifi_ccsp_t;

#define CCSP_SYSTEM_LOG_FACILITY   LOG_LOCAL5
#define CCSP_EVENT_LOG_FACILITY    LOG_LOCAL4

#define OneWifiTraceBaseStr(arg ...)                                \
    do {                                                            \
        snprintf(TempChar, 4095, arg);                              \
    } while (FALSE)                                                 \

#define syslog_event(MODULE_NAME, priority, format, args...)        \
{                                                                   \
    openlog("[" MODULE_NAME "]", LOG_PID, CCSP_EVENT_LOG_FACILITY); \
    syslog(priority, format, ## args);                              \
    closelog();                                                     \
}

#define OneWifiEventTrace(msg)                                      \
{                                                                   \
    char  TempChar[4096],*loglevel = NULL, *logmsg = NULL;          \
    OneWifiTraceBaseStr msg;                                        \
    loglevel = strtok_r(TempChar,",",&logmsg);(void)(loglevel);     \
    syslog_event("OneWifi", LOG_NOTICE, "%s", logmsg);              \
}

char *psm_get_value_Rdkb(char *recName, char *strValue);
int psm_set_value_Rdkb(char *recName, char *strValue);
int get_partner_id_Rdkb(char *partner_id);

#ifdef __cplusplus
}
#endif

#endif  // CCSP_H
