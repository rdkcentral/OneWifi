#ifndef WIFI_ANALYTICS_H
#define WIFI_ANALYTICS_H

#ifdef __cplusplus
extern "C" {
#endif

#define ANAYLYTICS_PERIOD            60

#define analytics_format_mgr_core    "MGR -> CORE : %s : %s\r\n"
#define analytics_format_ovsm_core   "OVSM -> CORE : %s : %s\r\n"
#define analytics_format_core_ovsm   "CORE -> OVSM : %s : %s\r\n"
#define analytics_format_generic     "%s -> %s : %s : %s\r\n"
#define analytics_format_hal_core    "HAL -> CORE : %s : %s\r\n"
#define analytics_format_other_core  "OMGR -> CORE : %s : %s\r\n"
#define analytics_format_dml_core    "DML -> CORE : %s : %s\r\n"
#define analytics_format_core_core   "CORE -> CORE : %s : %s\r\n"

#ifdef __cplusplus
}
#endif

#endif // WIFI_ANALYTICS_H