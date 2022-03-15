#ifndef WIFI_WEBCONFIG_DML_H
#define WIFI_WEBCONFIG_DML_H

#include "rbus.h"
#include "wifi_webconfig.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    webconfig_t		webconfig;
    wifi_global_config_t    config;
    wifi_hal_capability_t   hal_cap;
    rdk_wifi_radio_t    radios[MAX_NUM_RADIOS];
    rbusHandle_t	rbus_handle;	
} webconfig_dml_t;

#ifdef __cplusplus
}
#endif

#endif // WIFI_WEBCONFIG__DML_H
