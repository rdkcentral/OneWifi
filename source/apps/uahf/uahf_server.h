#ifndef WIFI_UAHF_SERVER_H
#define WIFI_UAHF_SERVER_H
#include "wifi_ctrl.h"
#include "wifi_hal.h"
#include "wifi_mgr.h"
#include "wifi_util.h"
typedef struct {
    void *data;
} uahf_server_data_t;

int uahf_start_server(wifi_app_t *);

#endif
