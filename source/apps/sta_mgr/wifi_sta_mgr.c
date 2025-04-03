#include "wifi_sta_mgr.h"
#include "stdlib.h"
#include "wifi_ctrl.h"
#include "wifi_hal.h"
#include "wifi_mgr.h"
#include "wifi_util.h"
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/time.h>

int sta_mgr_event(wifi_app_t *app, wifi_event_t *event)
{
    return RETURN_OK;
}

int sta_mgr_init(wifi_app_t *app, unsigned int create_flag)
{
    if (app_init(app, create_flag) != 0) {
        return RETURN_ERR;
    }
    wifi_util_info_print(WIFI_APPS, "%s:%d: Init sta mgr\n", __func__, __LINE__);

    return RETURN_OK;
}

int sta_mgr_deinit(wifi_app_t *app)
{
    return RETURN_OK;
}
