#include "uahf.h"
#include "uahf_server.h"
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

int uahf_update(wifi_app_t *app)
{
    //launch_server
    uahf_start_server();
    return RETURN_OK;
}

int uahf_init(wifi_app_t *app, unsigned int create_flag)
{
    if (app_init(app, create_flag) != 0) {
        return RETURN_ERR;
    }
    wifi_util_error_print(WIFI_APPS, "%s:%d: Init uahf\n", __func__, __LINE__);

    return RETURN_OK;
}

int uahf_deinit(wifi_app_t *app)
{
    return RETURN_OK;
}
