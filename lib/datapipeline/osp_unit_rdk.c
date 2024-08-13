/*
Copyright (c) 2017, Plume Design Inc. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
   1. Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
   2. Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
   3. Neither the name of the Plume Design Inc. nor the
      names of its contributors may be used to endorse or promote products
      derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL Plume Design Inc. BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <ctype.h>
#include <stdbool.h>
#include <errno.h>

#include "log.h"
#include "devinfo.h"
#include "const.h"
#include "build_version.h"
#include "util.h"

#include "osp_unit.h"

#define MODULE_ID LOG_MODULE_ID_OSA

#define MAX_CACHE_LEN       64

/*****************************************************************************/

static struct
{
    bool        serial_cached;
    char        serial[MAX_CACHE_LEN];

    bool        id_cached;
    char        id[MAX_CACHE_LEN];

    bool        model_cached;
    char        model[MAX_CACHE_LEN];

    bool        pver_cached;
    char        pver[MAX_CACHE_LEN];
} osp_unit_cache;

bool osp_unit_serial_get(char *buff, size_t buffsz)
{
    if (!osp_unit_cache.serial_cached)
    {
        if (!devinfo_getv(DEVINFO_SERIAL_NUM,
                          ARRAY_AND_SIZE(osp_unit_cache.serial)))
        {
            return false;
        }
        osp_unit_cache.serial_cached = true;
    }

    snprintf(buff, buffsz, "%s", osp_unit_cache.serial);
    return true;
}

#if defined(_WNXL11BWL_PRODUCT_REQ_)
bool osp_unit_id_get(char *buff, size_t buffsz)
{
    if (!osp_unit_cache.id_cached)
    {
        if (!devinfo_getv(DEVINFO_SERIAL_NUM,
                          ARRAY_AND_SIZE(osp_unit_cache.id)))
        {
            return false;
        }

        osp_unit_cache.id_cached = true;
    }
    snprintf(buff, buffsz, "%s", osp_unit_cache.id);
    return true;
}
#else
bool osp_unit_id_get(char *buff, size_t buffsz)
{
    if (!osp_unit_cache.id_cached)
    {
        if (!devinfo_getv(DEVINFO_CM_MAC,
                          ARRAY_AND_SIZE(osp_unit_cache.id)))
        {
            return false;
        }

        if (strlen(osp_unit_cache.id) != 17)
        {
            LOGE("osp_unit_id_get() bad CM_MAC format");
            return false;
        }

        osp_unit_cache.id_cached = true;
    }

    snprintf(buff,
             buffsz,
             "%c%c%c%c%c%c%c%c%c%c%c%c",
             toupper(osp_unit_cache.id[0]),
             toupper(osp_unit_cache.id[1]),
             // osp_unit_cache.id[2] == ":"
             toupper(osp_unit_cache.id[3]),
             toupper(osp_unit_cache.id[4]),
             // osp_unit_cache.id[5] == ":"
             toupper(osp_unit_cache.id[6]),
             toupper(osp_unit_cache.id[7]),
             // osp_unit_cache.id[8] == ":"
             toupper(osp_unit_cache.id[9]),
             toupper(osp_unit_cache.id[10]),
             // osp_unit_cache.id[11] == ":"
             toupper(osp_unit_cache.id[12]),
             toupper(osp_unit_cache.id[13]),
             // osp_unit_cache.id[14] == ":"
             toupper(osp_unit_cache.id[15]),
             toupper(osp_unit_cache.id[16]));

    return true;
}
#endif

bool osp_unit_sku_get(char *buff, size_t buffsz)
{
    // SKU info not available
    return false;
}

bool osp_unit_model_get(char *buff, size_t buffsz)
{
    if (!osp_unit_cache.model_cached)
    {
        if (!devinfo_getv(DEVINFO_MODEL_NUM,
                          ARRAY_AND_SIZE(osp_unit_cache.model)))
        {
            return false;
        }
        osp_unit_cache.model_cached = true;
    }

    snprintf(buff, buffsz, "%s", osp_unit_cache.model);
    return true;
}

/* Note WPA3 configuration is not supported by the lagacy security schema ("security" parameter
   in Wifi_VIF_Config table). Therefore need to switch to the new schema in case correspoding
   RFC is being set for WPA3 capable devices. But Cloud-Controller can work with the new schema
   only in case the third digit in FW version is >= 3, for example:
   3.4.3; 4.0.3; 4.1.4 - these versions support new security schema.
   3.4.2; 4.0.1; 4.1.0 - these versions do not support new security schema.
*/
static void osp_unit_sw_version_update_by_security_schema_rfc(char *buff, size_t buffsz)
{
    int num1, num2, num3;
    char *str_other = NULL;
    char *mesh_security_legacy;
    bool legacy_enabled;

    mesh_security_legacy = strexa("syscfg", "get", "mesh_security_legacy");
    if (mesh_security_legacy == NULL)
    {
        LOGW("%s: Unable to get syscfg mesh_security_legacy", __func__);
        return;
    }
    legacy_enabled = strcmp(mesh_security_legacy, "true") == 0;

    if (sscanf(buff, "%d.%d.%d%ms", &num1, &num2, &num3, &str_other) < 3)
    {
        LOGW("%s: Failed to parse FW version", __func__);
        free(str_other);
        return;
    }

    if (legacy_enabled == true || num3 >= 3)
    {
        LOGI("%s: Keep same FW version[%s]. Legacy security enabled[%d], FW_num3[%d]", __func__,
            buff, legacy_enabled, num3);
        free(str_other);
        return;
    }

    num3 = 3;
    snprintf(buff, buffsz, "%d.%d.%d%s", num1, num2, num3, str_other);
    LOGI("%s: FW version is being changed [%s]", __func__, buff);
    free(str_other);
}

bool osp_unit_sw_version_get(char *buff, size_t buffsz)
{
//    snprintf(buff, buffsz, "%d", app_build_ver_get());
    osp_unit_sw_version_update_by_security_schema_rfc(buff, buffsz);
    return true;
}

bool osp_unit_hw_revision_get(char *buff, size_t buffsz)
{
    // HW version info not available
    return false;
}

bool osp_unit_platform_version_get(char *buff, size_t buffsz)
{
    if (!osp_unit_cache.pver_cached)
    {
        if (!devinfo_getv(DEVINFO_SOFTWARE_VER,
                          ARRAY_AND_SIZE(osp_unit_cache.pver)))
        {
            return false;
        }
        osp_unit_cache.pver_cached = true;
    }

    snprintf(buff, buffsz, "%s", osp_unit_cache.pver);
    return true;
}

bool osp_unit_vendor_part_get(char *buff, size_t buffsz)
{
    return false;
}

bool osp_unit_manufacturer_get(char *buff, size_t buffsz)
{
    return false;
}

bool osp_unit_factory_get(char *buff, size_t buffsz)
{
    return false;
}

bool osp_unit_mfg_date_get(char *buff, size_t buffsz)
{
    return false;
}

bool osp_unit_vendor_name_get(char *buff, size_t buffsz)
{
    return false;
}

bool osp_unit_dhcpc_hostname_get(void *buff, size_t buffsz)
{
    char serial_num[buffsz];
    char model_name[buffsz];

    memset(serial_num, 0, (sizeof(char) * buffsz));
    memset(model_name, 0, (sizeof(char) * buffsz));

    if (!osp_unit_serial_get(serial_num, sizeof(serial_num)))
    {
        LOG(ERR, "Unable to get serial number");
        return false;
    }
    if (!osp_unit_model_get(model_name, sizeof(model_name)))
    {
        LOG(ERR, "Unable to get model name");
        return false;
    }

    snprintf(buff, buffsz, "%s_%s", serial_num, model_name);

    return true;
}
