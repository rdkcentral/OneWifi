/************************************************************************************
  If not stated otherwise in this file or this component's LICENSE file the
  following copyright and licenses apply:

  Copyright 2026 RDK Management

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
/*
 * CI coverage-build mock stubs.
 *
 * A few OneWifi apps that are compiled for coverage on the linux/bpi mock, call
 * platform/HAL/DB entry points that only exist on real RDK builds:
 *   - wifi_enableCSIEngine / wifi_getRadioTransmitPower : provided by the real
 *     wifi HAL driver (the banana-pi mock platform does not implement them).
 *   - wifidb_get_preassoc_ctrl_config / wifidb_get_postassoc_ctrl_config :
 *     live inside wifi_db_apis.c's #ifdef ONEWIFI_DB_SUPPORT block, which the
 *     mock build does not enable.
 *
 * These are weak, no-op definitions so the coverage build links. If a higher
 * coverage tier provides the real symbol (e.g. by enabling ONEWIFI_DB_SUPPORT),
 * the strong definition wins and these are ignored.
 *
 * This file is NOT upstream and must never be pushed; it lives under
 * build/linux/compat and is only compiled for the coverage builds.
 */
 
#include "wifi_hal.h"
#include "wifi_mgr.h"

__attribute__((weak))
INT wifi_enableCSIEngine(INT apIndex, mac_address_t sta, BOOL enable)
{
    (void)apIndex; (void)sta; (void)enable;
    return RETURN_OK;
}

__attribute__((weak))
INT wifi_getRadioTransmitPower(INT radioIndex, ULONG *output_ulong)
{
    (void)radioIndex;
    if (output_ulong) {
        *output_ulong = 0;
    }
    return RETURN_OK;
}

__attribute__((weak))
int wifidb_get_preassoc_ctrl_config(char *vap_name, wifi_preassoc_control_t *preassoc)
{
    (void)vap_name; (void)preassoc;
    return 0;
}

__attribute__((weak))
int wifidb_get_postassoc_ctrl_config(char *vap_name, wifi_postassoc_control_t *postassoc)
{
    (void)vap_name; (void)postassoc;
    return 0;
}
