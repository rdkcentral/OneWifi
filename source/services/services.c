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
#include "wifi_hal.h"
#include "wifi_services_mgr.h"

service_t services[MAX_SERVICES] = {
    {
        "Private",
        "Private Service for Home Usages",
        {
            {
                "private_ssid",
                "2g",
                "AP"
            },
            {
                "private_ssid",
                "5g",
                "AP"
            },
            {
                "private_ssid",
                "6g",
                "AP"
            },
            {
                "",
                "",
                ""
            },
            {
                "",
                "",
                ""
            },
            {
                "",
                "",
                ""
            }
        }
    },
    {
        "Public",
        "Public Service for hotspots",
        {
            {
                "hotspot_open",
                "6g",
                "AP"
            },
            {
                "hotspot_open",
                "5g",
                "AP"
            },
            {
                "hotspot_secure",
                "2g",
                "AP"
            },
            {
                "hotspot_secure",
                "5g",
                "AP"
            },
            {
                "hotspot_secure",
                "6g",
                "AP"
            },
            {
                "",
                "",
                ""
            }
        }
    },
    {
        "Mesh",
        "Mesh Service to connect AP devices",
        {
            {
                "mesh_backhaul",
                "2g",
                "AP"
            },
            {
                "mesh_backhaul",
                "5g",
                "AP"
            },
            {
                "mesh_backhaul",
                "6g",
                "AP"
            },
            {
                "mesh_sta",
                "2g",
                "STA"
            },
            {
                "mesh_sta",
                "5g",
                "STA"
            },
            {
                "mesh_sta",
                "6g",
                "STA"
            }
        }

    },
    {
        "Managed",
        "Managed Service to provide Comcast controlled devices connectivity",
        {
            {
                "iot_ssid",
                "2g",
                "AP"
            },
            {
                "iot_ssid",
                "5g",
                "AP"
            },
            {
                "iot_ssid",
                "6g",
                "AP"
            },
            {
                "",
                "",
                ""
            },
            {
                "",
                "",
                ""
            },
            {
                "",
                "",
                ""
            }
        }

    },
    {
        "Configurable Persistent",
        "Configurable Service that persistes across reboot",
        {
            {
                "private_ssid",
                "2g",
                "AP"
            },
            {
                "private_ssid",
                "5g",
                "AP"
            },
            {
                "private_ssid",
                "6g",
                "AP"
            },
            {
                "",
                "",
                ""
            },
            {
                "",
                "",
                ""
            },
            {
                "",
                "",
                ""
            }
        }

    },
    {
        "Configurable Transient",
        "Configurable Service that is transient",
        {
            {
                "private_ssid",
                "2g",
                "AP"
            },
            {
                "private_ssid",
                "5g",
                "AP"
            },
            {
                "private_ssid",
                "6g",
                "AP"
            },
            {
                "",
                "",
                ""
            },
            {
                "",
                "",
                ""
            },
            {
                "",
                "",
                ""
            }
        }

    }
};
