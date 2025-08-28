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

#ifndef BUS_H
#define BUS_H

#include "bus_common.h"
#include "collection.h"
#include <ctype.h>
#include <string.h>
#include <dbus/dbus.h>
#include "ccsp_base_api.h"
#ifdef __cplusplus

extern "C" {
#endif

#define DBUS_INTERFACE_BASE   "com.cisco.spvtg.ccsp.baseInterface"
#define DBUS_PATH_EVENT       "/com/cisco/spvtg/ccsp/EVENT"
#define DBUS_INTERFACE_EVENT  "com.cisco.spvtg.ccsp.EVENT"
#define CCSP_CR_COMPONENT_ID  "eRT.com.cisco.spvtg.ccsp.CR"
#define CCSP_DBUS_PATH_CR     "/com/cisco/spvtg/ccsp/CR"
#define DBUS_COMP_PATH        "/com/cisco/spvtg/ccsp/%s"
#define DBUS_COMP_NAME       "com.cisco.spvtg.ccsp.%s"
#define CCSP_DBUS_INTERFACE_CR  "com.cisco.spvtg.ccsp.CR"
#define PSM_COMP_NAME        "eRT.com.cisco.spvtg.ccsp.psm"
#define PSM_COMP_PATH       "/com/cisco/spvtg/ccsp/PSM"

#define DBUS_MESSAGE_APPEND_CSTRING(iter,string) do {   \
    if(string)  \
        dbus_message_iter_append_basic (iter, DBUS_TYPE_STRING, &string); \
    else \
    {  \
        char *tmp = ""; \
        dbus_message_iter_append_basic (iter, DBUS_TYPE_STRING, &tmp); \
    } \
} while (0)

typedef DBusConnection*  dbusHandle_t;

typedef struct {
    wifi_bus_desc_t        desc;
    bus_cb_multiplexing_t  bus_cb_mux;
} wifi_bus_t;


typedef struct {
    char *parameterName;
    char *parameterValue;
    enum dataType_e type;
} parameterValStruct1_t;

typedef struct
{
    char *name_space;
    enum dataType_e dataType;
} name_spaceType1_t;

typedef struct
{
    char*                   name;       /**< Name of an element               */
    bus_element_type_t      element_type;       /**< Type of an element      */
    bus_callback_table_t    cbTable;    /**< Element Handler table. A specific
                                             callback can be NULL, if no usage*/
    data_model_properties_t data_type;
}dbusDataElement_t;

typedef struct
{
    char *componentName;
    char *dbusPath;
    enum dataType_e type;
    char *remoteCR_name;
    char *remoteCR_dbus_path;
} componentStruct1_t;

typedef struct bus_handle {
    union {
        dbusHandle_t dbus_handle;
    } u;
    char component_name[64];
    char dbus_path[64];
    DBusObjectPathVTable comp_vtable;
    hash_map_t           *subscribe_callback;
    hash_map_t           *method_callback;
} bus_handle_t;

void bus_releaseOpenTelemetryContext();
wifi_bus_desc_t *get_bus_descriptor();
wifi_bus_t *get_bus_obj(void);
bus_error_t bus_init(bus_handle_t *handle);
bus_error_t find_destination_path(bus_handle_t *handle,char const *namespace,char **bus_path,char **comp);
#ifdef __cplusplus
}
#endif

#endif // BUS_H
