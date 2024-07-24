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

#ifndef BUS_COMMON_H
#define BUS_COMMON_H

#include "wifi_util.h"

#ifdef __cplusplus
extern "C" {
#endif

#define BUS_MAX_NAME_LENGTH 64
#define ZERO_TABLE 0
#define UNREFERENCED_PARAMETER(_p_) (void)(_p_)

#define BUS_METHOD_GET 0
#define BUS_METHOD_SET 1

typedef char bus_name_string_t[BUS_MAX_NAME_LENGTH];

typedef enum {
    bus_data_type_boolean = 0x500,
    bus_data_type_char,
    bus_data_type_byte,
    bus_data_type_int8,
    bus_data_type_uint8,
    bus_data_data_int16, /**< 16 bit int */
    bus_data_type_uint16, /**< 16 bit unsigned int */
    bus_data_type_int32, /**< 32 bit int */
    bus_data_type_uint32, /**< 32 bit unsigned int */
    bus_data_type_init64, /**< 64 bit int */
    bus_data_type_uint64, /**< 64 bit unsigned int */
    bus_data_type_single, /**< 32 bit float */
    bus_data_type_double, /**< 64 bit float */
    bus_data_type_datetime, /**< busDateTime_t structure for Date/Time */
    bus_data_type_string, /**< null terminated C style string */
    bus_data_type_bytes, /**< byte array */
    bus_data_type_property, /**< property instance */
    bus_data_type_object, /**< object instance */
    bus_data_type_none
} bus_data_type_t;

typedef enum {
    bus_element_type_property = 1,
    bus_element_type_table,
    bus_element_type_event,
    bus_element_type_method,
    bus_element_type_max
} bus_element_type_t;

typedef enum bus_speed { slow_speed, mid_speed, high_speed } bus_speed_t;

typedef enum {
    bus_event_action_subscribe = 0,
    bus_event_action_unsubscribe,
} bus_event_sub_action_t;

typedef enum bus_error {
    // Generic error codes
    bus_error_success = 0, /**< Succes                   */
    bus_error_general = 1, /**< General Error            */
    bus_error_invalid_input, /**< Invalid Input            */
    bus_error_not_inttialized, /**< Bus not initialized      */
    bus_error_out_of_resources, /**< Running out of resources */
    bus_error_destination_not_found, /**< Dest element not found   */
    bus_error_destination_not_reachable, /**< Dest element not reachable*/
    bus_error_destination_response_failure, /**< Dest failed to respond   */
    bus_error_invalid_response_from_destination, /**< Invalid dest response   */
    bus_error_invalid_operation, /**< Invalid Operation        */
    bus_error_invalid_event, /**< Invalid Event            */
    bus_error_invalid_handle, /**< Invalid Handle           */
    bus_error_session_already_exist, /**< Session already opened   */
    bus_error_component_name_duplicate, /**< Comp name already exists */
    bus_error_element_name_duplicate, /**< One or more element name(s) were previously registered */
    bus_error_element_name_missing, /**< No names were provided in the name field */
    bus_error_component_does_not_exist, /**< A bus connection for this component name was not
                                           previously opened. */
    bus_error_element_does_not_exist, /**< One or more data element name(s) do not currently have a
                                         valid registration */
    bus_error_access_not_allowed, /**< Access to the requested data element was not permitted by the
                                     provider component. */
    bus_error_invalid_context, /**< The Context is not same as what was sent in the get callback
                                  handler.*/
    bus_error_timeout, /**< The operation timedout   */
    bus_error_async_response, /**< The method request will be handle asynchronously by provider */
    bus_error_invalid_method, /**< Invalid Method           */
    bus_error_nosubscribers, /**< No subscribers present   */
    bus_error_subscription_already_exist, /**< The subscription already exists*/
    bus_error_invalid_namespace, /**< Invalid namespace as per standard */
    bus_error_direct_con_not_exist /**< Direct connection not exist */
} bus_error_t;

#define VERIFY_NULL_WITH_RC(T)                                                                \
    if (NULL == (T)) {                                                                        \
        wifi_util_error_print(WIFI_CTRL, "[%s] input parameter: %s is NULL\n", __func__, #T); \
        return bus_error_invalid_input;                                                       \
    }

#ifdef __cplusplus
}
#endif

#endif // BUS_COMMON_H
