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
#ifndef HE_BUS_COMMON_H
#define HE_BUS_COMMON_H

#ifdef __cplusplus
extern "C" {
#endif

#include "collection.h"
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct _he_bus_handle *he_bus_handle_t;

#define HE_BUS_RETURN_ERR -1
#define HE_BUS_RETURN_OK 0

#define FREE_BUFF_MEMORY(buff) \
    do {                       \
        if ((buff) != NULL) {  \
            free((buff));      \
            (buff) = NULL;     \
        }                      \
    } while (0)

#define HE_BUS_MSG_IDENTIFICATION_NUM 0x12345678
#define HE_BUS_RES_RECV_TIMEOUT_S 10
#define HE_BUS_MAX_NAME_LENGTH 64

#define HE_BUS_VERIFY_NULL(T) \
    if (NULL == T) {   \
        return;        \
    }

#define HE_BUS_VERIFY_NULL_WITH_RETURN_ADDR(T) \
    if (NULL == T) {                    \
        return NULL;                    \
    }

#define HE_BUS_VERIFY_NULL_WITH_RETURN_INT(T) \
    if (NULL == T) {                   \
        return HE_BUS_RETURN_ERR;      \
    }

#define HE_BUS_NO_DATA_OBJ 0
#define HE_BUS_SINGLE_DATA_OBJ 1

typedef char he_bus_name_string_t[HE_BUS_MAX_NAME_LENGTH];
typedef char he_bus_comp_name_str_t[HE_BUS_MAX_NAME_LENGTH];

typedef enum {
    he_bus_element_type_property = 1,
    he_bus_element_type_table,
    he_bus_element_type_event,
    he_bus_element_type_method,
    he_bus_element_type_max
} he_bus_element_type_t;

typedef enum {
    he_bus_element_subtype_get = 1,
    he_bus_element_subtype_set,
    he_bus_element_subtype_notify,
    he_bus_element_subtype_type_max
} he_bus_element_subtype_t;

typedef enum {
    he_bus_data_type_boolean = 0x500,
    he_bus_data_type_char,
    he_bus_data_type_byte,
    he_bus_data_type_int8,
    he_bus_data_type_uint8,
    he_bus_data_type_int16,
    he_bus_data_type_uint16,
    he_bus_data_type_int32,
    he_bus_data_type_uint32,
    he_bus_data_type_int64,
    he_bus_data_type_uint64,
    he_bus_data_type_single,
    he_bus_data_type_double,
    he_bus_data_type_datetime,
    he_bus_data_type_string,
    he_bus_data_type_bytes,
    he_bus_data_type_property,
    he_bus_data_type_object,
    he_bus_data_value_to_string,
    he_bus_data_type_none
} he_bus_data_type_t;

typedef enum {
    he_bus_event_action_subscribe = 0,
    he_bus_event_action_unsubscribe,
} he_bus_event_sub_action_t;

typedef enum {
    he_bus_event_object_created,
    he_bus_event_object_deleted,
    he_bus_event_value_changed,
    he_bus_event_general,
    he_bus_event_initial_value,
    he_bus_event_interval,
    he_bus_event_duration_complete,
    he_bus_subscription_event
} he_bus_event_type_t;

typedef enum {
    he_bus_inital_msg = 1,
    he_bus_msg_get,
    he_bus_msg_set,
    he_bus_msg_notify,
    he_bus_msg_request,
    he_bus_msg_response
} he_bus_msg_type_t;

typedef enum {
    he_bus_msg_reg_event = 1,
    he_bus_msg_get_event,
    he_bus_msg_set_event,
    he_bus_msg_table_insert_event,
    he_bus_msg_table_remove_event,
    he_bus_msg_publish_event,
    he_bus_msg_sub_event,
    he_bus_msg_sub_ex_async_event
} he_bus_msg_sub_type_t;

typedef enum he_bus_error {
    // Generic error codes
    he_bus_error_success = 0,
    he_bus_error_general = 1,
    he_bus_error_invalid_input,
    he_bus_error_not_inttialized,
    he_bus_error_out_of_resources,
    he_bus_error_destination_not_found,
    he_bus_error_destination_not_reachable,
    he_bus_error_destination_response_failure,
    he_bus_error_invalid_response_from_destination,
    he_bus_error_invalid_operation,
    he_bus_error_invalid_event,
    he_bus_error_invalid_handle,
    he_bus_error_session_already_exist,
    he_bus_error_component_name_duplicate,
    he_bus_error_element_name_duplicate,
    he_bus_error_element_name_missing,
    he_bus_error_component_does_not_exist,
    he_bus_error_element_does_not_exist,
    he_bus_error_access_not_allowed,
    he_bus_error_invalid_context,
    he_bus_error_timeout,
    he_bus_error_async_response,
    he_bus_error_invalid_method,
    he_bus_error_nosubscribers,
    he_bus_error_subscription_already_exist,
    he_bus_error_invalid_namespace,
    he_bus_error_direct_con_not_exist
} he_bus_error_t;

typedef enum he_bus_object_type {
    he_bus_object_single_instance,
    he_bus_object_multi_instance
} he_bus_object_type_t;

typedef union he_bus_raw_data_format {
    bool b;
    char c;
    unsigned char u;
    int8_t i8;
    uint8_t u8;
    int16_t i16;
    uint16_t u16;
    int32_t i32;
    uint32_t u32;
    int64_t i64;
    uint64_t u64;
    float f32;
    double f64;
    void const *bytes;
} he_bus_raw_data_format_t;

typedef struct he_bus_raw_data {
    he_bus_data_type_t data_type;
    he_bus_raw_data_format_t raw_data;
    uint32_t raw_data_len;
} he_bus_raw_data_t;

typedef struct he_bus_stretch_buff {
    uint8_t *buff;
    uint32_t buff_len;
} he_bus_stretch_buff_t;

typedef struct he_bus_data_object {
    uint32_t name_len;
    he_bus_name_string_t name;
    he_bus_msg_sub_type_t msg_sub_type;
    bool is_data_set;
    he_bus_error_t status;
    he_bus_raw_data_t data;
    struct he_bus_data_object *next_data;
} he_bus_data_object_t;

typedef struct he_bus_raw_data_msg {
    uint32_t bus_msg_identity;
    uint32_t total_raw_msg_len;
    uint32_t component_name_len;
    he_bus_comp_name_str_t component_name;
    he_bus_msg_type_t msg_type;
    uint32_t num_of_obj;
    he_bus_data_object_t data_obj;
} he_bus_raw_data_msg_t;

typedef struct sub_payload_data {
    he_bus_event_sub_action_t action;
    uint32_t interval;
} sub_payload_data_t;

typedef struct he_bus_mgr {
    bool bus_server_init;
    pthread_t bus_broadcast_server_tid;
    pthread_t bus_unicast_server_tid;
    pthread_t bus_client_tid;
    hash_map_t *bus_main_handle;
} he_bus_mgr_t;

he_bus_mgr_t *get_bus_mgr_object(void);
void *get_bus_user_cb(hash_map_t *user_cb_map, char *name);

#ifdef __cplusplus
}
#endif
#endif // HE_BUS_COMMON_H
