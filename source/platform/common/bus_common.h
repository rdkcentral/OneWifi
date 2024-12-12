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

#define VERIFY_NULL(T) \
    do { \
        if (NULL == (T)) { \
            wifi_util_error_print(WIFI_BUS, "%s:%d Parameter '%s' is NULL\n", \
                   __func__, __LINE__, #T); \
            return; \
        } \
    } while(0)

#define VERIFY_NULL_WITH_RETURN_ADDR(T) \
    do { \
        if (NULL == (T)) { \
            wifi_util_error_print(WIFI_BUS, "%s:%d Parameter '%s' is NULL\n", \
                   __func__, __LINE__, #T); \
            return NULL; \
        } \
    } while(0)

#define VERIFY_NULL_WITH_RETURN_INT(T) \
    do { \
        if (NULL == (T)) { \
            wifi_util_error_print(WIFI_BUS, "%s:%d Parameter '%s' is NULL\n", \
                   __func__, __LINE__, #T); \
            return RETURN_ERR; \
        } \
    } while(0)

#define BUS_CHECK_NULL_WITH_RC(ptr, rc) \
    do { \
        if ((ptr) == NULL) { \
            wifi_util_error_print(WIFI_BUS, "%s:%d Parameter '%s' is NULL\n", \
                   __func__, __LINE__, #ptr); \
            return (rc); \
        } \
    } while (0)

#define BUS_SERVER_PROCESS_NAME     "OneWifi"
#define BUS_MAX_NAME_LENGTH         128
#define BUS_NODE_NAME               80
#define ZERO_TABLE                  0
#define UNREFERENCED_PARAMETER(_p_) (void)(_p_)

#define BUS_METHOD_GET              0
#define BUS_METHOD_SET              1

#define ERROR_CHECK(CMD) \
    do { \
        int l_error; \
        if ((l_error = CMD) != 0) { \
            wifi_util_info_print(WIFI_CTRL, "Error %d: running command " #CMD, l_error); \
        } \
    } while (0)

#define DEINIT_MUTEX(mutex) \
    do { \
        ERROR_CHECK(pthread_mutex_destroy(&mutex)); \
    } while (0)

#define INIT_MUTEX(mutex) \
    do { \
        pthread_mutexattr_t attrib; \
        ERROR_CHECK(pthread_mutexattr_init(&attrib)); \
        ERROR_CHECK(pthread_mutexattr_settype(&attrib, PTHREAD_MUTEX_ERRORCHECK)); \
        ERROR_CHECK(pthread_mutex_init(&mutex, &attrib)); \
    } while (0)

#define BUS_MUX_LOCK(l_mutex) \
    do { \
        ERROR_CHECK(pthread_mutex_lock(l_mutex)); \
    } while (0)

#define BUS_MUX_UNLOCK(l_mutex) \
    do { \
        ERROR_CHECK(pthread_mutex_unlock(l_mutex)); \
    } while (0)

typedef char bus_name_string_t[BUS_MAX_NAME_LENGTH];

typedef enum
{
    bus_data_type_boolean = 0x500,
    bus_data_type_char,
    bus_data_type_byte,
    bus_data_type_int8,
    bus_data_type_uint8,
    bus_data_type_int16,
    bus_data_type_uint16,
    bus_data_type_int32,
    bus_data_type_uint32,
    bus_data_type_init64,
    bus_data_type_uint64,
    bus_data_type_single,
    bus_data_type_double,
    bus_data_type_datetime,
    bus_data_type_string,
    bus_data_type_bytes,
    bus_data_type_property,
    bus_data_type_object,
    bus_data_type_none
} bus_data_type_t;

typedef enum {
    bus_element_type_property = 1,
    bus_element_type_table,
    bus_element_type_event,
    bus_element_type_method,
    bus_element_type_max
} bus_element_type_t;

typedef enum bus_speed {
    slow_speed,
    mid_speed,
    high_speed
} bus_speed_t;

typedef enum
{
    bus_event_action_subscribe = 0,
    bus_event_action_unsubscribe,
} bus_event_sub_action_t;

typedef enum bus_error
{
    //Bus generic error codes
    bus_error_success                  = 0,    /**< Succes                   */
    bus_error_general                  = 1,    /**< General Error            */
    bus_error_invalid_input,                   /**< Invalid Input            */
    bus_error_not_inttialized,                 /**< Bus not initialized      */
    bus_error_out_of_resources,                /**< Running out of resources */
    bus_error_destination_not_found,           /**< Dest element not found   */
    bus_error_destination_not_reachable,       /**< Dest element not reachable*/
    bus_error_destination_response_failure,    /**< Dest failed to respond   */
    bus_error_invalid_response_from_destination,/**< Invalid dest response   */
    bus_error_invalid_operation,               /**< Invalid Operation        */
    bus_error_invalid_event,                   /**< Invalid Event            */
    bus_error_invalid_handle,                  /**< Invalid Handle           */
    bus_error_session_already_exist,           /**< Session already opened   */
    bus_error_component_name_duplicate,        /**< Comp name already exists */
    bus_error_element_name_duplicate,          /**< One or more element name(s) were previously registered */
    bus_error_element_name_missing,            /**< No names were provided in the name field */
    bus_error_component_does_not_exist,        /**< A bus connection for this component name was not previously opened. */
    bus_error_element_does_not_exist,          /**< One or more data element name(s) do not currently have a valid registration */
    bus_error_access_not_allowed,              /**< Access to the requested data element was not permitted by the provider component. */
    bus_error_invalid_context,                 /**< The Context is not same as what was sent in the get callback handler.*/
    bus_error_timeout,                         /**< The operation timedout   */
    bus_error_async_response,                  /**< The method request will be handle asynchronously by provider */
    bus_error_invalid_method,                  /**< Invalid Method           */
    bus_error_nosubscribers,                   /**< No subscribers present   */
    bus_error_subscription_already_exist,      /**< The subscription already exists*/
    bus_error_invalid_namespace,               /**< Invalid namespace as per standard */
    bus_error_direct_con_not_exist             /**< Direct connection not exist */
} bus_error_t;

#define VERIFY_NULL_WITH_RC(T) \
    if (NULL == (T)) { \
        wifi_util_error_print(WIFI_CTRL, "[%s] input parameter: %s is NULL\n", __func__, #T); \
        return bus_error_invalid_input; \
    }

typedef enum child_node_ref {
    original_child_node,
    reference_child_node
} child_node_ref_t;

typedef enum node_elem_data_type {
    node_elem_reg_data = 1,
    node_elem_sub_data,
} node_elem_data_type_t;

typedef struct data_model_properties {
    bus_data_type_t  data_format;
    bool             data_permission;
    long int         min_data_range;
    long int         max_data_range;
    uint32_t         num_of_str_validation;
    char             **str_validation;
} data_model_properties_t;

typedef union raw_data_format{
    bool           b;
    char           c;
    unsigned char  u;
    int8_t         i8;
    uint8_t        u8;
    int16_t        i16;
    uint16_t       u16;
    int32_t        i32;
    uint32_t       u32;
    int64_t        i64;
    uint64_t       u64;
    float          f32;
    double         f64;
    void           *bytes;
} raw_data_format_t;

typedef struct raw_data {
    bus_data_type_t          data_type;
    raw_data_format_t        raw_data;
    unsigned int             raw_data_len;
} raw_data_t;

typedef struct bus_event_sub bus_event_sub_t;
typedef struct elem_node_map elem_node_map_t;
typedef struct bus_handle bus_handle_t;
typedef struct bus_data_element bus_data_element_t;

typedef bus_error_t (*bus_get_handler_t)(char *event_name, raw_data_t *p_data);
typedef bus_error_t (*bus_set_handler_t)(char *event_name, raw_data_t *p_data);
typedef bus_error_t (*bus_table_add_row_handler_t)(char const* tableName, char const* aliasName, uint32_t* instNum);
typedef bus_error_t (*bus_table_remove_row_handler_t)(char const* rowName);
typedef bus_error_t (*bus_method_handler_t)(char const* methodName, raw_data_t *inParams, raw_data_t *outParams, void *asyncHandle);
typedef bus_error_t (*bus_name_sub_handler_t)(char *eventName, bus_event_sub_action_t action, int32_t interval, bool* autoPublish);

typedef bus_error_t (*bus_event_sub_handler_t)(char *event_name, raw_data_t *p_data);
typedef bus_error_t (*bus_event_sub_ex_async_handler_t)(char *event_name, bus_error_t ret);

/* Following are bus function pointers */
typedef bus_error_t (* wifi_bus_init_t)                         (bus_handle_t *handle);
typedef bus_error_t (* wifi_bus_open_t)                         (bus_handle_t *handle, char *component_name);
typedef bus_error_t (* wifi_bus_close_t)                        (bus_handle_t *handle);
typedef bus_error_t (* wifi_bus_data_get_t)                     (bus_handle_t *handle, char const *name, raw_data_t *data);
typedef void        (* wifi_bus_data_free_t)                    (raw_data_t *data);
typedef bus_error_t (* wifi_bus_set_t)                          (bus_handle_t *handle, char const *name, raw_data_t *data);
typedef bus_error_t (* wifi_bus_event_publish_t)                (bus_handle_t *handle, char const *name, raw_data_t *data);
typedef bus_error_t (* wifi_bus_get_trace_context_t)            (bus_handle_t *handle, char* traceParent, uint32_t traceParentLength, char* traceState, uint32_t traceStateLength);
typedef bus_error_t (* wifi_bus_raw_event_publish_t)            (bus_handle_t *handle, char *name, void *data, uint32_t size);
typedef bus_error_t (* wifi_bus_set_str_t)                      (bus_handle_t *handle, char const* param_name, char const *param_str);
typedef bus_error_t (* wifi_bus_event_subs_t)                   (bus_handle_t *handle, char const* event_name, void *cb, void *userData, int timeout);
typedef bus_error_t (* wifi_bus_event_subscribe_ex_t)           (bus_handle_t *handle, bus_event_sub_t *l_sub_info_map, int num_sub, int timeout);
typedef bus_error_t (* wifi_bus_event_subscribe_ex_async_t)     (bus_handle_t *handle, bus_event_sub_t *l_sub_info_map, int num_sub, void *l_sub_handler, int timeout);
typedef bus_error_t (* wifi_bus_reg_elements_t)                 (bus_handle_t *handle, bus_data_element_t *data_element, uint32_t num_of_element);
typedef bus_error_t (* wifi_bus_method_invoke_t)                (bus_handle_t *handle, void *paramName, char *event, raw_data_t *input_data, raw_data_t *output_data, bool input_bus_data);
typedef bus_error_t (* wifi_bus_reg_table_row_t)                (bus_handle_t *handle, char const *name, uint32_t row_index, char const *alias);
typedef bus_error_t (* wifi_bus_unreg_table_row_t)              (bus_handle_t *handle, char const *name);
typedef bus_error_t (* wifi_bus_remove_table_row_t)             (bus_handle_t *handle, char const *name);

typedef struct {
    wifi_bus_init_t                bus_init_fn;
    wifi_bus_open_t                bus_open_fn;
    wifi_bus_close_t               bus_close_fn;
    wifi_bus_data_get_t            bus_data_get_fn;
    wifi_bus_data_free_t           bus_data_free_fn;
    wifi_bus_set_t                 bus_set_fn;
    wifi_bus_reg_elements_t        bus_reg_data_element_fn;
    wifi_bus_event_publish_t       bus_event_publish_fn;
    wifi_bus_raw_event_publish_t   bus_raw_event_publish_fn;
    wifi_bus_set_str_t             bus_set_string_fn;
    wifi_bus_event_subs_t          bus_event_subs_fn;
    wifi_bus_event_subscribe_ex_t  bus_event_subs_ex_fn;
    wifi_bus_event_subscribe_ex_async_t  bus_event_subs_ex_async_fn;
    wifi_bus_method_invoke_t       bus_method_invoke_fn;
    wifi_bus_get_trace_context_t   bus_get_trace_context_fn;
    wifi_bus_reg_table_row_t       bus_reg_table_row_fn;
    wifi_bus_unreg_table_row_t     bus_unreg_table_row_fn;
    wifi_bus_remove_table_row_t    bus_remove_table_row_fn;
} wifi_bus_desc_t;

typedef struct bus_event_sub {
    char const*         event_name;
    void *              filter;
    uint32_t            interval;
    uint32_t            duration;
    void*               handler;
    void*               user_data;
    void*               handle;
    bus_event_sub_ex_async_handler_t async_handler;
    bool                publish_on_sub;
} bus_event_sub_t;


typedef struct bus_callback_table {
    bus_get_handler_t              get_handler;
    bus_set_handler_t              set_handler;
    bus_table_add_row_handler_t    table_add_row_handler;
    bus_table_remove_row_handler_t table_remove_row_handler;
    bus_name_sub_handler_t         event_sub_handler;
    bus_method_handler_t           method_handler;
} bus_callback_table_t;

typedef struct bus_sub_callback_table {
    bus_event_sub_handler_t           sub_handler;
    bus_event_sub_ex_async_handler_t  sub_ex_async_handler;
} bus_sub_callback_table_t;

typedef struct bus_data_element {
    char *                      full_name;
    bus_element_type_t          type;
    bus_callback_table_t        cb_table;
    bus_speed_t                 bus_speed;
    uint32_t                    num_of_table_row;
    data_model_properties_t     data_model_prop;
} bus_data_element_t;

typedef struct {
    char                        *full_name;
    bus_element_type_t          type;
    node_elem_data_type_t       node_data_type;
    void                        *cfg_data;
    uint32_t                    cfg_data_len;
    uint32_t                    num_of_table_row;
} bus_mux_data_elem_t;

typedef struct bus_mux_reg_node_data {
    bus_callback_table_t     cb_table;
    data_model_properties_t  data_model_prop;
} bus_mux_reg_node_data_t;

typedef struct bus_mux_sub_node_data {
    bus_sub_callback_table_t cb_table;
} bus_mux_sub_node_data_t;

typedef struct elem_node_map
{
    char                     name[BUS_NODE_NAME];
    bus_name_string_t        full_name;
    bus_element_type_t       type;
    node_elem_data_type_t    node_data_type;
    void                     *node_elem_data;
    uint32_t                 node_elem_data_len;
    elem_node_map_t          *parent;
    elem_node_map_t          *child;
    elem_node_map_t          *nextSibling;
    child_node_ref_t         reference_childs;
} elem_node_map_t;

typedef struct bus_cb_multiplexing {
    elem_node_map_t  *bus_reg_cb_root;
    elem_node_map_t  *bus_sub_cb_root;
    pthread_mutex_t  bus_mux_mutex;
} bus_cb_multiplexing_t;

typedef struct node_traversal_cb_param
{
    union {
        char       *comp_name;
    } u;
} node_traversal_cb_param_t;

typedef void (*bus_traversal_callback)(elem_node_map_t* node, node_traversal_cb_param_t param);

typedef struct node_elem_traversal_arg
{
    bus_traversal_callback     traversal_cb;
    node_traversal_cb_param_t  param;
} node_elem_traversal_arg_t;

elem_node_map_t *get_bus_mux_reg_cb_map(void);
elem_node_map_t *get_bus_mux_sub_cb_map(void);
elem_node_map_t* retrieve_instance_elem_node(elem_node_map_t* root, const char* elmentName);
elem_node_map_t* bus_insert_elem_node(elem_node_map_t* root, bus_mux_data_elem_t* elem);
bus_error_t bus_remove_all_elems(elem_node_map_t *root);
elem_node_map_t *get_bus_node_info(elem_node_map_t *cb_root, char *name);
bus_error_t bus_table_add_row(elem_node_map_t *p_root_node, char *name_space, uint32_t table_index);
bus_error_t bus_table_remove_row(elem_node_map_t *p_root_node, char *p_name_space);
void print_registered_elems(elem_node_map_t *root, int level);

int validate_dm_set_parameters(data_model_properties_t *data_model_prop, raw_data_t *bus_set_data);

#ifdef __cplusplus
}
#endif

#endif // BUS_COMMON_H
