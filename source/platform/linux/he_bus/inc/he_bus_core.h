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
#ifndef HE_BUS_CORE_H
#define HE_BUS_CORE_H

#ifdef __cplusplus
extern "C" {
#endif

#include "collection.h"
#include "he_bus_common.h"
#include "he_bus_connection.h"
#include <pthread.h>
#include <stdint.h>

#define HE_BUS_ERROR_CHECK(CMD)                                                                      \
    {                                                                                         \
        int err;                                                                              \
        if ((err = CMD) != 0) {                                                               \
            he_bus_core_error_print("Error %d:%s running command " #CMD, err, strerror(err)); \
        }                                                                                     \
    }

#define INIT_HANDLE_MUTEX(handle_mutex)                                            \
    {                                                                              \
        pthread_mutexattr_t attrib;                                                \
        HE_BUS_ERROR_CHECK(pthread_mutexattr_init(&attrib));                              \
        HE_BUS_ERROR_CHECK(pthread_mutexattr_settype(&attrib, PTHREAD_MUTEX_ERRORCHECK)); \
        HE_BUS_ERROR_CHECK(pthread_mutex_init(&handle_mutex, &attrib));                   \
    }

#define DEINIT_HANDLE_MUTEX(handle_mutex)                  \
    {                                                      \
        HE_BUS_ERROR_CHECK(pthread_mutex_destroy(&handle_mutex)); \
    }

#define HANDLE_LOCK(handle_mutex)                      \
    {                                                  \
        HE_BUS_ERROR_CHECK(pthread_mutex_lock(&handle_mutex)) \
    }

#define HANDLE_UNLOCK(handle_mutex)                      \
    {                                                    \
        HE_BUS_ERROR_CHECK(pthread_mutex_unlock(&handle_mutex)) \
    }

#define ELM_LOCK(l_mutex)                         \
    {                                             \
        HE_BUS_ERROR_CHECK(pthread_mutex_lock(&l_mutex)) \
    }

#define ELM_UNLOCK(l_mutex)                         \
    {                                               \
        HE_BUS_ERROR_CHECK(pthread_mutex_unlock(&l_mutex)) \
    }

#define DEINIT_ELM_MUTEX(l_mutex)                     \
    {                                                 \
        HE_BUS_ERROR_CHECK(pthread_mutex_destroy(&l_mutex)); \
    }

typedef enum child_node_reference { actual_child_node, ref_child_node } child_node_reference_t;

typedef struct he_bus_object he_bus_object_t;
typedef struct element_node element_node_t;
typedef struct data_model_prop data_model_prop_t;
typedef struct _he_bus_handle *he_bus_handle_t;

typedef he_bus_error_t (*he_bus_get_handler_t)(char *event_name, he_bus_raw_data_t *p_data, void *user_data);
typedef he_bus_error_t (*he_bus_set_handler_t)(char *event_name, he_bus_raw_data_t *p_data, void *user_data);
typedef he_bus_error_t (*he_bus_table_add_row_handler_t)(char const *tableName,
    char const *aliasName, uint32_t *instNum);
typedef he_bus_error_t (*he_bus_table_remove_row_handler_t)(char const *rowName);
typedef he_bus_error_t (*he_bus_method_handler_t)(char const *methodName,
    he_bus_raw_data_t *inParams, he_bus_raw_data_t *outParams, void *asyncHandle);
typedef he_bus_error_t (*he_bus_event_sub_handler_t)(char *eventName,
    he_bus_event_sub_action_t action, int32_t interval, bool *autoPublish);

typedef he_bus_error_t (
    *he_bus_event_consumer_sub_handler_t)(char *event_name, he_bus_raw_data_t *p_data, void *userData);
typedef he_bus_error_t (*he_bus_event_sub_ex_async_handler_t)(char *event_name, he_bus_error_t ret, void *userData);

typedef struct he_bus_callback_table {
    he_bus_get_handler_t get_handler; /**< Get parameters handler for the named paramter   */
    he_bus_set_handler_t set_handler; /**< Set parameters handler for the named parameter  */
    he_bus_table_add_row_handler_t table_add_row_handler; /**< Add row handler to a table*/
    he_bus_table_remove_row_handler_t table_remove_row_handler; /**< Remove a row from a table*/
    he_bus_event_sub_handler_t event_sub_handler; /**< Event subscribe and unsubscribe
                                                       handler for the event name */
    he_bus_method_handler_t method_handler; /**< Method handler  */
} he_bus_callback_table_t;

typedef struct he_bus_sub_callback_table {
    he_bus_event_consumer_sub_handler_t sub_handler;
    he_bus_event_sub_ex_async_handler_t sub_ex_async_handler;
} he_bus_sub_callback_table_t;

typedef struct {
    char *full_name; /* full name/path of element */
    he_bus_element_type_t type; /**< Type of an element */
    he_bus_callback_table_t cb_table; /**< Element Handler table. A specific
                                       callback can be NULL, if no usage */
    uint8_t bus_speed;
    uint32_t num_of_table_row; /**< If we have table rows then we need to set some number otherwise
                                  this parameter value is zero */
} he_bus_data_element_t;

typedef struct he_bus_object {
    he_bus_name_string_t name;
    he_bus_object_type_t type; /*single or multi-instance*/
    hash_map_t *properties; /*the list of properties(tr181 parameters) on this object*/
} he_bus_object_t;

typedef struct {
    he_bus_name_string_t name; /**< Fully qualified event name */
    he_bus_event_type_t type; /**< The type of event */
    queue_t *data_queue; /**< The raw data queue for the event */
    queue_t *priority_data_queue; /**< The raw priority data queue for the priority event only */
} he_bus_event_t;

typedef struct subscription_element {
    he_bus_comp_name_str_t component_name;
    he_bus_name_string_t full_name;
    int socket_fd;
    he_bus_event_sub_action_t action;
} subscription_element_t;

typedef struct own_sub_element {
    // bus_name_string_t       full_name;  //sub map key
    int socket_fd;
    he_bus_event_sub_action_t action;
    uint32_t interval;
    he_bus_sub_callback_table_t sub_cb_table;
} own_sub_element_t;

typedef struct he_bus_event_sub {
    char const *event_name;
    he_bus_event_sub_action_t action;
    uint32_t interval;
    he_bus_sub_callback_table_t handler;
} he_bus_event_sub_t;

typedef struct data_model_prop {
    he_bus_data_type_t data_format;
    bool data_permission;
    long int min_data_range;
    long int max_data_range;
    int num_of_str_validation;
    char **str_validation;
} data_model_prop_t;

typedef struct element_node {
    char name[64]; /* relative name of element */
    he_bus_name_string_t full_name; /* full name/path of element */
    he_bus_element_type_t type; /**< Type of an element */
    he_bus_callback_table_t cb_table; /**< Element Handler table. A specific
                                       callback can be NULL, if no usage */
    /* use component name to create a hash map key
     * we can use this subscription_element_t structure to store subscriber info
     */
    hash_map_t *subscriptions; /* The list of BUSSubscription_t to this element */
    element_node_t *parent; /* Up */
    element_node_t *child; /* Downward */
    element_node_t *nextSibling; /* Right */
    pthread_mutex_t element_mutex; /* To protect if there is a direct/private connection */
    unsigned char bus_speed;
    data_model_prop_t data_model_value;
    child_node_reference_t reference_childs;
} element_node_t;

typedef struct _he_bus_handle {
    he_bus_name_string_t component_name;
    uint32_t component_id;
    element_node_t *root_element; /* This object content this(element_node_t) structure info */
    hash_map_t *sub_map; /* use this("own_sub_element_t") structure for map
                            info and namespace is key. */
    he_bus_conn_info_t conn_info;
    pthread_mutex_t handle_mutex;
} he_bus_handle;

typedef struct traversal_cb_param {
    union {
        hash_map_t *node_data;
        char *comp_name;
    } u;
} traversal_cb_param_t;

typedef void (*he_bus_traversal_callback)(element_node_t *node, traversal_cb_param_t param);

typedef struct node_element_traversal_arg {
    he_bus_traversal_callback traversal_cb;
    traversal_cb_param_t param;
} node_element_traversal_arg_t;

typedef struct node_element_persistent_data {
    hash_map_t *subscriptions;
} node_element_persistent_data_t;

element_node_t *get_empty_element_node(void);
element_node_t *bus_insert_element(he_bus_handle_t handle, element_node_t *root,
    he_bus_data_element_t *elem);
void printRegisteredElements(element_node_t *root, int level);
element_node_t *retrieve_instance_element(he_bus_handle_t handle, element_node_t *root,
    const char *elmentName);
he_bus_error_t update_bus_tree(he_bus_handle_t old_bus_handle, const char *json_name);
he_bus_error_t free_node_elements(he_bus_handle_t handle, element_node_t *node);
he_bus_error_t bus_remove_all_elements(he_bus_handle_t handle);

he_bus_error_t remove_client_all_details(he_bus_handle_t handle, char *comp_name);

void free_bus_msg_obj_data(he_bus_data_object_t *p_obj_data);
he_bus_error_t bus_event_sub_to_provider(he_bus_handle_t handle, he_bus_event_sub_t *sub_data_map,
    uint32_t num_of_sub);
void free_raw_data_struct(he_bus_raw_data_t *p_data);

he_bus_error_t he_bus_server_init(he_bus_handle_t *handle, char *component_name);
he_bus_error_t he_bus_open(he_bus_handle_t *handle, char *component_name);
he_bus_error_t he_bus_close(he_bus_handle_t handle);
he_bus_error_t he_bus_reg_data_elem(he_bus_handle_t handle, he_bus_data_element_t *p_bus_reg_data,
    uint32_t num_of_elem);
he_bus_error_t he_bus_event_sub(he_bus_handle_t handle, char const *event_name,
    he_bus_event_consumer_sub_handler_t sub_handler, uint32_t interval);
he_bus_error_t he_bus_event_sub_ex(he_bus_handle_t handle, he_bus_event_sub_t *p_sub_data_map,
    uint32_t num_of_sub, uint32_t timeout);
he_bus_error_t he_bus_event_sub_ex_async(he_bus_handle_t handle, he_bus_event_sub_t *sub_map,
    uint32_t num_of_sub, he_bus_event_sub_ex_async_handler_t sub_ex_async_handler,
    uint32_t timeout);
// caller needs to free allocated memory
he_bus_error_t he_bus_get_data(he_bus_handle_t handle, char const *event_name, he_bus_raw_data_t *p_data);
he_bus_error_t he_bus_set_data(he_bus_handle_t handle, char const *event_name, he_bus_raw_data_t *p_data);
he_bus_error_t he_bus_publish_event(he_bus_handle_t handle, char const *event_name,
    he_bus_raw_data_t *p_data);

#ifdef __cplusplus
}
#endif
#endif // HE_BUS_CORE_H
