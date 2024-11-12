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
#include "he_bus_core.h"
#include "he_bus_common.h"
#include "he_bus_data_conversion.h"
#include "he_bus_json_decode.h"
#include "he_bus_memory.h"
#include "he_bus_utils.h"

#define VERIFY_NULL_WITH_RC(T)                                                       \
    if (NULL == (T)) {                                                               \
        he_bus_core_error_print("[%s] input parameter: %s is NULL\n", __func__, #T); \
        return he_bus_error_invalid_input;                                           \
    }

static he_bus_error_t bus_component_param_init(he_bus_mgr_t *bus_mgr, he_bus_handle_t *handle,
    char *component_name)
{
    if (bus_mgr == NULL || handle == NULL || component_name == NULL) {
        he_bus_core_error_print("%s:%d invalid parameter on bus component init\r\n", __func__,
            __LINE__);
        return he_bus_error_invalid_input;
    }

    if (bus_mgr->bus_main_handle == NULL) {
        bus_mgr->bus_main_handle = hash_map_create();
        if (bus_mgr->bus_main_handle == NULL) {
            he_bus_core_error_print("%s:%d bus main object init falied\r\n", __func__, __LINE__);
            return he_bus_error_general;
        }
    }
    he_bus_handle_t bus_handle_obj = hash_map_get(bus_mgr->bus_main_handle, component_name);
    if (bus_handle_obj == NULL) {
        static unsigned int component_id = 0;

        bus_handle_obj = he_bus_malloc(sizeof(he_bus_handle));
        if (bus_handle_obj == NULL) {
            he_bus_core_error_print("%s:%d bus object malloc is falied for %s:\r\n", __func__,
                __LINE__, component_name);
            return he_bus_error_general;
        }

        bus_handle_obj->root_element = get_empty_element_node();
        if (bus_handle_obj->root_element == NULL) {
            he_bus_core_error_print("%s:%d bus root object create is falied for %s:\r\n", __func__,
                __LINE__, component_name);
            he_bus_free(bus_handle_obj);
            return he_bus_error_general;
        }
        strncpy(bus_handle_obj->component_name, component_name, strlen(component_name) + 1);
        bus_handle_obj->component_id = ++component_id;

        bus_handle_obj->sub_map = hash_map_create();
        INIT_HANDLE_MUTEX(bus_handle_obj->handle_mutex);

        hash_map_put(bus_mgr->bus_main_handle, strdup(component_name), bus_handle_obj);
        he_bus_core_info_print("%s:%d bus object is initialized for %s: id:%d\r\n", __func__,
            __LINE__, component_name, bus_handle_obj->component_id);
    } else {
        he_bus_core_info_print("%s:%d bus object already initialized for %s\r\n", __func__,
            __LINE__, component_name);
    }
    *handle = bus_handle_obj;
    return he_bus_error_success;
}

static he_bus_error_t bus_component_param_deinit(he_bus_handle_t handle)
{
    if (handle == NULL) {
        he_bus_core_error_print("%s:%d invalid parameter on bus component deinit\r\n", __func__,
            __LINE__);
        return he_bus_error_invalid_input;
    }
    he_bus_mgr_t *bus_mgr = get_bus_mgr_object();
    he_bus_conn_info_t *conn_info = get_bus_connection_object(handle);
    he_bus_client_info_t *p_client_info = &conn_info->client_info;

    if (bus_mgr->bus_main_handle == NULL) {
        he_bus_core_error_print("%s:%d bus main object deinit falied\r\n", __func__, __LINE__);
        return he_bus_error_general;
    }

    bus_remove_all_elements(handle);
    hash_map_destroy(handle->sub_map);
    he_bus_core_info_print(
        "%s:%d bus handle deinit:%p server connection state:%d client state:%d\r\n", __func__,
        __LINE__, handle, conn_info->server_info.is_running, p_client_info->is_running);
    conn_info->server_info.is_running = 0;
    p_client_info->is_running = 0;
    DEINIT_HANDLE_MUTEX(handle->handle_mutex);
    handle = hash_map_remove(bus_mgr->bus_main_handle, handle->component_name);
    if (handle != NULL) {
        he_bus_core_info_print("%s:%d bus handle deinit:%p success\r\n", __func__, __LINE__,
            handle);
        he_bus_free(handle);
    }
    return he_bus_error_success;
}

he_bus_error_t he_bus_server_init(he_bus_handle_t *handle, char *component_name)
{
    he_bus_error_t status = he_bus_error_success;
    he_bus_mgr_t *bus_mgr = get_bus_mgr_object();

    if (bus_mgr->bus_server_init != true) {
        status = bus_component_param_init(bus_mgr, handle, component_name);
        if (status != he_bus_error_success) {
            he_bus_core_error_print("%s:%d bus init failed for %s\r\n", __func__, __LINE__,
                component_name);
            return status;
        }
        // start server
        he_bus_conn_info_t *conn_info = get_bus_connection_object(*handle);
        conn_info->server_info.is_running = true;

        if (pthread_create(&bus_mgr->bus_broadcast_server_tid, NULL,
                ipc_unix_broadcast_server_start, *handle) != 0) {
            he_bus_core_error_print(":%s broadcast server thread create error\n", __func__);
            return he_bus_error_not_inttialized;
        }

        if (pthread_create(&bus_mgr->bus_unicast_server_tid, NULL, ipc_unix_unicast_server_start,
                *handle) != 0) {
            he_bus_core_error_print(":%s unicast server thread create error\n", __func__);
            return he_bus_error_not_inttialized;
        }

        bus_mgr->bus_server_init = true;
    } else {
        he_bus_core_info_print("%s:%d bus component already init for %s\r\n", __func__, __LINE__,
            component_name);
    }
    return status;
}

he_bus_error_t he_bus_open(he_bus_handle_t *handle, char *component_name)
{
    he_bus_error_t status = he_bus_error_success;
    he_bus_mgr_t *bus_mgr = get_bus_mgr_object();

    status = bus_component_param_init(bus_mgr, handle, component_name);
    if (status != he_bus_error_success) {
        he_bus_core_error_print("%s:%d bus init failed for %s\r\n", __func__, __LINE__,
            component_name);
        return status;
    }
    // start client
    he_bus_conn_info_t *conn_info = get_bus_connection_object(*handle);
    conn_info->client_info.is_running = true;

    if (pthread_create(&bus_mgr->bus_client_tid, NULL, ipc_unix_broadcast_client_start, *handle) !=
        0) {
        he_bus_core_error_print(":%s broadcast client thread create error\n", __func__);
        return he_bus_error_not_inttialized;
    }

    return status;
}

he_bus_error_t he_bus_close(he_bus_handle_t handle)
{
    return bus_component_param_deinit(handle);
}

element_node_t *get_empty_element_node(void)
{
    element_node_t *node;
    pthread_mutexattr_t attrib;

    node = (element_node_t *)he_bus_calloc(1, sizeof(element_node_t));
    node->type = 0; // default of zero means OBJECT and if this gets used as a leaf, it will get
                    // update to be a either parameter, event, or method
    ERROR_CHECK(pthread_mutexattr_init(&attrib));
    ERROR_CHECK(pthread_mutexattr_settype(&attrib, PTHREAD_MUTEX_ERRORCHECK));
    ERROR_CHECK(pthread_mutex_init(&node->element_mutex, &attrib));
    node->reference_childs = actual_child_node;

    return node;
}

he_bus_error_t insert_new_table_row(element_node_t *table_root, char *node_name)
{
    element_node_t *current_node = table_root;
    element_node_t *temp_node = NULL;
    element_node_t *next_node = NULL;
    char buff[128];

    next_node = current_node->child;

    while (next_node != NULL) {
        he_bus_core_dbg_print("child name=[%s], Token = [%s]\r\n", next_node->name, node_name);
        if (strcmp(next_node->name, node_name) == 0) {
            he_bus_core_dbg_print("child name=[%s], Token = [%s] already present\r\n",
                next_node->name, node_name);
            break;
        } else {
            current_node = next_node;
            next_node = current_node->nextSibling;
            if (next_node == NULL) {
                he_bus_core_dbg_print("Create Sibling [%s]\r\n", node_name);
                temp_node = get_empty_element_node();
                temp_node->parent = current_node->parent;
                if (strlen(current_node->parent->full_name) != 0) {
                    snprintf(buff, sizeof(buff), "%s.%s", current_node->parent->full_name,
                        node_name);
                } else {
                    snprintf(buff, sizeof(buff), "%s", node_name);
                }
                he_bus_core_dbg_print("Full name [%s]\r\n", buff);
                strncpy(temp_node->full_name, buff, strlen(buff) + 1);
                strncpy(temp_node->name, node_name, strlen(node_name) + 1);
                current_node->nextSibling = temp_node;
                current_node = temp_node;
                break;
            }
        }
    }
    return he_bus_error_success;
}

he_bus_error_t add_table_row(he_bus_handle_t handle, element_node_t *table_root,
    unsigned int num_of_table_row)
{
    (void)handle;
    char str_node_index_name[8];
    uint32_t index = 0;

    if (table_root->cb_table.table_add_row_handler) {
        ELM_LOCK(table_root->element_mutex);
        for (unsigned int i = 1; i <= num_of_table_row; i++) {
            if (table_root->cb_table.table_add_row_handler(table_root->full_name, " ", &index) ==
                he_bus_error_success) {
                // index = i;
                snprintf(str_node_index_name, sizeof(str_node_index_name), "%d", index);
                insert_new_table_row(table_root, str_node_index_name);
            } else {
                he_bus_core_error_print("table row add failure for %s\r\n", table_root->full_name);
            }
        }
        ELM_UNLOCK(table_root->element_mutex);
    } else {
        he_bus_core_error_print("table row add handler not found for %s\r\n",
            table_root->full_name);
        return he_bus_error_invalid_handle;
    }
    return he_bus_error_success;
}

element_node_t *link_tables_with_new_node(element_node_t *parent_node)
{
    VERIFY_NULL_WITH_RETURN_ADDR(parent_node);

    element_node_t *child_node_reference = parent_node->child;
    element_node_t *next_node = parent_node->nextSibling;
    while (next_node) {
        if (next_node->child == NULL) {
            next_node->child = child_node_reference;
            next_node->reference_childs = ref_child_node;
        }
        next_node = next_node->nextSibling;
    }
    return child_node_reference;
}

bool is_grandparent_node_is_table(element_node_t *cur_parent)
{
    element_node_t *grandparent_node = ((cur_parent != NULL) ? cur_parent->parent : NULL);
    if (grandparent_node && grandparent_node->type == he_bus_element_type_table) {
        return true;
    }
    return false;
}

element_node_t *bus_insert_element(he_bus_handle_t handle, element_node_t *root,
    he_bus_data_element_t *elem)
{
    char *token = NULL;
    char *saveptr = NULL;
    he_bus_name_string_t name;
    element_node_t *current_node = root;
    element_node_t *temp_node = NULL;
    element_node_t *next_node = NULL;
    int ret = 0, create_child = 0;
    char buff[128];

    if (current_node == NULL || elem == NULL) {
        return NULL;
    }
    HANDLE_LOCK(handle->handle_mutex);
    next_node = current_node->child;
    create_child = 1;

    he_bus_core_error_print("Request to insert element [%s]!!\r\n", elem->full_name);

    strncpy(name, elem->full_name, strlen(elem->full_name) + 1);

    /* If this is a table being registered using .{i}. syntax, such as
       "Device.WiFi.AccessPoint.{i}.", then we strip off the .{i}.
       because its the token before that which is the actual table name.
        e.g. "Device.WiFi.AccessPoint." is the table and {i} is a row placeholder.
       After the table is added below, we will add the {i} as child of table,
        but this {i} will be called a row template.  And from this template
        we can instantiate all the objects and properties under it when we
        add a row instance.
     */
    if (elem->type == he_bus_element_type_table) {
        size_t len = strlen(name);
        if (len > 4) {
            if (strcmp(name + len - 5, ".{i}.") == 0) {
                name[len - 5] = 0;
            } else if (strcmp(name + len - 4, ".{i}") == 0) {
                name[len - 4] = 0;
            }
        }
    }

    token = strtok_r(name, ".", &saveptr);

    while (token != NULL) {
        if (next_node == NULL) {
            if (create_child) {
                he_bus_core_dbg_print("Create child [%s]\n", token);
                temp_node = get_empty_element_node();
                temp_node->parent = current_node;
                if (current_node == root) {
                    strncpy(temp_node->full_name, token, strlen(token) + 1);
                } else {
                    snprintf(buff, sizeof(buff), "%s.%s", current_node->full_name, token);
                    strncpy(temp_node->full_name, buff, strlen(buff) + 1);
                }
                strncpy(temp_node->name, token, strlen(token) + 1);
                current_node->child = temp_node;
                current_node = temp_node;
                next_node = current_node->child;
                create_child = 1;
                if (is_grandparent_node_is_table(current_node->parent)) {
                    // Link tables with new node.
                    link_tables_with_new_node(current_node->parent);
                }
            }
        }
        while (next_node != NULL) {
            he_bus_core_dbg_print("child name=[%s], Token = [%s]\n", next_node->name, token);
            if (strcmp(next_node->name, token) == 0) {
                current_node = next_node;
                next_node = current_node->child;
                create_child = 1;
                break;
            } else {
                current_node = next_node;
                next_node = current_node->nextSibling;
                create_child = 0;
                if (next_node == NULL) {
                    he_bus_core_dbg_print("Create Sibling [%s]\n", token);
                    temp_node = get_empty_element_node();
                    temp_node->parent = current_node->parent;
                    if (strlen(current_node->parent->full_name) != 0) {
                        snprintf(buff, sizeof(buff), "%s.%s", current_node->parent->full_name,
                            token);
                    } else {
                        snprintf(buff, sizeof(buff), "%s", token);
                    }
                    he_bus_core_dbg_print("Full name [%s]\n", buff);
                    strncpy(temp_node->full_name, buff, strlen(buff) + 1);
                    strncpy(temp_node->name, token, strlen(token) + 1);
                    current_node->nextSibling = temp_node;
                    current_node = temp_node;
                    create_child = 1;
                }
            }
        }
        token = strtok_r(NULL, ".", &saveptr);
    }
    if (ret == 0) {
        current_node->type = elem->type;
        current_node->cb_table = elem->cb_table;

        /* See the big comment near the top of this function.
           We add {i} as a child object of the table.
           This will be the row template used to instantiate rows from.
           Its presumed a provider will register more elements under this, such as
            Device.WiFi.AccessPoint.{i}.Foo etc,...
         */
        if (elem->type == he_bus_element_type_table) {
            // trigger add table registration callback
            element_node_t *rowTemplate = get_empty_element_node();
            rowTemplate->parent = current_node;
            strncpy(rowTemplate->name, "{i}", strlen("{i}") + 1);
            snprintf(buff, sizeof(buff), "%s.%s", current_node->full_name, rowTemplate->name);
            strncpy(rowTemplate->full_name, buff, strlen(buff) + 1);
            current_node->child = rowTemplate;

            // Add table row instances
            add_table_row(handle, current_node, elem->num_of_table_row);
        }
    }
    HANDLE_UNLOCK(handle->handle_mutex);

    if (ret == 0) {
        // replicateAcrossTableRowInstances(current_node);
        return current_node;
    } else {
        return NULL;
    }
}

element_node_t *retrieve_instance_element(he_bus_handle_t handle, element_node_t *root,
    const char *elmentName)
{
    char *token = NULL;
    char *saveptr = NULL;
    he_bus_name_string_t name;
    element_node_t *current_node = root;
    element_node_t *next_node = NULL;
    int tokenFound = 0;
    bool isWildcard = false;

    he_bus_core_dbg_print("Request to retrieve element [%s]\n", elmentName);
    HANDLE_LOCK(handle->handle_mutex);
    if (current_node == NULL) {
        return NULL;
    }

    strncpy(name, elmentName, strlen(elmentName) + 1);

    next_node = current_node->child;

    /*TODO if name is a table row with an alias containing a dot, this will break (e.g.
     * "Foo.[alias.1]")*/
    token = strtok_r(name, ".", &saveptr);
    while (token != NULL) {
        he_bus_core_dbg_print("Token = [%s]\n", token);
        tokenFound = 0;

        if (next_node == NULL) {
            break;
        }

        he_bus_core_dbg_print("child name=[%s], Token = [%s]\n", next_node->name, token);

        if (strcmp(next_node->name, token) == 0) {
            he_bus_core_dbg_print("tokenFound!\n");
            tokenFound = 1;
            current_node = next_node;
            next_node = current_node->child;
        } else {
            current_node = next_node;
            next_node = current_node->nextSibling;

            while (next_node != NULL) {
                he_bus_core_dbg_print("child name=[%s], Token = [%s]\n", next_node->name, token);
                if (strcmp(next_node->name, token) == 0) {
                    he_bus_core_dbg_print("tokenFound!\n");
                    tokenFound = 1;
                    current_node = next_node;
                    next_node = current_node->child;
                    break;
                } else {
#if 0
                    /*check the alias if its a table row*/
                    if(next_node->parent->type == he_bus_element_type_table)
                    {
                        if(next_node->alias)
                        {
                            size_t tlen = strlen(token);
                            if(tlen > 2 && token[0] == '[' && token[tlen-1] == ']')
                            {
                                if(strlen(next_node->alias) == tlen-2 && strncmp(next_node->alias, token+1, tlen-2) == 0)
                                {
                                    he_bus_core_dbg_print("tokenFound by alias %s!\n", next_node->alias);
                                    tokenFound = 1;
                                    current_node = next_node;
                                    next_node = current_node->child;
                                    break;
                                }
                            }
                        }
                    }
#endif

                    current_node = next_node;
                    next_node = current_node->nextSibling;
                }
            }
        }

        token = strtok_r(NULL, ".", &saveptr);

        if (token && next_node && next_node->parent &&
            next_node->parent->type == he_bus_element_type_table) {
            if (!isWildcard && !strcmp(token, "*"))
                isWildcard = true;

            /* retrieveInstanceElement should return only the registration element if the table has
               a getHandler installed (used by MtaAgent/TR104) of if wildcard query */
            if (isWildcard || next_node->parent->cb_table.get_handler) {
                token = "{i}";
            }
        }
    }

    HANDLE_UNLOCK(handle->handle_mutex);

    if (tokenFound) {
        he_bus_core_dbg_print("Found Element with param name [%s]\n", current_node->name);
        return current_node;
    } else {
        return NULL;
    }
}

void node_elements_free(element_node_t *node, traversal_cb_param_t param)
{
    (void)param;
    VERIFY_NULL(node);

    if (node->subscriptions) {
        //@TODO TBD Do we need to send un-subscribe event notification to provider subscription
        //callback ?
        ELM_LOCK(node->element_mutex);
        hash_map_destroy(node->subscriptions);
        ELM_UNLOCK(node->element_mutex);
    }
    if (node->data_model_value.str_validation) {
        for (int index = 0; index < node->data_model_value.num_of_str_validation; index++) {
            he_bus_free(node->data_model_value.str_validation[index]);
        }
        he_bus_free(node->data_model_value.str_validation);
    }
    DEINIT_ELM_MUTEX(node->element_mutex);
    he_bus_core_dbg_print("node delete [%p]:%s:%s\r\n", node, node->name, node->full_name);
    he_bus_free(node);
}

static void node_element_recurse_traversal(element_node_t *node,
    node_element_traversal_arg_t *input_action)
{
    VERIFY_NULL(node);
    element_node_t *child = node->child;

    if (node->reference_childs != ref_child_node) {
        while (child) {
            element_node_t *tmp = child;
            child = child->nextSibling;
            node_element_recurse_traversal(tmp, input_action);
        }
    } else {
        he_bus_core_dbg_print("mirror link node found [%p]->child:%p\r\n", node, node->child);
    }

    if (input_action->traversal_cb != NULL) {
        input_action->traversal_cb(node, input_action->param);
    }
}

void node_element_traversal(element_node_t *node, node_element_traversal_arg_t *input_action)
{
    VERIFY_NULL(node);
    element_node_t *parent = node->parent;
    element_node_t *child = node->child;

    while (child) {
        element_node_t *tmp = child;
        child = child->nextSibling;
        node_element_recurse_traversal(tmp, input_action);
    }

    if (parent) {
        if (parent->child == node) {
            parent->child = node->nextSibling;
        } else {
            child = parent->child;
            while (child) {
                if (child->nextSibling == node) {
                    child->nextSibling = node->nextSibling;
                    break;
                }
                child = child->nextSibling;
            }
        }
    }

    if (input_action->traversal_cb != NULL) {
        input_action->traversal_cb(node, input_action->param);
    }
}

he_bus_error_t bus_remove_all_elements(he_bus_handle_t handle)
{
    element_node_t *root = handle->root_element;
    node_element_traversal_arg_t input_arg;
    input_arg.traversal_cb = node_elements_free;

    HANDLE_LOCK(handle->handle_mutex);

    while (root) {
        element_node_t *tmp = root;
        root = root->nextSibling;
        node_element_traversal(tmp, &input_arg);
    }

    HANDLE_UNLOCK(handle->handle_mutex);
    return he_bus_error_success;
}

he_bus_error_t free_node_elements(he_bus_handle_t handle, element_node_t *node)
{
    node_element_traversal_arg_t input_arg;
    input_arg.traversal_cb = node_elements_free;

    HANDLE_LOCK(handle->handle_mutex);

    node_element_traversal(node, &input_arg);

    HANDLE_UNLOCK(handle->handle_mutex);
    return he_bus_error_success;
}

char const *get_type_string(he_bus_element_type_t type)
{
    switch (type) {
    case he_bus_element_type_property:
        return "property";
    case he_bus_element_type_table:
        return "table";
    case he_bus_element_type_event:
        return "event";
    case he_bus_element_type_method:
        return "method";
    default:
        return "object";
    }
}

static void printElement(element_node_t *node, int level)
{
    he_bus_core_dbg_print("%*s[name:%s type:%s full_name:" ANSI_COLOR_GREEN " %s " ANSI_COLOR_RESET
                          "addr:%p, parent:%p, child:%p sub:%p]\n",
        level * 2, level ? " " : "", node->name, get_type_string(node->type), node->full_name, node,
        node->parent, node->child, node->subscriptions);
}

void printRegisteredElements(element_node_t *root, int level)
{
    element_node_t *child = root;
    element_node_t *sibling = NULL;

    if (child) {
        printElement(child, level);
        if (child->child) {
            printRegisteredElements(child->child, level + 1);
        }
        sibling = child->nextSibling;
        while (sibling) {
            printElement(sibling, level);
            if (sibling->child) {
                printRegisteredElements(sibling->child, level + 1);
            }
            sibling = sibling->nextSibling;
        }
    }
}

void retrive_existing_sub_entries_cb(element_node_t *node, traversal_cb_param_t param)
{
    VERIFY_NULL(node);
    VERIFY_NULL(param.u.node_data);

    node_element_persistent_data_t *element_data;
    element_data = hash_map_get(param.u.node_data, node->full_name);
    if (element_data != NULL) {
        he_bus_core_dbg_print("retrive_existing_sub_entries_cb:%s\r\n", node->full_name);
        node->subscriptions = element_data->subscriptions;
        hash_map_remove(param.u.node_data, node->full_name);
        he_bus_free(element_data);
    }
}

void save_existing_sub_entries_cb(element_node_t *node, traversal_cb_param_t param)
{
    VERIFY_NULL(node);
    VERIFY_NULL(param.u.node_data);
    node_element_persistent_data_t *element_data = he_bus_malloc(
        sizeof(node_element_persistent_data_t));

    element_data->subscriptions = node->subscriptions;
    hash_map_put(param.u.node_data, strdup(node->full_name), element_data);
    he_bus_core_dbg_print("save_existing_subscriptions_entries:%s\r\n", node->full_name);
    node->subscriptions = NULL;
}

he_bus_error_t move_existing_subscriptions_entries(he_bus_handle_t handle,
    element_node_t *old_root_node, element_node_t *new_root_node)
{
    node_element_traversal_arg_t input_arg;
    input_arg.traversal_cb = save_existing_sub_entries_cb;
    input_arg.param.u.node_data = hash_map_create();

    node_element_traversal(old_root_node, &input_arg);

    input_arg.traversal_cb = retrive_existing_sub_entries_cb;
    node_element_traversal(new_root_node, &input_arg);
    //@TODO Do we really want to Add code for remove individual node value and send un-subscribe
    //event to client ?
    hash_map_destroy(input_arg.param.u.node_data);
    return he_bus_error_success;
}

he_bus_error_t update_bus_tree(he_bus_handle_t old_bus_handle, const char *json_name)
{
    VERIFY_NULL_WITH_RC(old_bus_handle);
    VERIFY_NULL_WITH_RC(json_name);

    // construct new tree
    he_bus_handle new_bus_handle;

    new_bus_handle.root_element = get_empty_element_node();
    if (new_bus_handle.root_element == NULL) {
        he_bus_core_error_print("%s:%d bus root object create is falied for:%s\r\n", __func__,
            __LINE__, json_name);
        return he_bus_error_out_of_resources;
    }

    decode_json_object(&new_bus_handle, json_name);
    move_existing_subscriptions_entries(old_bus_handle, old_bus_handle->root_element,
        new_bus_handle.root_element);

    bus_remove_all_elements(old_bus_handle);
    old_bus_handle->root_element = new_bus_handle.root_element;
    return he_bus_error_success;
}

he_bus_error_t bus_publish_data_to_all_sub(he_bus_handle_t handle, he_bus_data_object_t *obj_data)
{
    if (handle == NULL || obj_data == NULL || obj_data->name_len == 0) {
        he_bus_core_error_print("%s:%d Input node element name not found\r\n", __func__, __LINE__);
        return he_bus_error_element_name_missing;
    }
    he_bus_raw_data_msg_t raw_data = { 0 };
    he_bus_stretch_buff_t output_buff = { 0 };

    he_bus_error_t ret = prepare_initial_bus_header(&raw_data, handle->component_name,
        he_bus_msg_notify);
    if (ret != he_bus_error_success) {
        he_bus_core_error_print("%s:%d initial bus header preapre is failed:%d for %s\r\n",
            __func__, __LINE__, ret, obj_data->name);
        return ret;
    }

    ret = prepare_rem_payload_bus_msg_data(obj_data->name, &raw_data, obj_data->msg_sub_type,
        &obj_data->data, he_bus_error_success);
    if (ret != he_bus_error_success) {
        he_bus_core_error_print("%s:%d rem bus payload preapre is failed:%d for %s\r\n", __func__,
            __LINE__, ret, obj_data->name);
        return ret;
    }

    element_node_t *node = retrieve_instance_element(handle, handle->root_element, obj_data->name);
    if (node == NULL) {
        he_bus_core_error_print("%s:%d Node is not found for :%s namespace\r\n", __func__, __LINE__,
            obj_data->name);
        return he_bus_error_destination_not_found;
    }

    if (convert_bus_raw_msg_data_to_buffer(&raw_data, &output_buff) != he_bus_error_success) {
        he_bus_core_error_print("%s:%d wrong data for :%s namespace\r\n", __func__, __LINE__,
            obj_data->name);
        FREE_BUFF_MEMORY(output_buff.buff);
        return he_bus_error_invalid_input;
    }

    ELM_LOCK(node->element_mutex);
    subscription_element_t *p_subscription_data = hash_map_get_first(node->subscriptions);
    while (p_subscription_data != NULL) {
        if (p_subscription_data->action == he_bus_event_action_subscribe) {
            send_data_to_endpoint(p_subscription_data->socket_fd, output_buff.buff,
                output_buff.buff_len);
        }
        p_subscription_data = hash_map_get_next(node->subscriptions, p_subscription_data);
    }
    ELM_UNLOCK(node->element_mutex);

    FREE_BUFF_MEMORY(output_buff.buff);

    return he_bus_error_success;
}

he_bus_error_t he_bus_publish_event(he_bus_handle_t handle, char *event_name,
    he_bus_raw_data_t *p_data)
{
    VERIFY_NULL_WITH_RC(event_name);
    VERIFY_NULL_WITH_RC(handle);
    VERIFY_NULL_WITH_RC(p_data);

    he_bus_data_object_t obj_data = { 0 };

    obj_data.name_len = strlen(event_name) + 1;
    strncpy(obj_data.name, event_name, obj_data.name_len);
    obj_data.msg_sub_type = he_bus_msg_publish_event;
    obj_data.is_data_set = true;
    obj_data.status = he_bus_error_success;
    obj_data.data.data_type = p_data->data_type;
    obj_data.data.raw_data = p_data->raw_data;
    obj_data.data.raw_data_len = p_data->raw_data_len;
    return bus_publish_data_to_all_sub(handle, &obj_data);
}

int save_bus_sub_event_entries(he_bus_handle_t handle, hash_map_t *sub_map,
    he_bus_event_sub_t *sub_data_map)
{
    VERIFY_NULL_WITH_RC(sub_map);
    VERIFY_NULL_WITH_RC(handle);
    VERIFY_NULL_WITH_RC(sub_data_map);

    char *event_name = sub_data_map->event_name;
    own_sub_element_t *p_sub_data;
    he_bus_connection_info_t *conn_info = get_bus_broadcast_client_info(handle);

    he_bus_core_info_print("%s:%d save sub map for [%s]:%d\r\n", __func__, __LINE__, event_name,
        conn_info->fd);
    if (sub_map != NULL) {
        p_sub_data = he_bus_calloc(1, sizeof(own_sub_element_t));
        p_sub_data->action = sub_data_map->action;
        p_sub_data->interval = sub_data_map->interval;
        p_sub_data->sub_cb_table = sub_data_map->handler;
        p_sub_data->socket_fd = conn_info->fd;
        hash_map_put(sub_map, strdup(event_name), p_sub_data);
        he_bus_core_info_print("%s:%d new sub entry added for [%s]:%p\r\n", __func__, __LINE__,
            event_name, p_sub_data);
    }
    return HE_BUS_RETURN_OK;
}

he_bus_error_t he_bus_event_sub_to_provider(he_bus_handle_t handle,
    he_bus_event_sub_t *sub_data_map, uint32_t num_of_sub, he_bus_msg_sub_type_t msg_sub_type)
{
    VERIFY_NULL_WITH_RC(sub_data_map);
    VERIFY_NULL_WITH_RC(handle);

    char *event_name;
    he_bus_raw_data_msg_t sub_data = { 0 };
    he_bus_raw_data_t payload_data;
    int ret;
    sub_payload_data_t sub_input_data;

    he_bus_error_t status = prepare_initial_bus_header(&sub_data, handle->component_name,
        he_bus_msg_request);
    if (status != he_bus_error_success) {
        he_bus_core_error_print("%s:%d initial bus header preapre is failed:%d\r\n", __func__,
            __LINE__, status);
        return status;
    }

    for (uint32_t index = 0; index < num_of_sub; index++) {
        event_name = sub_data_map[index].event_name;
        own_sub_element_t *p_sub_data = hash_map_get(handle->sub_map, event_name);
        if (p_sub_data != NULL) {
            he_bus_core_error_print("%s:%d event:%s already subscribe with provider\r\n", __func__,
                __LINE__, event_name);
            return he_bus_error_subscription_already_exist; // @TODO TBD Do we need to return error
                                                            // or not ?
        } else {
            sub_input_data.action = sub_data_map[index].action;
            sub_input_data.interval = sub_data_map[index].interval;

            payload_data.data_type = he_bus_data_type_bytes;
            payload_data.raw_data.bytes = he_bus_malloc(sizeof(sub_payload_data_t));
            memcpy(payload_data.raw_data.bytes, &sub_input_data, sizeof(sub_payload_data_t));
            payload_data.raw_data_len = sizeof(sub_payload_data_t);

            status = prepare_rem_payload_bus_msg_data(event_name, &sub_data, msg_sub_type,
                &payload_data, he_bus_error_success);
            if (status != he_bus_error_success) {
                he_bus_core_error_print("%s:%d rem bus payload preapre is failed:%d for %s\r\n",
                    __func__, __LINE__, status, event_name);
                return status;
            }
        }
    }

    he_bus_stretch_buff_t raw_buff = { 0 };

    if (convert_bus_raw_msg_data_to_buffer(&sub_data, &raw_buff) != he_bus_error_success) {
        he_bus_core_error_print("%s:%d wrong data for :%s namespace\r\n", __func__, __LINE__,
            sub_data.component_name);
        FREE_BUFF_MEMORY(raw_buff.buff);
        return he_bus_error_invalid_input;
    }

    he_bus_core_info_print("%s:%d event:%s subscribe event sub type:%d\r\n", __func__, __LINE__,
        event_name, msg_sub_type);
    if (msg_sub_type == he_bus_msg_sub_event) {
        he_bus_stretch_buff_t res_data = { 0 };

        ret = ipc_unix_send_data_and_wait_for_res(&raw_buff, &res_data, HE_BUS_RES_RECV_TIMEOUT_S);
        if (ret != HE_BUS_RETURN_OK) {
            he_bus_core_info_print("%s:%d event:%s subscribe send failure:%d\r\n", __func__,
                __LINE__, event_name, ret);
            status = he_bus_error_destination_not_reachable;
        } else {
            // check subscribe response and save sub info locally.
            he_bus_raw_data_msg_t recv_data = { 0 };
            he_bus_error_t status;

            he_bus_core_info_print("%s:%d event:%s subscribe response received from provider\r\n",
                __func__, __LINE__, event_name);
            convert_buffer_to_bus_raw_msg_data(&recv_data, &res_data);
            if (recv_data.msg_type == he_bus_msg_response) {
                for (uint32_t index = 0; index < num_of_sub; index++) {
                    status = validate_sub_response(&sub_data_map[index], &recv_data);
                    if (status != he_bus_error_success) {
                        he_bus_core_info_print(
                            "%s:%d event:%s subscribe response validation falied:%d\r\n", __func__,
                            __LINE__, sub_data_map[index].event_name, status);
                    } else {
                        save_bus_sub_event_entries(handle, handle->sub_map, &sub_data_map[index]);
                    }
                }
            } else {
                he_bus_core_info_print("%s:%d event:%s subscribe response:%d\r\n", __func__,
                    __LINE__, event_name, recv_data.msg_type);
            }
            free_bus_msg_obj_data(&recv_data.data_obj);
        }
        FREE_BUFF_MEMORY(res_data.buff);
    } else if (msg_sub_type == he_bus_msg_sub_ex_async_event) {
        ret = ipc_unix_client_send_data(handle, raw_buff.buff, raw_buff.buff_len);
        if (ret != HE_BUS_RETURN_OK) {
            he_bus_core_info_print("%s:%d event:%s subscribe send failure:%d\r\n", __func__,
                __LINE__, event_name, ret);
            return he_bus_error_destination_not_reachable;
        } else {
            for (uint32_t index = 0; index < num_of_sub; index++) {
                save_bus_sub_event_entries(handle, handle->sub_map, &sub_data_map[index]);
            }
        }
    }

    FREE_BUFF_MEMORY(raw_buff.buff);
    free_bus_msg_obj_data(&sub_data.data_obj);
    return status;
}

he_bus_error_t he_bus_event_sub(he_bus_handle_t handle, char *event_name,
    he_bus_event_consumer_sub_handler_t sub_handler, uint32_t timeout)
{
    VERIFY_NULL_WITH_RC(event_name);
    VERIFY_NULL_WITH_RC(handle);

    he_bus_event_sub_t sub_data_map = { 0 };

    sub_data_map.event_name = event_name;
    sub_data_map.action = he_bus_event_action_subscribe;
    sub_data_map.interval = 0;
    sub_data_map.handler.sub_handler = sub_handler;
    sub_data_map.handler.sub_ex_async_handler = NULL;

    return he_bus_event_sub_to_provider(handle, &sub_data_map, 1, he_bus_msg_sub_event);
}

he_bus_error_t he_bus_event_sub_ex(he_bus_handle_t handle, he_bus_event_sub_t *p_sub_data_map,
    uint32_t num_of_sub, uint32_t timeout)
{
    VERIFY_NULL_WITH_RC(handle);
    VERIFY_NULL_WITH_RC(p_sub_data_map);

    return he_bus_event_sub_to_provider(handle, p_sub_data_map, num_of_sub, he_bus_msg_sub_event);
}

he_bus_error_t he_bus_event_sub_ex_async(he_bus_handle_t handle, he_bus_event_sub_t *sub_map,
    uint32_t num_of_sub, he_bus_event_sub_ex_async_handler_t sub_ex_async_handler, uint32_t timeout)
{
    if (handle == NULL || sub_map == NULL) {
        he_bus_core_error_print("%s:%d sub_map is NULL :%d\r\n", __func__, __LINE__, num_of_sub);
        return he_bus_error_invalid_input;
    }

    for (uint32_t index = 0; index < num_of_sub; index++) {
        sub_map[index].handler.sub_ex_async_handler = sub_ex_async_handler;
    }

    return he_bus_event_sub_to_provider(handle, sub_map, num_of_sub, he_bus_msg_sub_ex_async_event);
}

// caller needs to free allocated memory
he_bus_error_t he_bus_get_data(he_bus_handle_t handle, char *event_name, he_bus_raw_data_t *p_data)
{
    VERIFY_NULL_WITH_RC(event_name);
    VERIFY_NULL_WITH_RC(handle);
    VERIFY_NULL_WITH_RC(p_data);

    he_bus_raw_data_msg_t req_data = { 0 };
    he_bus_stretch_buff_t raw_buff = { 0 };
    he_bus_stretch_buff_t res_data = { 0 };
    he_bus_error_t status = he_bus_error_success;
    he_bus_raw_data_t payload_data = { 0 };

    status = prepare_initial_bus_header(&req_data, handle->component_name, he_bus_msg_get);
    if (status != he_bus_error_success) {
        he_bus_core_error_print("%s:%d initial bus header preapre is failed:%d\r\n", __func__,
            __LINE__, status);
        return status;
    }

    status = prepare_rem_payload_bus_msg_data(event_name, &req_data, he_bus_msg_get_event,
        &payload_data, he_bus_error_success);
    if (status != he_bus_error_success) {
        he_bus_core_error_print("%s:%d rem bus payload preapre is failed:%d for %s\r\n", __func__,
            __LINE__, status, event_name);
        return status;
    }

    if (convert_bus_raw_msg_data_to_buffer(&req_data, &raw_buff) != he_bus_error_success) {
        he_bus_core_error_print("%s:%d wrong data for :%s namespace\r\n", __func__, __LINE__,
            event_name);
        FREE_BUFF_MEMORY(raw_buff.buff);
        return he_bus_error_invalid_input;
    }

    int ret = ipc_unix_send_data_and_wait_for_res(&raw_buff, &res_data, HE_BUS_RES_RECV_TIMEOUT_S);
    if (ret != HE_BUS_RETURN_OK) {
        he_bus_core_info_print("%s:%d event:%s bus get send failure:%d\r\n", __func__, __LINE__,
            event_name, ret);
        status = he_bus_error_destination_not_reachable;
    } else {
        // read bus response and parse.
        he_bus_raw_data_msg_t recv_data = { 0 };
        he_bus_data_object_t *p_obj_data = &recv_data.data_obj;

        he_bus_core_info_print("%s:%d event:%s bus get response received from provider\r\n",
            __func__, __LINE__, event_name);
        convert_buffer_to_bus_raw_msg_data(&recv_data, &res_data);
        if (recv_data.msg_type == he_bus_msg_response &&
            p_obj_data->msg_sub_type == he_bus_msg_get_event) {
            if (!strncmp(event_name, p_obj_data->name, (strlen(p_obj_data->name) + 1))) {
                he_bus_core_info_print("%s:%d event:%s bus get response found\r\n", __func__,
                    __LINE__, event_name);
                if (p_obj_data->status == he_bus_error_success) {
                    memcpy(p_data, &p_obj_data->data, sizeof(p_obj_data->data));
                } else {
                    he_bus_core_error_print("%s:%d event:%s bus get is falied:%d\r\n", __func__,
                    __LINE__, event_name, p_obj_data->status);
                    status = p_obj_data->status;
                }
            }
        } else {
            he_bus_core_info_print("%s:%d event:%s bus get response:%d\r\n", __func__, __LINE__,
                event_name, recv_data.msg_type);
            free_bus_msg_obj_data(&recv_data.data_obj);
            status = he_bus_error_destination_response_failure;
        }
    }

    FREE_BUFF_MEMORY(raw_buff.buff);
    FREE_BUFF_MEMORY(res_data.buff);
    return status;
}

he_bus_error_t he_bus_set_data(he_bus_handle_t handle, char *event_name, he_bus_raw_data_t *p_data)
{
    VERIFY_NULL_WITH_RC(event_name);
    VERIFY_NULL_WITH_RC(handle);
    VERIFY_NULL_WITH_RC(p_data);

    he_bus_raw_data_msg_t req_data = { 0 };
    he_bus_stretch_buff_t raw_buff = { 0 };
    he_bus_stretch_buff_t res_data = { 0 };
    he_bus_error_t status = he_bus_error_success;

    status = prepare_initial_bus_header(&req_data, handle->component_name, he_bus_msg_set);
    if (status != he_bus_error_success) {
        he_bus_core_error_print("%s:%d initial bus header preapre is failed:%d\r\n", __func__,
            __LINE__, status);
        return status;
    }

    status = prepare_rem_payload_bus_msg_data(event_name, &req_data, he_bus_msg_set_event, p_data,
        he_bus_error_success);
    if (status != he_bus_error_success) {
        he_bus_core_error_print("%s:%d rem bus payload preapre is failed:%d for %s\r\n", __func__,
            __LINE__, status, event_name);
        return status;
    }

    if (convert_bus_raw_msg_data_to_buffer(&req_data, &raw_buff) != he_bus_error_success) {
        he_bus_core_error_print("%s:%d wrong data for :%s namespace\r\n", __func__, __LINE__,
            event_name);
        FREE_BUFF_MEMORY(raw_buff.buff);
        return he_bus_error_invalid_input;
    }

    int ret = ipc_unix_send_data_and_wait_for_res(&raw_buff, &res_data, HE_BUS_RES_RECV_TIMEOUT_S);
    if (ret != HE_BUS_RETURN_OK) {
        he_bus_core_info_print("%s:%d event:%s bus set send failure:%d\r\n", __func__, __LINE__,
            event_name, ret);
        status = he_bus_error_destination_not_reachable;
    } else {
        // read bus response and parse.
        he_bus_raw_data_msg_t recv_data = { 0 };
        he_bus_data_object_t *p_obj_data = &recv_data.data_obj;

        he_bus_core_info_print("%s:%d event:%s bus set response received\r\n", __func__, __LINE__,
            event_name);
        convert_buffer_to_bus_raw_msg_data(&recv_data, &res_data);
        if (recv_data.msg_type == he_bus_msg_response &&
            p_obj_data->msg_sub_type == he_bus_msg_set_event) {
            if (!strncmp(event_name, p_obj_data->name, (strlen(p_obj_data->name) + 1))) {
                he_bus_core_info_print("%s:%d event:%s bus set response found:%d\r\n", __func__,
                    __LINE__, event_name, p_obj_data->status);
                status = p_obj_data->status;
            }
        } else {
            he_bus_core_info_print("%s:%d event:%s bus set response:%d\r\n", __func__, __LINE__,
                event_name, recv_data.msg_type);
            status = he_bus_error_destination_response_failure;
        }
        free_bus_msg_obj_data(&recv_data.data_obj);
    }

    FREE_BUFF_MEMORY(raw_buff.buff);
    FREE_BUFF_MEMORY(res_data.buff);
    return status;
}

void remove_client_existing_sub_info_cb(element_node_t *node, traversal_cb_param_t param)
{
    VERIFY_NULL(node);
    VERIFY_NULL(param.u.comp_name);

    if (node->subscriptions != NULL) {
        ELM_LOCK(node->element_mutex);
        subscription_element_t *p_sub_data = hash_map_remove(node->subscriptions,
            param.u.comp_name);
        if (p_sub_data != NULL) {
            if (node->cb_table.event_sub_handler != NULL) {
                bool autoPublish;

                node->cb_table.event_sub_handler(node->full_name, he_bus_event_action_unsubscribe,
                    0, &autoPublish);
            }
            he_bus_core_info_print("%s:%d event:%s client:%s sub remove:%p\r\n", __func__, __LINE__,
                node->full_name, param.u.comp_name, p_sub_data);
            he_bus_free(p_sub_data);
        }
        ELM_UNLOCK(node->element_mutex);
    }
}

he_bus_error_t bus_remove_client_all_sub_details(he_bus_handle_t handle, char *comp_name)
{
    VERIFY_NULL_WITH_RC(comp_name);
    VERIFY_NULL_WITH_RC(handle);
    element_node_t *root = handle->root_element;
    node_element_traversal_arg_t input_arg;
    input_arg.traversal_cb = remove_client_existing_sub_info_cb;
    input_arg.param.u.comp_name = comp_name;

    HANDLE_LOCK(handle->handle_mutex);

    while (root) {
        element_node_t *tmp = root;
        root = root->nextSibling;
        node_element_traversal(tmp, &input_arg);
    }

    HANDLE_UNLOCK(handle->handle_mutex);
    return he_bus_error_success;
}

he_bus_error_t remove_client_all_details(he_bus_handle_t handle, char *comp_name)
{
    VERIFY_NULL_WITH_RC(comp_name);
    VERIFY_NULL_WITH_RC(handle);
    he_bus_error_t status;

    status = bus_remove_client_all_sub_details(handle, comp_name);

    return status;
}

he_bus_error_t he_bus_reg_data_elem(he_bus_handle_t handle, he_bus_data_element_t *p_bus_reg_data,
    uint32_t num_of_elem)
{
    VERIFY_NULL_WITH_RC(p_bus_reg_data);
    VERIFY_NULL_WITH_RC(handle);
    he_bus_core_info_print("%s:%d: register num of namespace:%d\n", __func__, __LINE__,
        num_of_elem);

    he_bus_data_element_t dataElements;
    data_model_prop_t data_model_value = { 0 };

    for (uint32_t index = 0; index < num_of_elem; index++) {
        memcpy(&dataElements, &p_bus_reg_data[index], sizeof(he_bus_data_element_t));

        element_node_t *node = bus_insert_element(handle, handle->root_element, &dataElements);
        if (node != NULL) {
            node->data_model_value = data_model_value;
        }
    }

    return HE_BUS_RETURN_OK;
}
