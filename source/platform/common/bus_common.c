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
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <stdbool.h>
#include "bus.h"
#include "bus_common.h"
#include "wifi_util.h"

#define COMPARE_INT_RANGE(min_value, max_value, set_value) do { \
    if ((set_value) < (min_value)) { \
        wifi_util_info_print(WIFI_BUS, "Value %d is less than the minimum value (%d)\n", (set_value), (min_value)); \
        return RETURN_ERR; \
    } else if ((set_value) > (max_value)) { \
        wifi_util_info_print(WIFI_BUS, "Value %d is greater than the maximum value (%d)\n", (set_value), (max_value)); \
        return RETURN_ERR; \
    } \
} while (0)

pthread_mutex_t *get_bus_mux_mutex(void)
{
    wifi_bus_t *p_bus = get_bus_obj();
    return &p_bus->bus_cb_mux.bus_mux_mutex;
}

elem_node_map_t *get_bus_mux_reg_cb_map(void)
{
    wifi_bus_t *p_bus = get_bus_obj();
    return p_bus->bus_cb_mux.bus_reg_cb_root;
}

elem_node_map_t *get_bus_mux_sub_cb_map(void)
{
    wifi_bus_t *p_bus = get_bus_obj();
    return p_bus->bus_cb_mux.bus_sub_cb_root;
}

static elem_node_map_t* get_empty_elem_node(void)
{
    elem_node_map_t* node;

    node = (elem_node_map_t *) calloc(1, sizeof(elem_node_map_t));
    BUS_CHECK_NULL_WITH_RC(node, NULL);
    node->type = 0;
    node->reference_childs = original_child_node;

    return node;
}

void init_bus_mux_root(void)
{
    wifi_bus_t *bus_obj = get_bus_obj();

    bus_obj->bus_cb_mux.bus_reg_cb_root = get_empty_elem_node();
    bus_obj->bus_cb_mux.bus_sub_cb_root = get_empty_elem_node();
    INIT_MUTEX(bus_obj->bus_cb_mux.bus_mux_mutex);
}

void deinit_bus_all_mux_param(void)
{
    wifi_bus_t *bus_obj = get_bus_obj();

    bus_remove_all_elems(bus_obj->bus_cb_mux.bus_reg_cb_root);
    bus_remove_all_elems(bus_obj->bus_cb_mux.bus_sub_cb_root);
    DEINIT_MUTEX(bus_obj->bus_cb_mux.bus_mux_mutex);
}

static elem_node_map_t *insert_table_row(elem_node_map_t *table_root, char *node_name)
{
    elem_node_map_t* current_node = table_root;
    elem_node_map_t* temp_node    = NULL;
    elem_node_map_t* next_node    = NULL;
    char             buff[256];
    bus_error_t      status = bus_error_destination_not_found;

    VERIFY_NULL_WITH_RETURN_ADDR(table_root);
    VERIFY_NULL_WITH_RETURN_ADDR(node_name);

    next_node = current_node->child;

    while(next_node != NULL)
    {
        wifi_util_dbg_print(WIFI_BUS,"child name=[%s], Token = [%s]\r\n", next_node->name, node_name);
        if(strcmp(next_node->name, node_name) == 0)
        {
            current_node = next_node;
            wifi_util_dbg_print(WIFI_BUS,"child name=[%s], Token = [%s] already present\r\n", next_node->name, node_name);
            status = bus_error_success;
            break;
        }
        else
        {
            current_node = next_node;
            next_node = current_node->nextSibling;
            if(next_node == NULL)
            {
                wifi_util_dbg_print(WIFI_BUS,"Create Sibling [%s]\r\n", node_name);
                temp_node = get_empty_elem_node();
                VERIFY_NULL_WITH_RETURN_ADDR(temp_node);
                temp_node->parent = current_node->parent;
                if(strlen(current_node->parent->full_name) != 0) {
                    snprintf(buff, sizeof(buff), "%s.%s", current_node->parent->full_name, node_name);
                } else {
                    snprintf(buff, sizeof(buff), "%s", node_name);
                }
                wifi_util_dbg_print(WIFI_BUS,"Full name [%s]\r\n", buff);
                snprintf(temp_node->full_name, sizeof(temp_node->full_name), "%s", buff);
                strncpy(temp_node->name, node_name, strlen(node_name) + 1);
                current_node->nextSibling = temp_node;
                current_node = temp_node;
                status = bus_error_success;
                break;
            }
        }
    }

    if (status == bus_error_success) {
        return current_node;
    }
    return NULL;
}

bus_error_t bus_add_table_row(elem_node_map_t *table_root, unsigned int num_of_table_row)
{
    char       str_node_index_name[8];
    uint32_t   index = 0;

    for (unsigned int i = 1; i <= num_of_table_row; i++) {
        index = i;
        snprintf(str_node_index_name, sizeof(str_node_index_name), "%d", index);
        insert_table_row(table_root, str_node_index_name);
    }
    return bus_error_success;
}

static bool is_string_digit(const char *str)
{
    if (str == NULL || *str == '\0') {
        return 0;
    }

    for (int i = 0; str[i] != '\0'; i++) {
        if (str[i] < '0' || str[i] > '9') {
            return false;
        }
    }
    return true;
}

static elem_node_map_t* link_tables_with_node(elem_node_map_t* parent_node)
{
    VERIFY_NULL_WITH_RETURN_ADDR(parent_node);

    elem_node_map_t* child_node_reference = parent_node->child;
    elem_node_map_t* next_node = parent_node->nextSibling;
    while(next_node) {
        if (next_node->child == NULL && is_string_digit(next_node->name)) {
            next_node->child = child_node_reference;
            next_node->reference_childs = reference_child_node;
            wifi_util_dbg_print(WIFI_BUS,"%s:%d Added duplicate node ref for=%s\r\n", __func__,
                __LINE__, next_node->full_name);
        }
        next_node = next_node->nextSibling;
    }
    return child_node_reference;
}

static void duplicate_node_ref(elem_node_map_t* child_table_node, elem_node_map_t* parent_node)
{
    VERIFY_NULL(child_table_node);
    VERIFY_NULL(parent_node);
    elem_node_map_t *child_node = parent_node->child;
    while(child_node) {
        if(strcmp(child_node->name, "{i}") == 0) {
            break;
        }
        child_node = child_node->nextSibling;
    }
    VERIFY_NULL(child_node);

    if ((parent_node->node_elem_data_len != 0) && (child_table_node->node_elem_data == NULL)) {
        child_table_node->node_data_type = parent_node->node_data_type;
        child_table_node->node_elem_data = malloc(parent_node->node_elem_data_len);
        VERIFY_NULL(child_table_node->node_elem_data);
        memcpy(child_table_node->node_elem_data, parent_node->node_elem_data, parent_node->node_elem_data_len);
        child_table_node->node_elem_data_len = parent_node->node_elem_data_len;
        wifi_util_info_print(WIFI_BUS,"%s:%d Added node new data info for %s--data len:%d\r\n", __func__,
            __LINE__, child_table_node->full_name, parent_node->node_elem_data_len);
    }

    if (child_table_node->child == NULL) {
        child_table_node->child = child_node->child;
        child_table_node->reference_childs = reference_child_node;
        wifi_util_info_print(WIFI_BUS,"%s:%d Added duplicate node ref for %s\r\n", __func__,
            __LINE__, child_table_node->full_name);
    }
}

static bool is_grandparent_node_elem_is_table(elem_node_map_t* cur_parent)
{
    elem_node_map_t* grandparent_node = ((cur_parent != NULL) ? cur_parent->parent : NULL);
    if (grandparent_node && grandparent_node->type == bus_element_type_table) {
        return true;
    }
    return false;
}

elem_node_map_t* bus_insert_elem_node(elem_node_map_t* root, bus_mux_data_elem_t* elem)
{
    char* token                  = NULL;
    char* saveptr                = NULL;
    bus_name_string_t name;
    elem_node_map_t* current_node = root;
    elem_node_map_t* temp_node    = NULL;
    elem_node_map_t* next_node    = NULL;
    int  ret = 0, create_child   = 0;
    char buff[256];

    if(current_node == NULL || elem == NULL)
    {
        return NULL;
    }
    BUS_MUX_LOCK(get_bus_mux_mutex());
    next_node = current_node->child;
    create_child = 1;

    wifi_util_info_print(WIFI_BUS,"Request to insert element [%s]!!\r\n", elem->full_name);

    strncpy(name, elem->full_name, strlen(elem->full_name) + 1);

    if(elem->type == bus_element_type_table)
    {
        size_t len = strlen(name);
        if(len > 4)
        {
            if(strcmp(name + len - 5, ".{i}.") == 0)
            {
                name[len-5] = 0;
            }
            else if(strcmp(name + len - 4, ".{i}") == 0)
            {
                name[len-4] = 0;
            }
        }
    }

    token = strtok_r(name, ".", &saveptr);

    while( token != NULL )
    {
        if(next_node == NULL)
        {
            if(create_child)
            {
                wifi_util_dbg_print(WIFI_BUS,"Create child [%s]\n", token);
                temp_node = get_empty_elem_node();
                BUS_CHECK_NULL_WITH_RC(temp_node, NULL);
                temp_node->parent = current_node;
                if(current_node == root)
                {
                    strncpy(temp_node->full_name, token, strlen(token) + 1);
                }
                else
                {
                    snprintf(buff, sizeof(buff), "%s.%s", current_node->full_name, token);
                    snprintf(temp_node->full_name, sizeof(temp_node->full_name), "%s", buff);
                }
                strncpy(temp_node->name, token, strlen(token) + 1);
                current_node->child = temp_node;
                current_node = temp_node;
                next_node = current_node->child;
                create_child = 1;
                if (is_grandparent_node_elem_is_table(current_node->parent)) {
                    // Link tables with new node.
                    link_tables_with_node(current_node->parent);
                }
            }
        }
        while(next_node != NULL)
        {
            wifi_util_dbg_print(WIFI_BUS,"child name=[%s], Token = [%s]\n", next_node->name, token);
            if(strcmp(next_node->name, token) == 0)
            {
                current_node = next_node;
                next_node = current_node->child;
                create_child = 1;
                break;
            }
            else
            {
                current_node = next_node;
                next_node = current_node->nextSibling;
                create_child = 0;
                if(next_node == NULL)
                {
                    wifi_util_dbg_print(WIFI_BUS,"Create Sibling [%s]\n", token);
                    temp_node = get_empty_elem_node();
                    BUS_CHECK_NULL_WITH_RC(temp_node, NULL);
                    temp_node->parent = current_node->parent;
                    if(strlen(current_node->parent->full_name) != 0) {
                        snprintf(buff, sizeof(buff), "%s.%s", current_node->parent->full_name, token);
                    } else {
                        snprintf(buff, sizeof(buff), "%s", token);
                    }
                    wifi_util_dbg_print(WIFI_BUS,"Full name [%s]\n", buff);
                    snprintf(temp_node->full_name, sizeof(temp_node->full_name), "%s", buff);
                    strncpy(temp_node->name, token, strlen(token) + 1);
                    current_node->nextSibling = temp_node;
                    current_node = temp_node;
                    create_child = 1;
                }
            }
        }
        token = strtok_r(NULL, ".", &saveptr);
    }
    if(ret == 0)
    {
        current_node->type           = elem->type;
        current_node->node_data_type = elem->node_data_type;
        current_node->node_elem_data = malloc(elem->cfg_data_len);
        BUS_CHECK_NULL_WITH_RC(current_node->node_elem_data, NULL);
        memcpy(current_node->node_elem_data, elem->cfg_data, elem->cfg_data_len);
        current_node->node_elem_data_len = elem->cfg_data_len;

        if(elem->type == bus_element_type_table)
        {
            elem_node_map_t* rowTemplate = get_empty_elem_node();
            BUS_CHECK_NULL_WITH_RC(rowTemplate, NULL);
            rowTemplate->parent = current_node;
            strncpy(rowTemplate->name, "{i}", strlen("{i}") + 1);
            snprintf(buff, sizeof(buff), "%s.%s", current_node->full_name, rowTemplate->name);
            snprintf(rowTemplate->full_name, sizeof(rowTemplate->full_name), "%s", buff);
            current_node->child = rowTemplate;

            //bus_add_table_row(current_node, elem->num_of_table_row);
        }
    }
    BUS_MUX_UNLOCK(get_bus_mux_mutex());

    if(ret == 0)
    {
        return current_node;
    }
    else
    {
        return NULL;
    }
}

elem_node_map_t* retrieve_instance_elem_node(elem_node_map_t* root, const char* elmentName)
{
    char* token                  = NULL;
    char* saveptr                = NULL;
    bus_name_string_t name;
    elem_node_map_t* current_node = root;
    elem_node_map_t* next_node    = NULL;
    int tokenFound               = 0;
    bool isWildcard              = false;

    if(current_node == NULL || elmentName == NULL)
    {
        return NULL;
    }

    wifi_util_dbg_print(WIFI_BUS,"Request to retrieve element [%s]\n", elmentName);
    BUS_MUX_LOCK(get_bus_mux_mutex());
    strncpy(name, elmentName, strlen(elmentName) + 1);

    next_node = current_node->child;

    token = strtok_r(name, ".", &saveptr);
    while( token != NULL)
    {
        wifi_util_dbg_print(WIFI_BUS,"Token = [%s]\n", token);
        tokenFound = 0;

        if(next_node == NULL)
        {
            break;
        }

        wifi_util_dbg_print(WIFI_BUS,"child name=[%s], Token = [%s]\n", next_node->name, token);

        if(strcmp(next_node->name, token) == 0)
        {
            wifi_util_dbg_print(WIFI_BUS,"tokenFound!\n");
            tokenFound = 1;
            current_node = next_node;
            next_node = current_node->child;
        }
        else
        {
            current_node = next_node;
            next_node = current_node->nextSibling;

            while(next_node != NULL)
            {
                wifi_util_dbg_print(WIFI_BUS,"child name=[%s], Token = [%s]\n", next_node->name, token);
                if(strcmp(next_node->name, token) == 0)
                {
                    wifi_util_dbg_print(WIFI_BUS,"tokenFound!\n");
                    tokenFound = 1;
                    current_node = next_node;
                    next_node = current_node->child;
                    break;
                } else {
                    current_node = next_node;
                    next_node = current_node->nextSibling;
                }
            }
        }

        token = strtok_r(NULL, ".", &saveptr);

        if(token && next_node && next_node->parent && next_node->parent->type == bus_element_type_table)
        {
            bus_callback_table_t *user_cb = NULL;
            bus_mux_reg_node_data_t *reg_node_data = next_node->parent->node_elem_data;

            if (reg_node_data != NULL) {
                user_cb = &reg_node_data->cb_table;
            }

            if (!isWildcard && !strcmp(token,"*")) {
                isWildcard = true;
            }

            if (isWildcard || (user_cb && user_cb->get_handler)) {
                token = "{i}";
            }
        }
    }

    BUS_MUX_UNLOCK(get_bus_mux_mutex());

    if(tokenFound)
    {
        wifi_util_dbg_print(WIFI_BUS,"Found Element with param name [%s]\n", current_node->name);
        return current_node;
    }
    else
    {
        return NULL;
    }
}

elem_node_map_t *get_bus_node_info(elem_node_map_t *cb_root, char *name)
{
    bus_name_string_t recv_name     = { 0 };
    elem_node_map_t   *node_elem;

    if (cb_root == NULL || name == NULL) {
        wifi_util_error_print(WIFI_BUS, "%s:%d: user cb root map not found\n", __func__, __LINE__);
        return NULL;
    }

    snprintf(recv_name, sizeof(recv_name), "%s", name);

    node_elem = retrieve_instance_elem_node(cb_root, recv_name);
    if (node_elem != NULL) {
        return node_elem;
    }
    wifi_util_info_print(WIFI_BUS,"%s bus callback not found=%s\n", __func__, recv_name);

    return NULL;
}

bus_error_t bus_table_add_row(elem_node_map_t *p_root_node, char *p_name_space, uint32_t table_index)
{
    elem_node_map_t *retrieve_table_elem;
    char            str_table_name[8];

    retrieve_table_elem = get_bus_node_info(p_root_node, p_name_space);
    if (retrieve_table_elem != NULL) {
        elem_node_map_t *table_node_elem;

        snprintf(str_table_name, sizeof(str_table_name), "%d", table_index);
        table_node_elem = insert_table_row(retrieve_table_elem, str_table_name);
        if (table_node_elem == NULL) {
            wifi_util_error_print(WIFI_BUS,"%s:%d table node is not found:%s.%d\n", __func__,
                __LINE__, p_name_space, table_index);
            return bus_error_general;
        }
        wifi_util_info_print(WIFI_BUS,"%s:%d Added table node:%s.%d\n", __func__,
            __LINE__, p_name_space, table_index);
        duplicate_node_ref(table_node_elem, retrieve_table_elem);
    } else {
        wifi_util_error_print(WIFI_BUS,"%s:%d table node is not found:%s.%d\n", __func__,
            __LINE__, p_name_space, table_index);
        return bus_error_general;
    }

    return bus_error_success;
}

static void node_elems_free(elem_node_map_t* node, node_traversal_cb_param_t param)
{
    (void)param;
    VERIFY_NULL(node);

    if (node->node_data_type == node_elem_reg_data) {
        bus_mux_reg_node_data_t *reg_node_data = (bus_mux_reg_node_data_t *)node->node_elem_data;
        if (reg_node_data != NULL) {
            data_model_properties_t *p_data_model_prop = &reg_node_data->data_model_prop;
            if (p_data_model_prop->str_validation) {
                for (uint32_t index = 0; index < p_data_model_prop->num_of_str_validation; index++) {
                    free(p_data_model_prop->str_validation[index]);
                }
                free(p_data_model_prop->str_validation);
            }
        }
    }
    if (node->node_elem_data != NULL) {
        free(node->node_elem_data);
        node->node_elem_data = NULL;
    }
    wifi_util_dbg_print(WIFI_BUS,"node delete [%p]:%s:%s\r\n", node, node->name, node->full_name);
    free(node);
}

static void node_elem_recurse_traversal(elem_node_map_t* node, node_elem_traversal_arg_t *input_action)
{
    VERIFY_NULL(node);
    elem_node_map_t* child = node->child;

    if (node->reference_childs != reference_child_node) {
        while(child)
        {
            elem_node_map_t* tmp = child;
            child = child->nextSibling;
            node_elem_recurse_traversal(tmp, input_action);
        }
    } else {
        wifi_util_dbg_print(WIFI_BUS,"mirror link node found [%p]->child:%p\r\n", node, node->child);
    }

    if (input_action->traversal_cb != NULL) {
        input_action->traversal_cb(node, input_action->param);
    }
}

static void node_elem_traversal(elem_node_map_t* node, node_elem_traversal_arg_t *input_action)
{
    VERIFY_NULL(node);
    elem_node_map_t* parent = node->parent;
    elem_node_map_t* child  = node->child;

    if (node->reference_childs != reference_child_node) {
        while(child)
        {
            elem_node_map_t* tmp = child;
            child = child->nextSibling;
            node_elem_recurse_traversal(tmp, input_action);
        }
    } else {
        wifi_util_info_print(WIFI_BUS,"%s:%d mirror link node found [%p]->child:%p\r\n", __func__,
            __LINE__, node, node->child);
    }

    if (parent)
    {
        if(parent->child == node)
        {
            parent->child = node->nextSibling;
        }
        else
        {
            child = parent->child;
            while(child)
            {
                if(child->nextSibling == node)
                {
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

bus_error_t bus_remove_all_elems(elem_node_map_t *root)
{
    node_elem_traversal_arg_t  input_arg;
    input_arg.traversal_cb = node_elems_free;

    BUS_MUX_LOCK(get_bus_mux_mutex());

    while(root)
    {
        elem_node_map_t* tmp = root;
        root = root->nextSibling;
        node_elem_traversal(tmp, &input_arg);
    }

    BUS_MUX_UNLOCK(get_bus_mux_mutex());
    return bus_error_success;
}

bus_error_t free_node_elems(elem_node_map_t *node)
{
    node_elem_traversal_arg_t  input_arg;
    input_arg.traversal_cb = node_elems_free;

    BUS_MUX_LOCK(get_bus_mux_mutex());

    node_elem_traversal(node, &input_arg);

    BUS_MUX_UNLOCK(get_bus_mux_mutex());
    return bus_error_success;
}

char const* get_type_string(bus_element_type_t type)
{
    switch(type)
    {
        case bus_element_type_property:
            return "property";
        case bus_element_type_table:
            return "table";
        case bus_element_type_event:
            return "event";
        case bus_element_type_method:
            return "method";
        default:
            return "object";
    }
}

static void print_elem(elem_node_map_t *node, int level)
{
    wifi_util_dbg_print(WIFI_BUS,"%*s[name:%s type:%s full_name: %s addr:%p, parent:%p, child:%p]\n",
        level*2, level ? " " : "",
        node->name,
        get_type_string(node->type),
        node->full_name,
        node,
        node->parent,
        node->child);

    bus_mux_reg_node_data_t *reg_node_data = (bus_mux_reg_node_data_t *)node->node_elem_data;
    if ((node->node_data_type == node_elem_reg_data) && (reg_node_data != NULL)) {
        bus_callback_table_t *p_cb_table = &reg_node_data->cb_table;
        wifi_util_dbg_print(WIFI_BUS,"[full_name: %s get_cb:%p set_cb:%p add_cb:%p remove:%p event:%p method:%p]\n",
            node->full_name, p_cb_table->get_handler, p_cb_table->set_handler, p_cb_table->table_add_row_handler,
            p_cb_table->table_remove_row_handler, p_cb_table->event_sub_handler, p_cb_table->method_handler);
    } else {
        wifi_util_dbg_print(WIFI_BUS,"[cb:%d not found full_name: %s cb_pointer:%p]\n",
            node->node_data_type, node->full_name, reg_node_data);
    }
}

void print_registered_elems(elem_node_map_t *root, int level)
{
    elem_node_map_t *child   = root;
    elem_node_map_t *sibling = NULL;

    if(child) {
        print_elem(child, level);
        if(child->child) {
            print_registered_elems(child->child, level+1);
        }
        sibling = child->nextSibling;
        while(sibling) {
            print_elem(sibling, level);
            if(sibling->child) {
                print_registered_elems(sibling->child, level+1);
            }
            sibling = sibling->nextSibling;
        }
    }
}

bus_error_t bus_table_remove_row(elem_node_map_t *p_root_node, char *p_name_space)
{
    elem_node_map_t *table_row_node = get_bus_node_info(p_root_node, p_name_space);
    if (table_row_node != NULL) {
        return free_node_elems(table_row_node);
    }
    return bus_error_destination_not_found;
}

int check_dm_min_max_data_range(long int min_data, long int max_data, raw_data_t *bus_set_data)
{
    if (min_data == 0 && max_data == 0) {
        wifi_util_info_print(WIFI_BUS,"%s:%d: int range validation is not needed\n",__func__, __LINE__);
        return RETURN_OK;
    }

    wifi_util_info_print(WIFI_BUS,"%s:%d: set data type:%d\n",__func__, __LINE__, bus_set_data->data_type);
    if (bus_set_data->data_type == bus_data_type_boolean) {
        COMPARE_INT_RANGE((bool)min_data, (bool)max_data, bus_set_data->raw_data.b);
    } else if (bus_set_data->data_type == bus_data_type_int8) {
        COMPARE_INT_RANGE((int8_t)min_data, (int8_t)max_data, bus_set_data->raw_data.i8);
    } else if (bus_set_data->data_type == bus_data_type_uint8) {
        COMPARE_INT_RANGE((uint8_t)min_data, (uint8_t)max_data, bus_set_data->raw_data.u8);
    } else if (bus_set_data->data_type == bus_data_type_int16) {
        COMPARE_INT_RANGE((int16_t)min_data, (int16_t)max_data, bus_set_data->raw_data.i16);
    } else if (bus_set_data->data_type == bus_data_type_uint16) {
        COMPARE_INT_RANGE((uint16_t)min_data, (uint16_t)max_data, bus_set_data->raw_data.u16);
    } else if (bus_set_data->data_type == bus_data_type_int32) {
        COMPARE_INT_RANGE((int32_t)min_data, (int32_t)max_data, bus_set_data->raw_data.i32);
    } else if (bus_set_data->data_type == bus_data_type_uint32) {
        COMPARE_INT_RANGE((uint32_t)min_data, (uint32_t)max_data, bus_set_data->raw_data.u32);
    }

    return RETURN_OK;
}

int validate_dm_string_param(uint32_t num_of_str, char **str, char *set_str)
{
    if (num_of_str == 0) {
        wifi_util_info_print(WIFI_BUS,"%s:%d: string validation is not set\n",__func__, __LINE__);
    } else if (str == NULL || set_str == NULL) {
        wifi_util_info_print(WIFI_BUS,"%s:%d: input string is NULL:%p:%p\n", __func__, __LINE__, str, set_str);
    } else {
        uint32_t index;
        bool str_found = false;

        for(index = 0; index < num_of_str; index++) {
            if (str[index] && (strncmp(str[index], set_str, strlen(set_str) + 1) == 0)) {
                str_found = true;
                break;
	    }
        }
        if (str_found == false) {
            wifi_util_info_print(WIFI_BUS,"%s:%d: string:%s validation is failed:%d\n",__func__,
                __LINE__, set_str, num_of_str);
            return RETURN_ERR;
	}
    }

    return RETURN_OK;
}

int validate_dm_set_parameters(data_model_properties_t *data_model_prop, raw_data_t *bus_set_data)
{
    int ret = RETURN_ERR;

    BUS_CHECK_NULL_WITH_RC(data_model_prop, ret);

    if (data_model_prop->data_permission == false) {
        wifi_util_error_print(WIFI_BUS,"%s:%d: data is not permit to set\n",__func__, __LINE__);
        return ret;
    }

    ret = check_dm_min_max_data_range(data_model_prop->min_data_range, data_model_prop->max_data_range, bus_set_data);
    if (ret != RETURN_OK) {
        wifi_util_error_print(WIFI_BUS,"%s:%d: set data min/max data range is not propered\n",__func__, __LINE__);
        return ret;
    } else if (bus_set_data->data_type == bus_data_type_string) {
        ret = validate_dm_string_param(data_model_prop->num_of_str_validation, data_model_prop->str_validation,
            (char *)bus_set_data->raw_data.bytes);
    }

    return ret;
}

bus_data_prop_t *memory_alloc_for_bus_data_prop(void)
{
    bus_data_prop_t *temp = calloc(1, sizeof(bus_data_prop_t));
    VERIFY_NULL_WITH_RETURN_ADDR(temp);
    temp->ref_count = 1;
    return temp;
}

int bus_data_prop_retain(bus_data_prop_t *p_prop)
{
    VERIFY_NULL_WITH_RETURN_INT(p_prop);
    p_prop->ref_count++;
    return RETURN_OK;
}

void free_bus_raw_data(raw_data_t *data)
{
    if ((data->raw_data.bytes)
        && (data->data_type == bus_data_type_bytes
            || data->data_type == bus_data_type_string)) {
        free(data->raw_data.bytes);
    }
}

void bus_release_data_prop(bus_data_prop_t *p_data_prop, uint32_t *num_prop)
{
    bus_data_prop_t *next, *prev, *cur;

    if (p_data_prop->ref_count == 1) {
        free_bus_raw_data(&p_data_prop->value);
        p_data_prop->is_data_set = false;
        p_data_prop->ref_count = 0;
        (*num_prop)--;
    } else if (p_data_prop->ref_count > 1) {
        wifi_util_info_print(WIFI_BUS,"%s:%d memory:%p still have some references:%d\r\n",
                __func__, __LINE__, p_data_prop, p_data_prop->ref_count);
        p_data_prop->ref_count--;
    } else {
        wifi_util_info_print(WIFI_BUS,"%s:%d memory:%p not have some references:%d\r\n",
                __func__, __LINE__, p_data_prop, p_data_prop->ref_count);
    }

    prev = p_data_prop;
    cur = p_data_prop->next_data;
    while (cur) {
        next = cur->next_data;
        if (cur->ref_count == 1) {
            free_bus_raw_data(&cur->value);
            free(cur);
            (*num_prop)--;
            prev->next_data = next;
        } else if (cur->ref_count > 1) {
            wifi_util_info_print(WIFI_BUS,"%s:%d memory:%p still have some references:%d\r\n",
                __func__, __LINE__, cur, cur->ref_count);
            cur->ref_count--;
            prev = cur;
        } else {
            wifi_util_error_print(WIFI_BUS,"%s:%d memory:%p not have some references:%d\r\n",
                __func__, __LINE__, cur, cur->ref_count);
            prev = cur;
        }
        cur = next;
    }

    wifi_util_info_print(WIFI_BUS,"%s:%d remaining num_prop:%d\r\n", __func__, __LINE__, *num_prop);
}

void bus_release_data_obj(bus_data_obj_t *p_bus_obj)
{
    bus_release_data_prop(&p_bus_obj->data_prop, &p_bus_obj->num_prop);
}

int clone_raw_data(raw_data_t *dst, raw_data_t *src)
{
    BUS_CHECK_NULL_WITH_RC(dst, RETURN_ERR);
    BUS_CHECK_NULL_WITH_RC(src, RETURN_ERR);

    memcpy(dst, src, sizeof(raw_data_t));

    if ((dst->data_type == bus_data_type_bytes) || (dst->data_type == bus_data_type_string)) {
        dst->raw_data.bytes = malloc(dst->raw_data_len);
        BUS_CHECK_NULL_WITH_RC(dst->raw_data.bytes, RETURN_ERR);
        memcpy(dst->raw_data.bytes, src->raw_data.bytes, dst->raw_data_len);
    }
    return RETURN_OK;
}

int bus_get_raw_data_prop(bus_data_prop_t *p_bus_prop, const char *event_name, raw_data_t *p_raw_data)
{
    BUS_CHECK_NULL_WITH_RC(p_bus_prop, RETURN_ERR);
    BUS_CHECK_NULL_WITH_RC(p_raw_data, RETURN_ERR);

    if (event_name == NULL) {
        *p_raw_data = p_bus_prop->value;
    } else {
        uint32_t str_len = MIN_VAL(strlen(event_name) + 1, BUS_MAX_NAME_LENGTH);

        while(p_bus_prop) {
            if (!strncmp(event_name, p_bus_prop->name, str_len)) {
                *p_raw_data = p_bus_prop->value;
                return RETURN_OK;
            }
            p_bus_prop = p_bus_prop->next_data;
        }
    }

    return RETURN_ERR;
}

int bus_set_raw_data_prop(bus_data_prop_t *p_bus_prop, const char *event_name, raw_data_t *p_raw_data)
{
    BUS_CHECK_NULL_WITH_RC(p_bus_prop, RETURN_ERR);
    BUS_CHECK_NULL_WITH_RC(p_raw_data, RETURN_ERR);

    if (p_bus_prop->next_data == NULL && p_bus_prop->is_data_set == false) {
        clone_raw_data(&p_bus_prop->value, p_raw_data);
        if (event_name != NULL) {
            p_bus_prop->name_len = strlen(event_name) + 1;
            strncpy(p_bus_prop->name, event_name, p_bus_prop->name_len);
        } else {
            p_bus_prop->name_len = 0;
            memset(p_bus_prop->name, 0, sizeof(p_bus_prop->name));
        }
        p_bus_prop->is_data_set = true;
        bus_data_prop_retain(p_bus_prop);
    } else {
        bus_data_prop_t *temp = memory_alloc_for_bus_data_prop();
        BUS_CHECK_NULL_WITH_RC(temp, RETURN_ERR);

        clone_raw_data(&temp->value, p_raw_data);
        temp->is_data_set = true;
        if (event_name != NULL) {
            temp->name_len = strlen(event_name) + 1;
            strncpy(temp->name, event_name, temp->name_len);
        } else {
            temp->name_len = 0;
            memset(temp->name, 0, sizeof(temp->name));
        }

        temp->next_data = p_bus_prop->next_data;
        p_bus_prop->next_data = temp;
    }

    return RETURN_OK;
}

int bus_set_raw_data_obj(bus_data_obj_t *p_bus_obj, const char *event_name, raw_data_t *p_raw_data)
{
    BUS_CHECK_NULL_WITH_RC(p_bus_obj, RETURN_ERR);
    BUS_CHECK_NULL_WITH_RC(p_raw_data, RETURN_ERR);

    int ret = bus_set_raw_data_prop(&p_bus_obj->data_prop, event_name, p_raw_data);
    if (ret == RETURN_OK) {
        p_bus_obj->num_prop++;
    }

    return ret;
}
