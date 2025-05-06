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
#include "he_bus_data_conversion.h"
#include "he_bus_core.h"
#include "he_bus_memory.h"
#include "he_bus_utils.h"

#define VERIFY_NULL_WITH_RC(T)                                                       \
    if (NULL == (T)) {                                                               \
        he_bus_core_error_print("[%s] input parameter: %s is NULL\n", __func__, #T); \
        return he_bus_error_invalid_input;                                           \
    }

uint32_t convert_he_bus_raw_data_to_buffer(he_bus_raw_data_t *p_data, uint8_t *p_cur_data)
{
    if (p_data == NULL || p_cur_data == NULL) {
        he_bus_core_error_print("%s:%d Invalid input param\r\n", __func__, __LINE__);
        return 0;
    }

    uint32_t l_data_len = 0;

    memcpy(p_cur_data, &p_data->data_type, sizeof(p_data->data_type));
    p_cur_data += sizeof(p_data->data_type);
    l_data_len += sizeof(p_data->data_type);

    memcpy(p_cur_data, &p_data->raw_data_len, sizeof(p_data->raw_data_len));
    p_cur_data += sizeof(p_data->raw_data_len);
    l_data_len += sizeof(p_data->raw_data_len);

    if (p_data->data_type == he_bus_data_type_boolean) {
        memcpy(p_cur_data, &p_data->raw_data.b, sizeof(p_data->raw_data.b));
        p_cur_data += sizeof(p_data->raw_data.b);
        l_data_len += sizeof(p_data->raw_data.b);
    } else if (p_data->data_type == he_bus_data_type_char) {
        memcpy(p_cur_data, &p_data->raw_data.c, sizeof(p_data->raw_data.c));
        p_cur_data += sizeof(p_data->raw_data.c);
        l_data_len += sizeof(p_data->raw_data.c);
    } else if (p_data->data_type == he_bus_data_type_byte) {
        memcpy(p_cur_data, &p_data->raw_data.u, sizeof(p_data->raw_data.u));
        p_cur_data += sizeof(p_data->raw_data.u);
        l_data_len += sizeof(p_data->raw_data.u);
    } else if (p_data->data_type == he_bus_data_type_int8) {
        memcpy(p_cur_data, &p_data->raw_data.i8, sizeof(p_data->raw_data.i8));
        p_cur_data += sizeof(p_data->raw_data.i8);
        l_data_len += sizeof(p_data->raw_data.i8);
    } else if (p_data->data_type == he_bus_data_type_uint8) {
        memcpy(p_cur_data, &p_data->raw_data.u8, sizeof(p_data->raw_data.u8));
        p_cur_data += sizeof(p_data->raw_data.u8);
        l_data_len += sizeof(p_data->raw_data.u8);
    } else if (p_data->data_type == he_bus_data_type_int16) {
        memcpy(p_cur_data, &p_data->raw_data.i16, sizeof(p_data->raw_data.i16));
        p_cur_data += sizeof(p_data->raw_data.i16);
        l_data_len += sizeof(p_data->raw_data.i16);
    } else if (p_data->data_type == he_bus_data_type_uint16) {
        memcpy(p_cur_data, &p_data->raw_data.u16, sizeof(p_data->raw_data.u16));
        p_cur_data += sizeof(p_data->raw_data.u16);
        l_data_len += sizeof(p_data->raw_data.u16);
    } else if (p_data->data_type == he_bus_data_type_int32) {
        memcpy(p_cur_data, &p_data->raw_data.i32, sizeof(p_data->raw_data.i32));
        p_cur_data += sizeof(p_data->raw_data.i32);
        l_data_len += sizeof(p_data->raw_data.i32);
    } else if (p_data->data_type == he_bus_data_type_uint32) {
        memcpy(p_cur_data, &p_data->raw_data.u32, sizeof(p_data->raw_data.u32));
        p_cur_data += sizeof(p_data->raw_data.u32);
        l_data_len += sizeof(p_data->raw_data.u32);
    } else if (p_data->data_type == he_bus_data_type_int64) {
        memcpy(p_cur_data, &p_data->raw_data.i64, sizeof(p_data->raw_data.i64));
        p_cur_data += sizeof(p_data->raw_data.i64);
        l_data_len += sizeof(p_data->raw_data.i64);
    } else if (p_data->data_type == he_bus_data_type_uint64) {
        memcpy(p_cur_data, &p_data->raw_data.u64, sizeof(p_data->raw_data.u64));
        p_cur_data += sizeof(p_data->raw_data.u64);
        l_data_len += sizeof(p_data->raw_data.u64);
    } else if (p_data->data_type == he_bus_data_type_single) {
        memcpy(p_cur_data, &p_data->raw_data.f32, sizeof(p_data->raw_data.f64));
        p_cur_data += sizeof(p_data->raw_data.f32);
        l_data_len += sizeof(p_data->raw_data.f32);
    } else if (p_data->data_type == he_bus_data_type_double) {
        memcpy(p_cur_data, &p_data->raw_data.f64, sizeof(p_data->raw_data.f64));
        p_cur_data += sizeof(p_data->raw_data.f64);
        l_data_len += sizeof(p_data->raw_data.f64);
    } else {
        if (p_data->raw_data.bytes != NULL) {
            memcpy(p_cur_data, p_data->raw_data.bytes, p_data->raw_data_len);
            p_cur_data += p_data->raw_data_len;
            l_data_len += p_data->raw_data_len;
        }
    }

    return l_data_len;
}

uint32_t convert_buffer_to_raw_data(uint8_t *p_cur_data, he_bus_raw_data_t *p_data)
{
    if (p_cur_data == NULL || p_data == NULL) {
        he_bus_core_error_print("%s:%d Invalid input param\r\n", __func__, __LINE__);
        return 0;
    }
    uint32_t l_data_len = 0;

    memcpy(&p_data->data_type, p_cur_data, sizeof(p_data->data_type));
    p_cur_data += sizeof(p_data->data_type);
    l_data_len += sizeof(p_data->data_type);

    memcpy(&p_data->raw_data_len, p_cur_data, sizeof(p_data->raw_data_len));
    p_cur_data += sizeof(p_data->raw_data_len);
    l_data_len += sizeof(p_data->raw_data_len);

    if (p_data->data_type == he_bus_data_type_boolean) {
        memcpy(&p_data->raw_data.b, p_cur_data, sizeof(p_data->raw_data.b));
        p_cur_data += sizeof(p_data->raw_data.b);
        l_data_len += sizeof(p_data->raw_data.b);
    } else if (p_data->data_type == he_bus_data_type_char) {
        memcpy(&p_data->raw_data.c, p_cur_data, sizeof(p_data->raw_data.c));
        p_cur_data += sizeof(p_data->raw_data.c);
        l_data_len += sizeof(p_data->raw_data.c);
    } else if (p_data->data_type == he_bus_data_type_byte) {
        memcpy(&p_data->raw_data.u, p_cur_data, sizeof(p_data->raw_data.u));
        p_cur_data += sizeof(p_data->raw_data.u);
        l_data_len += sizeof(p_data->raw_data.u);
    } else if (p_data->data_type == he_bus_data_type_int8) {
        memcpy(&p_data->raw_data.i8, p_cur_data, sizeof(p_data->raw_data.i8));
        p_cur_data += sizeof(p_data->raw_data.i8);
        l_data_len += sizeof(p_data->raw_data.i8);
    } else if (p_data->data_type == he_bus_data_type_uint8) {
        memcpy(&p_data->raw_data.u8, p_cur_data, sizeof(p_data->raw_data.u8));
        p_cur_data += sizeof(p_data->raw_data.u8);
        l_data_len += sizeof(p_data->raw_data.u8);
    } else if (p_data->data_type == he_bus_data_type_int16) {
        memcpy(&p_data->raw_data.i16, p_cur_data, sizeof(p_data->raw_data.i16));
        p_cur_data += sizeof(p_data->raw_data.i16);
        l_data_len += sizeof(p_data->raw_data.i16);
    } else if (p_data->data_type == he_bus_data_type_uint16) {
        memcpy(&p_data->raw_data.u16, p_cur_data, sizeof(p_data->raw_data.u16));
        p_cur_data += sizeof(p_data->raw_data.u16);
        l_data_len += sizeof(p_data->raw_data.u16);
    } else if (p_data->data_type == he_bus_data_type_int32) {
        memcpy(&p_data->raw_data.i32, p_cur_data, sizeof(p_data->raw_data.i32));
        p_cur_data += sizeof(p_data->raw_data.i32);
        l_data_len += sizeof(p_data->raw_data.i32);
    } else if (p_data->data_type == he_bus_data_type_uint32) {
        memcpy(&p_data->raw_data.u32, p_cur_data, sizeof(p_data->raw_data.u32));
        p_cur_data += sizeof(p_data->raw_data.u32);
        l_data_len += sizeof(p_data->raw_data.u32);
    } else if (p_data->data_type == he_bus_data_type_int64) {
        memcpy(&p_data->raw_data.i64, p_cur_data, sizeof(p_data->raw_data.i64));
        p_cur_data += sizeof(p_data->raw_data.i64);
        l_data_len += sizeof(p_data->raw_data.i64);
    } else if (p_data->data_type == he_bus_data_type_uint64) {
        memcpy(&p_data->raw_data.u64, p_cur_data, sizeof(p_data->raw_data.u64));
        p_cur_data += sizeof(p_data->raw_data.u64);
        l_data_len += sizeof(p_data->raw_data.u64);
    } else if (p_data->data_type == he_bus_data_type_single) {
        memcpy(&p_data->raw_data.f32, p_cur_data, sizeof(p_data->raw_data.f64));
        p_cur_data += sizeof(p_data->raw_data.f32);
        l_data_len += sizeof(p_data->raw_data.f32);
    } else if (p_data->data_type == he_bus_data_type_double) {
        memcpy(&p_data->raw_data.f64, p_cur_data, sizeof(p_data->raw_data.f64));
        p_cur_data += sizeof(p_data->raw_data.f64);
        l_data_len += sizeof(p_data->raw_data.f64);
    } else if (p_data->raw_data_len != 0) {
        p_data->raw_data.bytes = he_bus_calloc(1, p_data->raw_data_len);

        memcpy(p_data->raw_data.bytes, p_cur_data, p_data->raw_data_len);
        p_cur_data += p_data->raw_data_len;
        l_data_len += p_data->raw_data_len;
    }

    return l_data_len;
}

uint32_t convert_he_bus_data_object_to_buffer(uint8_t *tmp, he_bus_data_object_t *p_obj_data)
{
    if (tmp == NULL || p_obj_data == NULL) {
        he_bus_core_error_print("%s:%d Invalid input param\r\n", __func__, __LINE__);
        return 0;
    }
    uint32_t obj_data_len = 0;
    uint32_t raw_data_len;

    memcpy(tmp, &p_obj_data->name_len, sizeof(p_obj_data->name_len));
    tmp += sizeof(p_obj_data->name_len);
    obj_data_len += sizeof(p_obj_data->name_len);

    strncpy((char *)tmp, p_obj_data->name, p_obj_data->name_len);
    tmp += p_obj_data->name_len;
    obj_data_len += p_obj_data->name_len;

    memcpy(tmp, &p_obj_data->msg_sub_type, sizeof(p_obj_data->msg_sub_type));
    tmp += sizeof(p_obj_data->msg_sub_type);
    obj_data_len += sizeof(p_obj_data->msg_sub_type);

    memcpy(tmp, &p_obj_data->is_data_set, sizeof(p_obj_data->is_data_set));
    tmp += sizeof(p_obj_data->is_data_set);
    obj_data_len += sizeof(p_obj_data->is_data_set);

    memcpy(tmp, &p_obj_data->status, sizeof(p_obj_data->status));
    tmp += sizeof(p_obj_data->status);
    obj_data_len += sizeof(p_obj_data->status);

    raw_data_len = convert_he_bus_raw_data_to_buffer(&p_obj_data->data, tmp);
    tmp += raw_data_len;
    obj_data_len += raw_data_len;

    return obj_data_len;
}

uint32_t convert_buffer_to_bus_data_object(he_bus_data_object_t *p_obj_data, uint8_t *tmp)
{
    if (tmp == NULL || p_obj_data == NULL) {
        he_bus_core_error_print("%s:%d Invalid input param\r\n", __func__, __LINE__);
        return 0;
    }
    uint32_t obj_data_len = 0;
    uint32_t raw_data_len;

    memcpy(&p_obj_data->name_len, tmp, sizeof(p_obj_data->name_len));
    tmp += sizeof(p_obj_data->name_len);
    obj_data_len += sizeof(p_obj_data->name_len);

    strncpy(p_obj_data->name, (char *)tmp, p_obj_data->name_len);
    tmp += p_obj_data->name_len;
    obj_data_len += p_obj_data->name_len;

    memcpy(&p_obj_data->msg_sub_type, tmp, sizeof(p_obj_data->msg_sub_type));
    tmp += sizeof(p_obj_data->msg_sub_type);
    obj_data_len += sizeof(p_obj_data->msg_sub_type);

    memcpy(&p_obj_data->is_data_set, tmp, sizeof(p_obj_data->is_data_set));
    tmp += sizeof(p_obj_data->is_data_set);
    obj_data_len += sizeof(p_obj_data->is_data_set);

    memcpy(&p_obj_data->status, tmp, sizeof(p_obj_data->status));
    tmp += sizeof(p_obj_data->status);
    obj_data_len += sizeof(p_obj_data->status);

    raw_data_len = convert_buffer_to_raw_data(tmp, &p_obj_data->data);
    tmp += raw_data_len;
    obj_data_len += raw_data_len;

    return obj_data_len;
}

he_bus_error_t convert_bus_raw_msg_data_to_buffer(he_bus_raw_data_msg_t *raw_data,
    he_bus_stretch_buff_t *output_data)
{
    uint8_t *tmp, *total_msg_len;
    uint32_t buff_len;

    if (raw_data == NULL || output_data == NULL) {
        he_bus_core_error_print("%s:%d Invalid input param\r\n", __func__, __LINE__);
        return he_bus_error_invalid_input;
    } else if (raw_data->total_raw_msg_len == 0) {
        he_bus_core_error_print("%s:%d Raw data not found\r\n", __func__, __LINE__);
        return he_bus_error_invalid_input;
    }

    he_bus_core_info_print("%s:%d recv data len:%d\r\n", __func__, __LINE__,
        raw_data->total_raw_msg_len);
    output_data->buff = he_bus_calloc(1, raw_data->total_raw_msg_len);
    tmp = output_data->buff;
    buff_len = 0;

    memcpy(tmp, &raw_data->bus_msg_identity, sizeof(raw_data->bus_msg_identity));
    tmp += sizeof(raw_data->bus_msg_identity);
    buff_len += sizeof(raw_data->bus_msg_identity);

    // total msg len will update later
    total_msg_len = tmp;
    tmp += sizeof(raw_data->total_raw_msg_len);
    buff_len += sizeof(raw_data->total_raw_msg_len);

    memcpy(tmp, &raw_data->component_name_len, sizeof(raw_data->component_name_len));
    tmp += sizeof(raw_data->component_name_len);
    buff_len += sizeof(raw_data->component_name_len);

    strncpy((char *)tmp, raw_data->component_name, raw_data->component_name_len);
    tmp += raw_data->component_name_len;
    buff_len += raw_data->component_name_len;

    memcpy(tmp, &raw_data->msg_type, sizeof(raw_data->msg_type));
    tmp += sizeof(raw_data->msg_type);
    buff_len += sizeof(raw_data->msg_type);

    memcpy(tmp, &raw_data->num_of_obj, sizeof(raw_data->num_of_obj));
    tmp += sizeof(raw_data->num_of_obj);
    buff_len += sizeof(raw_data->num_of_obj);

    if (raw_data->data_obj.is_data_set == true && raw_data->num_of_obj != 0) {
        he_bus_data_object_t *p_obj_data = &raw_data->data_obj;
        uint32_t obj_len;

        obj_len = convert_he_bus_data_object_to_buffer(tmp, p_obj_data);
        tmp += obj_len;
        buff_len += obj_len;

        p_obj_data = p_obj_data->next_data;
        while (p_obj_data != NULL) {
            obj_len = convert_he_bus_data_object_to_buffer(tmp, p_obj_data);
            tmp += obj_len;
            buff_len += obj_len;

            p_obj_data = p_obj_data->next_data;
        }
    } else {
        he_bus_core_error_print("%s:%d payload data is not available for:%s :%d\r\n", __func__,
            __LINE__, raw_data->component_name, raw_data->num_of_obj);
    }

    memcpy(total_msg_len, &buff_len, sizeof(buff_len));
    he_bus_core_info_print("%s:%d send buff data len:%d, actual len:%d\r\n", __func__, __LINE__,
        buff_len, raw_data->total_raw_msg_len);
    // ipc_unix_client_send_data(buff, buff_len);
    output_data->buff_len = buff_len;

    return he_bus_error_success;
}

he_bus_error_t convert_buffer_to_bus_raw_msg_data(he_bus_raw_data_msg_t *raw_data,
    he_bus_stretch_buff_t *input_data)
{
    uint8_t *tmp = input_data->buff;
    uint32_t buff_len = 0;
    uint32_t obj_len;

    if (input_data == NULL || raw_data == NULL) {
        he_bus_core_error_print("%s:%d Invalid input param\r\n", __func__, __LINE__);
        return he_bus_error_invalid_input;
    } else if (tmp == NULL || input_data->buff_len == 0) {
        he_bus_core_error_print("%s:%d Raw data not found\r\n", __func__, __LINE__);
        return he_bus_error_invalid_input;
    }

    he_bus_core_info_print("%s:%d recv raw data len:%d\r\n", __func__, __LINE__,
        input_data->buff_len);

    memcpy(&raw_data->bus_msg_identity, tmp, sizeof(raw_data->bus_msg_identity));
    tmp += sizeof(raw_data->bus_msg_identity);
    buff_len += sizeof(raw_data->bus_msg_identity);

    memcpy(&raw_data->total_raw_msg_len, tmp, sizeof(raw_data->total_raw_msg_len));
    tmp += sizeof(raw_data->total_raw_msg_len);
    buff_len += sizeof(raw_data->total_raw_msg_len);

    memcpy(&raw_data->component_name_len, tmp, sizeof(raw_data->component_name_len));
    tmp += sizeof(raw_data->component_name_len);
    buff_len += sizeof(raw_data->component_name_len);

    strncpy(raw_data->component_name, (char *)tmp, raw_data->component_name_len);
    tmp += raw_data->component_name_len;
    buff_len += raw_data->component_name_len;

    memcpy(&raw_data->msg_type, tmp, sizeof(raw_data->msg_type));
    tmp += sizeof(raw_data->msg_type);
    buff_len += sizeof(raw_data->msg_type);

    memcpy(&raw_data->num_of_obj, tmp, sizeof(raw_data->num_of_obj));
    tmp += sizeof(raw_data->num_of_obj);
    buff_len += sizeof(raw_data->num_of_obj);

    raw_data->data_obj.next_data = NULL;

    if (raw_data->num_of_obj != 0) {

        obj_len = convert_buffer_to_bus_data_object(&raw_data->data_obj, tmp);
        tmp += obj_len;
        buff_len += obj_len;

        uint32_t l_num_of_obj = raw_data->num_of_obj - 1;
        while (l_num_of_obj) {
            he_bus_data_object_t *l_obj;

            l_obj = he_bus_calloc(1, sizeof(he_bus_data_object_t));

            l_obj->next_data = NULL;

            obj_len = convert_buffer_to_bus_data_object(l_obj, tmp);
            tmp += obj_len;
            buff_len += obj_len;

            if (raw_data->data_obj.next_data == NULL) {
                raw_data->data_obj.next_data = l_obj;
            } else {
                l_obj->next_data = raw_data->data_obj.next_data;
                raw_data->data_obj.next_data = l_obj;
            }
            l_num_of_obj--;
        }
    }

    he_bus_core_info_print("%s:%d payload data recv from:%s :%d\r\n", __func__, __LINE__,
        raw_data->component_name, raw_data->num_of_obj);
    he_bus_core_info_print("%s:%d recv buff data len:%d, actual len:%d\r\n", __func__, __LINE__,
        buff_len, raw_data->total_raw_msg_len);

    return he_bus_error_success;
}

uint32_t set_bus_object_payload_data(he_bus_raw_data_t *src_data, he_bus_raw_data_t *dest_data)
{
    uint32_t total_payload_data = 0;

    src_data->data_type = dest_data->data_type;
    total_payload_data += sizeof(dest_data->data_type);
    src_data->raw_data = dest_data->raw_data;
    total_payload_data += dest_data->raw_data_len;
    src_data->raw_data_len = dest_data->raw_data_len;
    total_payload_data += sizeof(dest_data->raw_data_len);
    return total_payload_data;
}

uint32_t set_bus_object_data(char *event_name, he_bus_data_object_t *p_obj_data,
    he_bus_msg_sub_type_t msg_sub_type, he_bus_raw_data_t *cfg_data, he_bus_error_t ret_status)
{
    uint32_t total_len = 0;

    if (p_obj_data->next_data == NULL && (p_obj_data->is_data_set == false)) {
        p_obj_data->name_len = strlen(event_name) + 1;
        strncpy(p_obj_data->name, event_name, p_obj_data->name_len);
        total_len = sizeof(p_obj_data->name_len);
        total_len += p_obj_data->name_len;
        p_obj_data->msg_sub_type = msg_sub_type;
        total_len += sizeof(p_obj_data->msg_sub_type);
        p_obj_data->is_data_set = true;
        total_len += sizeof(p_obj_data->is_data_set);
        p_obj_data->status = ret_status;
        total_len += sizeof(p_obj_data->status);
        total_len += set_bus_object_payload_data(&p_obj_data->data, cfg_data);
        p_obj_data->next_data = NULL;
    } else {
        he_bus_data_object_t *tmp = he_bus_calloc(1, sizeof(he_bus_data_object_t));

        tmp->name_len = strlen(event_name) + 1;
        strncpy(tmp->name, event_name, tmp->name_len);
        total_len = sizeof(tmp->name_len);
        total_len += tmp->name_len;
        tmp->msg_sub_type = msg_sub_type;
        total_len += sizeof(tmp->msg_sub_type);
        tmp->is_data_set = true;
        total_len += sizeof(tmp->is_data_set);
        p_obj_data->status = ret_status;
        total_len += sizeof(p_obj_data->status);
        total_len += set_bus_object_payload_data(&tmp->data, cfg_data);

        if (p_obj_data->next_data == NULL) {
            p_obj_data->next_data = tmp;
            tmp->next_data = NULL;
        } else {
            tmp->next_data = p_obj_data->next_data;
            p_obj_data->next_data = tmp;
        }
    }
    return total_len;
}

void free_raw_data_struct(he_bus_raw_data_t *p_data)
{
    he_bus_core_info_print("%s:%d free raw obj data type:%02x\r\n", __func__, __LINE__,
        p_data->data_type);
    if ((p_data->data_type == he_bus_data_type_string ||
            p_data->data_type == he_bus_data_type_bytes) &&
        p_data->raw_data.bytes != NULL) {
        he_bus_free(p_data->raw_data.bytes);
        p_data->raw_data.bytes = NULL;
    }
}

void free_bus_msg_obj_data(he_bus_data_object_t *p_obj_data)
{
    free_raw_data_struct(&p_obj_data->data);
    p_obj_data = p_obj_data->next_data;
    he_bus_data_object_t *temp;

    he_bus_core_info_print("%s:%d free p_obj_data:%p\r\n", __func__, __LINE__, p_obj_data);
    while (p_obj_data != NULL) {
        temp = p_obj_data;
        p_obj_data = p_obj_data->next_data;
        free_raw_data_struct(&temp->data);
        he_bus_free(temp);
    }
}

he_bus_error_t process_bus_sub_event(he_bus_handle_t handle, int socket_fd, char *comp_name,
    he_bus_data_object_t *p_obj_data)
{
    subscription_element_t *p_sub_data;
    sub_payload_data_t sub_recv_data;

    if (handle == NULL || handle->root_element == NULL || p_obj_data == NULL ||
        p_obj_data->name_len == 0) {
        he_bus_core_error_print("%s:%d Node root element or object name is NULL - msg from:%s\r\n",
            __func__, __LINE__, comp_name);
        return he_bus_error_invalid_input;
    }

    element_node_t *node = retrieve_instance_element(handle, handle->root_element,
        p_obj_data->name);
    if (node == NULL) {
        he_bus_core_error_print("%s:%d Node is not found for :%s namespace\r\n", __func__, __LINE__,
            p_obj_data->name);
        return he_bus_error_destination_not_found;
    } else {
        if (node->subscriptions == NULL) {
            node->subscriptions = hash_map_create();
            if (node->subscriptions == NULL) {
                he_bus_core_error_print(
                    "%s:%d subscriptions map alloc is failed for %s:namespace\r\n", __func__,
                    __LINE__, p_obj_data->name);
                return he_bus_error_out_of_resources;
            }
        }
        he_bus_core_info_print("%s:%d fetch comp from sub map:%s curr stream id:%d\r\n", __func__,
            __LINE__, comp_name, socket_fd);
        ELM_LOCK(node->element_mutex);
        p_sub_data = hash_map_get(node->subscriptions, comp_name);
        if (p_sub_data == NULL) {
            p_sub_data = he_bus_calloc(1, sizeof(subscription_element_t));

            strncpy(p_sub_data->component_name, comp_name, strlen(comp_name) + 1);
            strncpy(p_sub_data->full_name, p_obj_data->name, strlen(p_obj_data->name) + 1);
            get_client_broadcast_fd(handle, comp_name, &socket_fd);
            p_sub_data->socket_fd = socket_fd;
            if (p_obj_data->data.data_type == he_bus_data_type_bytes) {
                memcpy(&sub_recv_data, p_obj_data->data.raw_data.bytes,
                    p_obj_data->data.raw_data_len);
                p_sub_data->action = sub_recv_data.action;
            } else {
                ELM_UNLOCK(node->element_mutex);
                he_bus_core_error_print("%s:%d wrong sub action raw data type:%d for %s\r\n",
                    __func__, __LINE__, p_obj_data->data.data_type, p_obj_data->name);
                return he_bus_error_invalid_input;
            }
            hash_map_put(node->subscriptions, strdup(comp_name), p_sub_data);
            he_bus_core_info_print(
                "%s:%d successfully added to sub map:%s::%s[%p] stream_id:%d\r\n", __func__,
                __LINE__, comp_name, p_obj_data->name, p_sub_data, socket_fd);

            if (node->cb_table.event_sub_handler != NULL) {
                bool autoPublish;
                node->cb_table.event_sub_handler(p_obj_data->name, p_sub_data->action,
                    sub_recv_data.interval, &autoPublish);
            }
        } else {
            ELM_UNLOCK(node->element_mutex);
            he_bus_core_error_print("%s:%d sub already found for comp:%s\r\n", __func__, __LINE__,
                comp_name);
            return he_bus_error_subscription_already_exist;
        }
        ELM_UNLOCK(node->element_mutex);
    }

    return he_bus_error_success;
}

he_bus_error_t process_bus_get_event(he_bus_handle_t handle, char *comp_name,
    he_bus_data_object_t *p_obj_data, he_bus_raw_data_t *p_res_raw_data)
{
    VERIFY_NULL_WITH_RC(handle);
    VERIFY_NULL_WITH_RC(comp_name);
    VERIFY_NULL_WITH_RC(p_obj_data);
    VERIFY_NULL_WITH_RC(p_res_raw_data);

    he_bus_error_t status = he_bus_error_success;
    if (handle->root_element == NULL || p_obj_data->name_len == 0) {
        he_bus_core_error_print("%s:%d Node root element or object name is NULL - msg from:%s\r\n",
            __func__, __LINE__, comp_name);
        return he_bus_error_invalid_input;
    }

    element_node_t *node = retrieve_instance_element(handle, handle->root_element,
        p_obj_data->name);
    if (node == NULL) {
        he_bus_core_error_print("%s:%d Node is not found for :%s namespace\r\n", __func__, __LINE__,
            p_obj_data->name);
        return he_bus_error_destination_not_found;
    } else {
        if (node->cb_table.get_handler != NULL) {
            ELM_LOCK(node->element_mutex);
            status = node->cb_table.get_handler(p_obj_data->name, p_res_raw_data);
            ELM_UNLOCK(node->element_mutex);
        } else {
            he_bus_core_error_print("%s:%d Node get handler is not found for :%s namespace\r\n",
                __func__, __LINE__, p_obj_data->name);
            return he_bus_error_invalid_handle;
        }
    }
    return status;
}

he_bus_error_t process_bus_set_event(he_bus_handle_t handle, char *comp_name,
    he_bus_data_object_t *p_obj_data)
{
    VERIFY_NULL_WITH_RC(handle);
    VERIFY_NULL_WITH_RC(comp_name);
    VERIFY_NULL_WITH_RC(p_obj_data);

    he_bus_error_t status = he_bus_error_success;
    if (handle->root_element == NULL || p_obj_data->name_len == 0) {
        he_bus_core_error_print("%s:%d Node root element or object name is NULL - msg from:%s\r\n",
            __func__, __LINE__, comp_name);
        return he_bus_error_invalid_input;
    }

    element_node_t *node = retrieve_instance_element(handle, handle->root_element,
        p_obj_data->name);
    if (node == NULL) {
        he_bus_core_error_print("%s:%d Node is not found for :%s namespace\r\n", __func__, __LINE__,
            p_obj_data->name);
        return he_bus_error_destination_not_found;
    } else {
        if (node->cb_table.set_handler != NULL) {
            ELM_LOCK(node->element_mutex);
            status = node->cb_table.set_handler(p_obj_data->name, &p_obj_data->data);
            ELM_UNLOCK(node->element_mutex);
        } else {
            he_bus_core_error_print("%s:%d Node get handler is not found for :%s namespace\r\n",
                __func__, __LINE__, p_obj_data->name);
            return he_bus_error_invalid_handle;
        }
    }
    return status;
}

he_bus_error_t handle_bus_msg_req_data(he_bus_handle_t handle, int fd,
    he_bus_raw_data_msg_t *p_msg_data, he_bus_raw_data_msg_t *p_res_data)
{
    VERIFY_NULL_WITH_RC(handle);
    VERIFY_NULL_WITH_RC(p_msg_data);
    VERIFY_NULL_WITH_RC(p_res_data);

    he_bus_error_t ret = he_bus_error_success;
    he_bus_data_object_t *p_obj_data = &p_msg_data->data_obj;
    uint32_t l_num_of_obj = (uint32_t)p_msg_data->num_of_obj;
    he_bus_raw_data_t payload_data = { 0 };

    prepare_initial_bus_header(p_res_data, p_msg_data->component_name, he_bus_msg_response);
    he_bus_core_info_print("%s:%d msg sub type:%d from:%s l_num_of_obj:%d\r\n", __func__, __LINE__,
        p_obj_data->msg_sub_type, p_obj_data->name, l_num_of_obj);
    while (l_num_of_obj > 0) {
        switch (p_obj_data->msg_sub_type) {
        case he_bus_msg_reg_event:

            break;
        case he_bus_msg_get_event:
            ret = process_bus_get_event(handle, p_msg_data->component_name, p_obj_data,
                &payload_data);
            prepare_rem_payload_bus_msg_data(p_obj_data->name, p_res_data, p_obj_data->msg_sub_type,
                &payload_data, ret);
            break;
        case he_bus_msg_set_event:
            ret = process_bus_set_event(handle, p_msg_data->component_name, p_obj_data);

            prepare_rem_payload_bus_msg_data(p_obj_data->name, p_res_data, p_obj_data->msg_sub_type,
                &payload_data, ret);
            break;
        case he_bus_msg_table_insert_event:

            break;
        case he_bus_msg_table_remove_event:

            break;
        case he_bus_msg_publish_event:

            break;
        case he_bus_msg_sub_event:
        case he_bus_msg_sub_ex_async_event:
            ret = process_bus_sub_event(handle, fd, p_msg_data->component_name, p_obj_data);

            prepare_rem_payload_bus_msg_data(p_obj_data->name, p_res_data, p_obj_data->msg_sub_type,
                &payload_data, ret);
            break;
        default:
            he_bus_core_error_print("%s:%d unsupported msg sub type:%d from:%s\r\n", __func__,
                __LINE__, p_obj_data->msg_sub_type, p_obj_data->name);
            ret = he_bus_error_invalid_input;

            prepare_rem_payload_bus_msg_data(p_obj_data->name, p_res_data, p_obj_data->msg_sub_type,
                &payload_data, ret);
            break;
        }
        l_num_of_obj--;
    }

    return ret;
}

he_bus_error_t process_bus_sub_ex_async_res_event(hash_map_t *p_sub_map, char *comp_name,
    he_bus_data_object_t *p_obj_data)
{
    if (p_sub_map == NULL) {
        he_bus_core_error_print("%s:%d own sub map is not found\r\n", __func__, __LINE__);
        return he_bus_error_success;
    } else if (comp_name == NULL || p_obj_data == NULL) {
        he_bus_core_error_print("%s:%d invalid input argument\r\n", __func__, __LINE__);
        return he_bus_error_invalid_input;
    }

    own_sub_element_t *p_sub_data = get_bus_user_cb(p_sub_map, p_obj_data->name);
    if (p_sub_data != NULL) {
        he_bus_core_info_print("%s:%d Async subscribe callback is found for [%s]\r\n", __func__,
            __LINE__, p_obj_data->name);
        if (p_sub_data->sub_cb_table.sub_ex_async_handler != NULL) {
            he_bus_core_dbg_print("%s:%d Async subscribe callback is triggered\r\n", __func__,
                __LINE__);
            p_sub_data->sub_cb_table.sub_ex_async_handler(p_obj_data->name,
                (he_bus_error_t)p_obj_data->data.raw_data.u32);
        }
        if (p_obj_data->data.data_type == he_bus_data_type_uint32 &&
            p_obj_data->data.raw_data.u32 != he_bus_error_success) {
            p_sub_data = hash_map_remove(p_sub_map, p_obj_data->name);
            if (p_sub_data != NULL) {
                he_bus_free(p_sub_data);
                p_sub_data = NULL;
            }
        }
    } else {
        he_bus_core_error_print("%s:%d subscribe callback not found for [%s]\r\n", __func__,
            __LINE__, p_obj_data->name);
    }

    return he_bus_error_success;
}

he_bus_error_t handle_bus_msg_res_data(he_bus_handle_t handle, he_bus_raw_data_msg_t *p_msg_data)
{
    VERIFY_NULL_WITH_RC(handle);
    VERIFY_NULL_WITH_RC(p_msg_data);

    he_bus_error_t ret = he_bus_error_success;
    he_bus_data_object_t *p_obj_data = &p_msg_data->data_obj;
    uint32_t l_num_of_obj = (uint32_t)p_msg_data->num_of_obj;

    he_bus_core_info_print("%s:%d msg res type:%d from:%s l_num_of_obj:%d\r\n", __func__, __LINE__,
        p_obj_data->msg_sub_type, p_obj_data->name, l_num_of_obj);
    while (l_num_of_obj > 0) {
        switch (p_obj_data->msg_sub_type) {
        case he_bus_msg_sub_ex_async_event:
            process_bus_sub_ex_async_res_event(handle->sub_map, p_msg_data->component_name,
                p_obj_data);
            break;
        default:
            he_bus_core_error_print("%s:%d unsupported msg sub type:%d from:%s\r\n", __func__,
                __LINE__, p_obj_data->msg_sub_type, p_obj_data->name);
            ret = he_bus_error_invalid_input;
            break;
        }
        l_num_of_obj--;
    }

    return ret;
}

he_bus_error_t process_bus_publish_event(hash_map_t *p_sub_map, he_bus_data_object_t *p_obj_data)
{
    if (p_sub_map == NULL) {
        he_bus_core_error_print("%s:%d own sub map is not found\r\n", __func__, __LINE__);
        return he_bus_error_success;
    } else if (p_obj_data == NULL) {
        he_bus_core_error_print("%s:%d invalid input argument\r\n", __func__, __LINE__);
        return he_bus_error_invalid_input;
    }

    own_sub_element_t *p_sub_data = get_bus_user_cb(p_sub_map, p_obj_data->name);
    if (p_sub_data != NULL) {
        he_bus_core_info_print("%s:%d subscribe callback is found for [%s]\r\n", __func__, __LINE__,
            p_obj_data->name);
        if (p_sub_data->sub_cb_table.sub_handler != NULL) {
            he_bus_core_dbg_print("%s:%d subscribe callback is triggered\r\n", __func__, __LINE__);
            p_sub_data->sub_cb_table.sub_handler(p_obj_data->name, &p_obj_data->data);
        }
    } else {
        he_bus_core_error_print("%s:%d subscribe callback not found for [%s]\r\n", __func__,
            __LINE__, p_obj_data->name);
    }

    return he_bus_error_success;
}

he_bus_error_t handle_bus_msg_notify_data(he_bus_handle_t handle, he_bus_raw_data_msg_t *p_msg_data)
{
    VERIFY_NULL_WITH_RC(handle);
    VERIFY_NULL_WITH_RC(p_msg_data);

    he_bus_error_t ret = he_bus_error_success;
    he_bus_data_object_t *p_obj_data = &p_msg_data->data_obj;
    uint32_t l_num_of_obj = (uint32_t)p_msg_data->num_of_obj;

    while (l_num_of_obj > 0) {
        switch (p_obj_data->msg_sub_type) {
        case he_bus_msg_publish_event:
            he_bus_core_error_print("%s:%d own comp name:%s msg for:%s\r\n", __func__, __LINE__,
                handle->component_name, p_msg_data->component_name);
            ret = process_bus_publish_event(handle->sub_map, p_obj_data);
            break;
        default:
            he_bus_core_error_print("%s:%d unsupported msg sub type:%d from:%s\r\n", __func__,
                __LINE__, p_obj_data->msg_sub_type, p_obj_data->name);
            ret = he_bus_error_invalid_input;
            break;
        }
        l_num_of_obj--;
    }

    return ret;
}

he_bus_error_t handle_bus_msg_data(he_bus_handle_t handle, int fd,
    he_bus_raw_data_msg_t *p_msg_data, he_bus_raw_data_msg_t *p_res_data)
{
    VERIFY_NULL_WITH_RC(handle);
    VERIFY_NULL_WITH_RC(p_msg_data);

    he_bus_error_t ret = he_bus_error_success;
    he_bus_core_info_print("%s:%d p_msg_data->msg_type:%d\r\n", __func__, __LINE__,
        p_msg_data->msg_type);

    switch (p_msg_data->msg_type) {
    case he_bus_inital_msg:

        break;
    case he_bus_msg_get:
        ret = handle_bus_msg_req_data(handle, fd, p_msg_data, p_res_data);
        break;
    case he_bus_msg_set:
        ret = handle_bus_msg_req_data(handle, fd, p_msg_data, p_res_data);
        break;
    case he_bus_msg_notify:
        ret = handle_bus_msg_notify_data(handle, p_msg_data);
        break;
    case he_bus_msg_request:
        ret = handle_bus_msg_req_data(handle, fd, p_msg_data, p_res_data);
        break;
    case he_bus_msg_response:
        ret = handle_bus_msg_res_data(handle, p_msg_data);
        break;
    default:
        he_bus_core_error_print("%s:%d unsupported msg type:%d from:%s\r\n", __func__, __LINE__,
            p_msg_data->msg_type, p_msg_data->component_name);
        ret = he_bus_error_invalid_input;
        break;
    }

    return ret;
}

he_bus_error_t decode_and_handle_data(he_bus_handle_t handle, int fd,
    he_bus_stretch_buff_t *raw_buff, he_bus_raw_data_msg_t *p_res_data)
{
    VERIFY_NULL_WITH_RC(handle);
    VERIFY_NULL_WITH_RC(raw_buff);

    he_bus_error_t ret = he_bus_error_success;
    he_bus_raw_data_msg_t recv_data = { 0 };

    convert_buffer_to_bus_raw_msg_data(&recv_data, raw_buff);
    ret = handle_bus_msg_data(handle, fd, &recv_data, p_res_data);

    free_bus_msg_obj_data(&recv_data.data_obj);
    return ret;
}

he_bus_error_t validate_sub_response(he_bus_event_sub_t *sub_data_map,
    he_bus_raw_data_msg_t *recv_data)
{
    VERIFY_NULL_WITH_RC(sub_data_map);
    VERIFY_NULL_WITH_RC(recv_data);

    uint32_t index = 0;
    he_bus_data_object_t *p_data = &recv_data->data_obj;

    while (index < recv_data->num_of_obj) {
        if (!strncmp(sub_data_map->event_name, p_data->name, (strlen(p_data->name) + 1))) {
            return p_data->status;
        }
        p_data = p_data->next_data;
        index++;
    }
    return he_bus_error_destination_response_failure;
}

he_bus_error_t prepare_initial_bus_header(he_bus_raw_data_msg_t *p_data, char *comp_name,
    he_bus_msg_type_t msg_type)
{
    if (p_data == NULL || comp_name == NULL) {
        he_bus_core_error_print("%s:%d input argument is NULL for msg type:%d\r\n", __func__,
            __LINE__, msg_type);
        return he_bus_error_invalid_input;
    }

    p_data->bus_msg_identity = HE_BUS_MSG_IDENTIFICATION_NUM;
    p_data->total_raw_msg_len = sizeof(p_data->bus_msg_identity);
    p_data->total_raw_msg_len += sizeof(p_data->total_raw_msg_len);

    p_data->component_name_len = strlen(comp_name) + 1;
    strncpy(p_data->component_name, comp_name, p_data->component_name_len);
    p_data->total_raw_msg_len += p_data->component_name_len;
    p_data->total_raw_msg_len += sizeof(p_data->component_name_len);

    p_data->msg_type = msg_type;
    p_data->total_raw_msg_len += sizeof(p_data->msg_type);
    p_data->total_raw_msg_len += sizeof(p_data->num_of_obj);

    p_data->num_of_obj = 0;
    p_data->data_obj.is_data_set = false;
    p_data->data_obj.next_data = NULL;

    return he_bus_error_success;
}

he_bus_error_t prepare_rem_payload_bus_msg_data(char *event_name,
    he_bus_raw_data_msg_t *p_base_hdr_data, he_bus_msg_sub_type_t msg_sub_type,
    he_bus_raw_data_t *payload_data, he_bus_error_t ret_status)
{
    if (event_name == NULL || p_base_hdr_data == NULL) {
        he_bus_core_error_print("%s:%d input argument is NULL for msg sub type:%d\r\n", __func__,
            __LINE__, msg_sub_type);
        return he_bus_error_invalid_input;
    }

    he_bus_data_object_t *p_obj_data = &p_base_hdr_data->data_obj;
    uint32_t payload_len = 0;

    payload_len = set_bus_object_data(event_name, p_obj_data, msg_sub_type, payload_data, ret_status);
    p_base_hdr_data->num_of_obj++;
    p_base_hdr_data->total_raw_msg_len += payload_len;
    return he_bus_error_success;
}

int send_bus_initial_msg_info(int fd, char *comp_name)
{
    VERIFY_NULL_WITH_RC(comp_name);

    he_bus_raw_data_msg_t initial_msg = { 0 };
    he_bus_stretch_buff_t raw_buff = { 0 };

    he_bus_error_t status = prepare_initial_bus_header(&initial_msg, comp_name, he_bus_inital_msg);
    if (status != he_bus_error_success) {
        he_bus_core_error_print("%s:%d initial bus header preapre is failed:%d\r\n", __func__,
            __LINE__, status);
        return HE_BUS_RETURN_ERR;
    }

    if (convert_bus_raw_msg_data_to_buffer(&initial_msg, &raw_buff) != he_bus_error_success) {
        he_bus_core_error_print("%s:%d wrong data for :%s component\r\n", __func__, __LINE__,
            comp_name);
        FREE_BUFF_MEMORY(raw_buff.buff);
        return HE_BUS_RETURN_ERR;
    }

    send_data_to_endpoint(fd, raw_buff.buff, raw_buff.buff_len);
    FREE_BUFF_MEMORY(raw_buff.buff);
    return HE_BUS_RETURN_OK;
}
