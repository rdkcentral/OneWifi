
#include "wifi_supp.h"
#include "wifi_supp_dbus.h"

const char * rdkb_dbus_type_as_string(const int type)
{
        switch (type) {
        case DBUS_TYPE_BYTE:
                return DBUS_TYPE_BYTE_AS_STRING;
        case DBUS_TYPE_BOOLEAN:
                return DBUS_TYPE_BOOLEAN_AS_STRING;
        case DBUS_TYPE_INT16:
                return DBUS_TYPE_INT16_AS_STRING;
        case DBUS_TYPE_UINT16:
                return DBUS_TYPE_UINT16_AS_STRING;
        case DBUS_TYPE_INT32:
                return DBUS_TYPE_INT32_AS_STRING;
        case DBUS_TYPE_UINT32:
                return DBUS_TYPE_UINT32_AS_STRING;
        case DBUS_TYPE_INT64:
                return DBUS_TYPE_INT64_AS_STRING;
        case DBUS_TYPE_UINT64:
                return DBUS_TYPE_UINT64_AS_STRING;
        case DBUS_TYPE_DOUBLE:
                return DBUS_TYPE_DOUBLE_AS_STRING;
        case DBUS_TYPE_STRING:
                return DBUS_TYPE_STRING_AS_STRING;
        case DBUS_TYPE_OBJECT_PATH:
                return DBUS_TYPE_OBJECT_PATH_AS_STRING;
        case DBUS_TYPE_ARRAY:
                return DBUS_TYPE_ARRAY_AS_STRING;
        default:
                return NULL;
        }
}

int rdkb_dbus_reg_obj_per_iface(char *path, char *ifname,
                                       rdkb_dbus_wifi_obj_desc_t *obj_desc)
{         
        DBusConnection *con;
        DBusError error;
        DBusObjectPathVTable vtable = {
                NULL, &rdkb_dbus_message_handler,
                NULL, NULL, NULL, NULL
        };
        
        con = obj_desc->connection;
        dbus_error_init(&error);
        printf("%s():%d Register path:%s, ifnmae:%s\n", __func__, __LINE__, path, ifname);
        if (!dbus_connection_try_register_object_path(con, path, &vtable,
                                                      obj_desc, &error)) {
                if (strcmp(error.name, DBUS_ERROR_OBJECT_PATH_IN_USE) == 0) {
                        printf("dbus: %s", error.message);
                } else {
                        printf("dbus: Could not set up message handler for interface %s object %s (error: %s message: %s)",
                                   ifname, path, error.name, error.message);
                }    
                dbus_error_free(&error);
                return -1;
        } 
        
        dbus_error_free(&error);
        return 0;
}

DBusMessage * rdkb_dbus_error_invalid_args(DBusMessage *message,
                                          const char *arg)
{
        DBusMessage *reply;

        reply = dbus_message_new_error(
                message, RDKB_DBUS_ERROR_INVALID_ARGS,
                "Did not receive correct message arguments.");
        if (arg != NULL)
                dbus_message_append_args(reply, DBUS_TYPE_STRING, &arg,
                                         DBUS_TYPE_INVALID);

        return reply;
}

int dbus_get_scan_type(DBusMessage *message, DBusMessageIter *var,
                                   char **type, DBusMessage **reply)
{
        if (dbus_message_iter_get_arg_type(var) != DBUS_TYPE_STRING) {
                printf("%s[dbus]: Type must be a string",
                           __func__);
                *reply = rdkb_dbus_error_invalid_args(
                        message, "Wrong Type value type. String required");
                return -1;
        }
        dbus_message_iter_get_basic(var, type);
        return 0;
}

static dbus_bool_t rdkb_dbus_dict_entry_get_byte_array(
        DBusMessageIter *iter, rdkb_dbus_dict_entry_t *entry)
{
        dbus_uint32_t count = 0;
        dbus_bool_t success = FALSE;
        char *buffer, *nbuffer;

        entry->bytearray_value = NULL;
        entry->array_type = DBUS_TYPE_BYTE;

        buffer = os_calloc(BYTE_ARRAY_CHUNK_SIZE, BYTE_ARRAY_ITEM_SIZE);
        if (!buffer) {
                return FALSE;
	}

        entry->array_len = 0;
        while (dbus_message_iter_get_arg_type(iter) == DBUS_TYPE_BYTE) {
                char byte;

                if ((count % BYTE_ARRAY_CHUNK_SIZE) == 0 && count != 0) {
                        nbuffer = os_realloc_array(
                                buffer, count + BYTE_ARRAY_CHUNK_SIZE,
                                BYTE_ARRAY_ITEM_SIZE);
                        if (nbuffer == NULL) {
                                os_free(buffer);
                                wifi_util_error_print(WIFI_SUPP,
                                           "dbus: %s out of memory trying to retrieve the string array",
                                           __func__);
                                goto done;
                        }
                        buffer = nbuffer;
                }

                dbus_message_iter_get_basic(iter, &byte);
                buffer[count] = byte;
                entry->array_len = ++count;
                dbus_message_iter_next(iter);
        }
        entry->bytearray_value = buffer;
        wpa_hexdump_key(MSG_MSGDUMP, "dbus: byte array contents",
                        entry->bytearray_value, entry->array_len);
                        
        /* Zero-length arrays are valid. */
        if (entry->array_len == 0) {
                os_free(entry->bytearray_value);
                entry->bytearray_value = NULL;
        }       
        
        success = TRUE;
        
done:
        return success;
}

static dbus_bool_t rdkb_dbus_dict_entry_get_str_array(
        DBusMessageIter *iter, int array_type,
        rdkb_dbus_dict_entry_t *entry)
{
        dbus_uint32_t count = 0;
        char **buffer, **nbuffer;

        entry->strarray_value = NULL;
        entry->array_len = 0;
        entry->array_type = DBUS_TYPE_STRING;

        buffer = os_calloc(STR_ARRAY_CHUNK_SIZE, STR_ARRAY_ITEM_SIZE);
        if (buffer == NULL)
                return FALSE;

        while (dbus_message_iter_get_arg_type(iter) == DBUS_TYPE_STRING) {
                const char *value;
                char *str;

                if ((count % STR_ARRAY_CHUNK_SIZE) == 0 && count != 0) {
                        nbuffer = os_realloc_array(
                                buffer, count + STR_ARRAY_CHUNK_SIZE,
                                STR_ARRAY_ITEM_SIZE);
                        if (nbuffer == NULL) {
                                wifi_util_error_print(WIFI_SUPP,
                                           "dbus: %s out of memory trying to retrieve the string array",
                                           __func__);
                                goto fail;
                        }
                        buffer = nbuffer;
                }

                dbus_message_iter_get_basic(iter, &value);
                wifi_util_error_print(WIFI_SUPP, "%s: string_array value: %s",
                           __func__, wpa_debug_show_keys ? value : "[omitted]");
                str = os_strdup(value);
                if (str == NULL) {
                        wifi_util_error_print(WIFI_SUPP,
                                   "dbus: %s out of memory trying to duplicate the string array",
                                   __func__);
                        goto fail;
                }
                buffer[count++] = str;
                dbus_message_iter_next(iter);
        }
        entry->strarray_value = buffer;
        entry->array_len = count;
        wifi_util_error_print(WIFI_SUPP, "%s: string_array length %u",
                   __func__, entry->array_len);

        if (entry->array_len == 0) {
                os_free(entry->strarray_value);
                entry->strarray_value = NULL;
        }

        return TRUE;

fail:
        while (count > 0) {
                count--;
                os_free(buffer[count]);
        }
        os_free(buffer);
        return FALSE;
}

void rdkb_dbus_dict_entry_clear(rdkb_dbus_dict_entry_t *entry)
{
        unsigned int i;

        if (!entry)
                return;
        switch (entry->type) {
        case DBUS_TYPE_OBJECT_PATH:
        case DBUS_TYPE_STRING:
                os_free(entry->str_value);
                break;
        case DBUS_TYPE_ARRAY:
                switch (entry->array_type) {
                case DBUS_TYPE_BYTE:
                        os_free(entry->bytearray_value);
                        break;
                case DBUS_TYPE_STRING:
                        if (!entry->strarray_value)
                                break;
                        for (i = 0; i < entry->array_len; i++)
                                os_free(entry->strarray_value[i]);
                        os_free(entry->strarray_value);
                        break;
                case RDKB_DBUS_TYPE_BIN_ARRAY:
                        for (i = 0; i < entry->array_len; i++)
                                wpabuf_free(entry->binarray_value[i]);
                        os_free(entry->binarray_value);
                        break;
                }
                break;
        }

        os_memset(entry, 0, sizeof(rdkb_dbus_dict_entry_t));
}

static dbus_bool_t rdkb_dbus_dict_entry_get_bin_array(
        DBusMessageIter *iter, rdkb_dbus_dict_entry_t *entry)
{
        rdkb_dbus_dict_entry_t tmpentry;
        size_t buflen = 0;
        int i, type;

        entry->array_type = RDKB_DBUS_TYPE_BIN_ARRAY;
        entry->array_len = 0;
        entry->binarray_value = NULL;

        type = dbus_message_iter_get_arg_type(iter);
        wifi_util_error_print(WIFI_SUPP, "%s: parsing binarray type %c", __func__, type);
        if (type == DBUS_TYPE_INVALID) {
                return TRUE;
        }
        if (type != DBUS_TYPE_ARRAY) {
                wifi_util_error_print(WIFI_SUPP, "%s: not an array type: %c",
                           __func__, type);
                return FALSE;
        }

        type = dbus_message_iter_get_element_type(iter);
        if (type != DBUS_TYPE_BYTE) {
                wifi_util_error_print(WIFI_SUPP, "%s: unexpected element type %c",
                           __func__, type);
                return FALSE;
        }

        while (dbus_message_iter_get_arg_type(iter) == DBUS_TYPE_ARRAY) {
                DBusMessageIter iter_array;

                if (entry->array_len == buflen) {
                        struct wpabuf **newbuf;

                        buflen += BIN_ARRAY_CHUNK_SIZE;

                        newbuf = os_realloc_array(entry->binarray_value,
                                                  buflen, BIN_ARRAY_ITEM_SIZE);
                        if (!newbuf)
                                goto cleanup;
                        entry->binarray_value = newbuf;
                }
                dbus_message_iter_recurse(iter, &iter_array);
                os_memset(&tmpentry, 0, sizeof(tmpentry));
                tmpentry.type = DBUS_TYPE_ARRAY;
                if (rdkb_dbus_dict_entry_get_byte_array(&iter_array, &tmpentry)
                    == FALSE)
                        goto cleanup;

                entry->binarray_value[entry->array_len] =
                        wpabuf_alloc_ext_data((uint8_t *) tmpentry.bytearray_value,
                                              tmpentry.array_len);
                if (entry->binarray_value[entry->array_len] == NULL) {
                        rdkb_dbus_dict_entry_clear(&tmpentry);
                        goto cleanup;
                }
                entry->array_len++;
                dbus_message_iter_next(iter);
        }
        wifi_util_error_print(WIFI_SUPP, "%s: binarray length %u",
                   __func__, entry->array_len);

        return TRUE;

 cleanup:
        for (i = 0; i < (int) entry->array_len; i++)
                wpabuf_free(entry->binarray_value[i]);
        os_free(entry->binarray_value);
        entry->array_len = 0;
        entry->binarray_value = NULL;
        return FALSE;
}

static dbus_bool_t rdkb_dbus_dict_entry_get_array(
        DBusMessageIter *iter_dict_val, rdkb_dbus_dict_entry_t *entry)
{
        int array_type = dbus_message_iter_get_element_type(iter_dict_val);
        dbus_bool_t success = FALSE;
        DBusMessageIter iter_array;

        wifi_util_error_print(WIFI_SUPP, "%s: array_type %c", __func__, array_type);

        dbus_message_iter_recurse(iter_dict_val, &iter_array);

        switch (array_type) {
        case DBUS_TYPE_BYTE:
                success = rdkb_dbus_dict_entry_get_byte_array(&iter_array,
                                                              entry);
                break;
        case DBUS_TYPE_STRING:
                success = rdkb_dbus_dict_entry_get_str_array(&iter_array,
                                                                array_type,
                                                                entry);
                break;
        case DBUS_TYPE_ARRAY:
                success = rdkb_dbus_dict_entry_get_bin_array(&iter_array, entry);
                break;
        default:
                wifi_util_error_print(WIFI_SUPP, "%s: unsupported array type %c",
                           __func__, array_type);
                break;
        }

        return success;
}

static dbus_bool_t rdkb_dbus_dict_fill_value_from_variant(
        rdkb_dbus_dict_entry_t *entry, DBusMessageIter *iter)
{
        const char *v;

        switch (entry->type) {
        case DBUS_TYPE_OBJECT_PATH:
                dbus_message_iter_get_basic(iter, &v);
                wifi_util_error_print(WIFI_SUPP, "%s: object path value: %s",
                           __func__, v);
                entry->str_value = os_strdup(v);
                if (entry->str_value == NULL)
                        return FALSE;
                break;
        case DBUS_TYPE_STRING:
                dbus_message_iter_get_basic(iter, &v);
                wifi_util_error_print(WIFI_SUPP, "%s: string value: %s",
                           __func__, wpa_debug_show_keys ? v : "[omitted]");
                entry->str_value = os_strdup(v);
                if (entry->str_value == NULL)
                        return FALSE;
                break;
        case DBUS_TYPE_BOOLEAN:
                dbus_message_iter_get_basic(iter, &entry->bool_value);
                wifi_util_error_print(WIFI_SUPP, "%s: boolean value: %d",
                           __func__, entry->bool_value);
                break;
        case DBUS_TYPE_BYTE:
                dbus_message_iter_get_basic(iter, &entry->byte_value);
                wifi_util_error_print(WIFI_SUPP, "%s: byte value: %d",
                           __func__, entry->byte_value);
                break;
        case DBUS_TYPE_INT16:
                dbus_message_iter_get_basic(iter, &entry->int16_value);
                wifi_util_error_print(WIFI_SUPP, "%s: int16 value: %d",
                           __func__, entry->int16_value);
                break;
        case DBUS_TYPE_UINT16:
                dbus_message_iter_get_basic(iter, &entry->uint16_value);
                wifi_util_error_print(WIFI_SUPP, "%s: uint16 value: %d",
                           __func__, entry->uint16_value);
                break;
        case DBUS_TYPE_INT32:
                dbus_message_iter_get_basic(iter, &entry->int32_value);
                wifi_util_error_print(WIFI_SUPP, "%s: int32 value: %d",
                           __func__, entry->int32_value);
                break;
        case DBUS_TYPE_UINT32:
                dbus_message_iter_get_basic(iter, &entry->uint32_value);
                wifi_util_error_print(WIFI_SUPP, "%s: uint32 value: %d",
                           __func__, entry->uint32_value);
                break;
        case DBUS_TYPE_INT64:
                dbus_message_iter_get_basic(iter, &entry->int64_value);
                wifi_util_error_print(WIFI_SUPP, "%s: int64 value: %lld",
                           __func__, (long long int) entry->int64_value);
                break;
        case DBUS_TYPE_UINT64:
                dbus_message_iter_get_basic(iter, &entry->uint64_value);
                wifi_util_error_print(WIFI_SUPP, "%s: uint64 value: %llu",
                           __func__,
                           (unsigned long long int) entry->uint64_value);
                break;
        case DBUS_TYPE_DOUBLE:
                dbus_message_iter_get_basic(iter, &entry->double_value);
                wifi_util_error_print(WIFI_SUPP, "%s: double value: %f",
                           __func__, entry->double_value);
                break;
        case DBUS_TYPE_ARRAY:
                return rdkb_dbus_dict_entry_get_array(iter, entry);
        default:
                wifi_util_error_print(WIFI_SUPP, "%s: unsupported type %c",
                           __func__, entry->type);
                return FALSE;
        }

        return TRUE;
}

dbus_bool_t rdkb_dbus_dict_get_entry(DBusMessageIter *iter_dict,
                                    rdkb_dbus_dict_entry_t * entry)
{
        DBusMessageIter iter_dict_entry, iter_dict_val;
        int type;
        const char *key;

        if (!iter_dict || !entry ||
            dbus_message_iter_get_arg_type(iter_dict) != DBUS_TYPE_DICT_ENTRY) {
                printf( "%s: not a dict entry", __func__);
                goto error;
        }

        dbus_message_iter_recurse(iter_dict, &iter_dict_entry);
        dbus_message_iter_get_basic(&iter_dict_entry, &key);
        printf( "%s: dict entry key: %s", __func__, key);
        entry->key = key;

        if (!dbus_message_iter_next(&iter_dict_entry)) {
                printf( "%s: no variant in dict entry", __func__);
                goto error;
        }
        type = dbus_message_iter_get_arg_type(&iter_dict_entry);
        if (type != DBUS_TYPE_VARIANT) {
                printf(
                           "%s: unexpected dict entry variant type: %c",
                           __func__, type);
                goto error;
        }

        dbus_message_iter_recurse(&iter_dict_entry, &iter_dict_val);
        entry->type = dbus_message_iter_get_arg_type(&iter_dict_val);
        printf( "%s: dict entry variant content type: %c",
                   __func__, entry->type);
        entry->array_type = DBUS_TYPE_INVALID;
        if (!rdkb_dbus_dict_fill_value_from_variant(entry, &iter_dict_val)) {
                printf(
                           "%s: failed to fetch dict values from variant",
                           __func__);
                goto error;
        }

        dbus_message_iter_next(iter_dict);
        return TRUE;

error:
        if (entry) {
                rdkb_dbus_dict_entry_clear(entry);
                entry->type = DBUS_TYPE_INVALID;
                entry->array_type = DBUS_TYPE_INVALID;
        }

        return FALSE;
}

dbus_bool_t rdkb_dbus_dict_open_read(DBusMessageIter *iter,
                                    DBusMessageIter *iter_dict,
                                    DBusError *error)
{
        int type;

        wifi_util_error_print(WIFI_SUPP, "%s: start reading a dict entry", __func__);
        if (!iter || !iter_dict) {
                dbus_set_error_const(error, DBUS_ERROR_FAILED,
                                     "[internal] missing message iterators");
                return FALSE;
        }

        type = dbus_message_iter_get_arg_type(iter);
        if (type != DBUS_TYPE_ARRAY ||
            dbus_message_iter_get_element_type(iter) != DBUS_TYPE_DICT_ENTRY) {
                wifi_util_error_print(WIFI_SUPP,
                           "%s: unexpected message argument types (arg=%c element=%c)",
                           __func__, type,
                           type != DBUS_TYPE_ARRAY ? '?' :
                           dbus_message_iter_get_element_type(iter));
                dbus_set_error_const(error, DBUS_ERROR_INVALID_ARGS,
                                     "unexpected message argument types");
                return FALSE;
        }

        dbus_message_iter_recurse(iter, iter_dict);
        return TRUE;
}

dbus_bool_t rdkb_dbus_dict_has_dict_entry(DBusMessageIter *iter_dict)
{
        if (!iter_dict)
                return FALSE;
        return dbus_message_iter_get_arg_type(iter_dict) ==
                DBUS_TYPE_DICT_ENTRY;
}

DBusMessage * rdkb_dbus_error_scan_error(DBusMessage *message,
                                                const char *error)
{
        return dbus_message_new_error(message,
                                      RDKB_DBUS_IFACE_SCAN_ERROR,
                                      error);
}

static dbus_bool_t rdkb_dbus_add_dict_entry_end(
        DBusMessageIter *iter_dict, DBusMessageIter *iter_dict_entry,
        DBusMessageIter *iter_dict_val)
{
        if (!dbus_message_iter_close_container(iter_dict_entry, iter_dict_val))
                return FALSE;

        return dbus_message_iter_close_container(iter_dict, iter_dict_entry);
}

dbus_bool_t rdkb_dbus_dict_end_array(DBusMessageIter *iter_dict,
                                    DBusMessageIter *iter_dict_entry,
                                    DBusMessageIter *iter_dict_val,
                                    DBusMessageIter *iter_array)
{
        if (!iter_dict || !iter_dict_entry || !iter_dict_val || !iter_array ||
            !dbus_message_iter_close_container(iter_dict_val, iter_array))
                return FALSE;

        return rdkb_dbus_add_dict_entry_end(iter_dict, iter_dict_entry,
                                            iter_dict_val);
}

dbus_bool_t rdkb_dbus_dict_end_str_array(DBusMessageIter *iter_dict,
                               DBusMessageIter *iter_dict_entry,
                               DBusMessageIter *iter_dict_val,
                               DBusMessageIter *iter_array)
{
        return rdkb_dbus_dict_end_array(iter_dict, iter_dict_entry,
                                       iter_dict_val, iter_array);
}

dbus_bool_t rdkb_dbus_dict_str_array_add_elem(DBusMessageIter *iter_array,
                                                   const char *elem)
{
        if (!iter_array || !elem)
                return FALSE;

        return dbus_message_iter_append_basic(iter_array, DBUS_TYPE_STRING,
                                              &elem);
}

static dbus_bool_t rdkb_dbus_add_dict_entry_start(
        DBusMessageIter *iter_dict, DBusMessageIter *iter_dict_entry,
        const char *key, const int value_type)
{
        if (!dbus_message_iter_open_container(iter_dict,
                                              DBUS_TYPE_DICT_ENTRY, NULL,
                                              iter_dict_entry))
                return FALSE;

        return dbus_message_iter_append_basic(iter_dict_entry, DBUS_TYPE_STRING,
                                              &key);
}

dbus_bool_t rdkb_dbus_dict_begin_array(DBusMessageIter *iter_dict,
                                      const char *key, const char *type,
                                      DBusMessageIter *iter_dict_entry,
                                      DBusMessageIter *iter_dict_val,
                                      DBusMessageIter *iter_array)
{
        char array_type[10];
        int err;

        err = snprintf(array_type, sizeof(array_type),
                          DBUS_TYPE_ARRAY_AS_STRING "%s",
                          type);
        if (snprintf_error(sizeof(array_type), err))
                return FALSE;

        if (!iter_dict || !iter_dict_entry || !iter_dict_val || !iter_array ||
            !rdkb_dbus_add_dict_entry_start(iter_dict, iter_dict_entry,
                                            key, DBUS_TYPE_ARRAY) ||
            !dbus_message_iter_open_container(iter_dict_entry,
                                              DBUS_TYPE_VARIANT,
                                              array_type,
                                              iter_dict_val))
                return FALSE;

        return dbus_message_iter_open_container(iter_dict_val, DBUS_TYPE_ARRAY,
                                                type, iter_array);
}

dbus_bool_t rdkb_dbus_dict_begin_str_array(DBusMessageIter *iter_dict,
                                             const char *key,
                                             DBusMessageIter *iter_dict_entry,
                                             DBusMessageIter *iter_dict_val,
                                             DBusMessageIter *iter_array)
{
        return rdkb_dbus_dict_begin_array(
                iter_dict, key,
                DBUS_TYPE_STRING_AS_STRING,
                iter_dict_entry, iter_dict_val, iter_array);
}

dbus_bool_t rdkb_dbus_dict_append_str_array(DBusMessageIter *iter_dict,
                                              const char *key,
                                              const char **items,
                                              const dbus_uint32_t num_items)
{                                             
        DBusMessageIter iter_dict_entry, iter_dict_val, iter_array;
        dbus_uint32_t i;
                    
        if (!key || (!items && num_items != 0) ||
            !rdkb_dbus_dict_begin_str_array(iter_dict, key,
                                              &iter_dict_entry, &iter_dict_val,
                                              &iter_array)) 
                return FALSE;
                     
        for (i = 0; i < num_items; i++) {
                if (!rdkb_dbus_dict_str_array_add_elem(&iter_array,
                                                            items[i]))
                        return FALSE;
        }
            
        return rdkb_dbus_dict_end_str_array(iter_dict, &iter_dict_entry,
                                              &iter_dict_val, &iter_array);
}


static dbus_bool_t rdkb_dbus_add_dict_entry_basic(DBusMessageIter *iter_dict,
                                                  const char *key,
                                                  const int value_type,
                                                  const void *value)
{
        DBusMessageIter iter_dict_entry, iter_dict_val;
        const char *type_as_string = NULL;

        if (key == NULL)
                return FALSE;

        type_as_string = rdkb_dbus_type_as_string(value_type);
        if (!type_as_string)
                return FALSE;

        if (!rdkb_dbus_add_dict_entry_start(iter_dict, &iter_dict_entry,
                                            key, value_type) ||
            !dbus_message_iter_open_container(&iter_dict_entry,
                                              DBUS_TYPE_VARIANT,
                                              type_as_string, &iter_dict_val) ||
            !dbus_message_iter_append_basic(&iter_dict_val, value_type, value))
                return FALSE;

        return rdkb_dbus_add_dict_entry_end(iter_dict, &iter_dict_entry,
                                            &iter_dict_val);
}

dbus_bool_t rdkb_dbus_dict_append_int32(DBusMessageIter *iter_dict,
                                       const char *key,
                                       const dbus_int32_t value)
{
        return rdkb_dbus_add_dict_entry_basic(iter_dict, key, DBUS_TYPE_INT32,
                                              &value);
}

dbus_bool_t rdkb_dbus_simple_prop_getter(DBusMessageIter *iter,
                                             const int type,
                                             const void *val,
                                             DBusError *error)
{
        DBusMessageIter variant_iter;

        if (!dbus_type_is_basic(type)) {
                dbus_set_error(error, DBUS_ERROR_FAILED,
                               "%s: given type is not basic", __func__);
                return FALSE;
        }

        printf("Before crash\n");
        if (!dbus_message_iter_open_container(iter, DBUS_TYPE_VARIANT,
                                              rdkb_dbus_type_as_string(type),
                                              &variant_iter) ||
            !dbus_message_iter_append_basic(&variant_iter, type, val) ||
            !dbus_message_iter_close_container(iter, &variant_iter)) {
                dbus_set_error(error, DBUS_ERROR_FAILED,
                               "%s: error constructing reply", __func__);
                return FALSE;
        }
        printf("AFTER Before crash\n");

        return TRUE;
}

dbus_bool_t rdkb_dbus_simple_prop_setter(DBusMessageIter *iter,
                                             DBusError *error,
                                             const int type, void *val)
{
        DBusMessageIter variant_iter;

        printf("1. In rdkb_dbus_simple_prop_setter\n");
        if (!dbus_type_is_basic(type)) {
                dbus_set_error(error, DBUS_ERROR_FAILED,
                               "%s: given type is not basic", __func__);
                return FALSE;
        }

        /* Look at the new value */
        dbus_message_iter_recurse(iter, &variant_iter);
        if (dbus_message_iter_get_arg_type(&variant_iter) != type) {
                dbus_set_error_const(error, DBUS_ERROR_FAILED,
                                     "wrong property type");
                return FALSE;
        }
        dbus_message_iter_get_basic(&variant_iter, val);
        printf("2. In rdkb_dbus_simple_prop_setter\n");


        return TRUE;
}

dbus_bool_t rdkb_dbus_dict_open_write(DBusMessageIter *iter,
                                     DBusMessageIter *iter_dict)
{
        dbus_bool_t result;

        if (!iter || !iter_dict)
                return FALSE;

        result = dbus_message_iter_open_container(
                iter,
                DBUS_TYPE_ARRAY,
                DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
                DBUS_TYPE_STRING_AS_STRING
                DBUS_TYPE_VARIANT_AS_STRING
                DBUS_DICT_ENTRY_END_CHAR_AS_STRING,
                iter_dict);
        return result;
}

dbus_bool_t rdkb_dbus_dict_close_write(DBusMessageIter *iter,
                                      DBusMessageIter *iter_dict)
{
        if (!iter || !iter_dict)
                return FALSE;

        return dbus_message_iter_close_container(iter, iter_dict);
}

DBusMessage * rdkb_dbus_reply_new_from_error(DBusMessage *message,
                                             DBusError *error,
                                             const char *fallback_name,
                                             const char *fallback_string)
{
        if (error && error->name && error->message) {
                return dbus_message_new_error(message, error->name,
                                              error->message);
        }
        if (fallback_name && fallback_string) {
                return dbus_message_new_error(message, fallback_name,
                                              fallback_string);
        }
        return NULL;
}

dbus_bool_t rdkb_dbus_simple_array_prop_getter(DBusMessageIter *iter,
                                                   const int type,
                                                   const void *array,
                                                   size_t array_len,
                                                   DBusError *error)
{
        DBusMessageIter variant_iter, array_iter;
        char type_str[] = "a?";
        const char *sub_type_str;
        size_t element_size, i;

        if (!dbus_type_is_basic(type)) {
                dbus_set_error(error, DBUS_ERROR_FAILED,
                               "%s: given type is not basic", __func__);
                return FALSE;
        }

        sub_type_str = rdkb_dbus_type_as_string(type);
        type_str[1] = sub_type_str[0];

        if (!dbus_message_iter_open_container(iter, DBUS_TYPE_VARIANT,
                                              type_str, &variant_iter) ||
            !dbus_message_iter_open_container(&variant_iter, DBUS_TYPE_ARRAY,
                                              sub_type_str, &array_iter)) {
                dbus_set_error(error, DBUS_ERROR_FAILED,
                               "%s: failed to construct message", __func__);
                return FALSE;
        }

        switch (type) {
        case DBUS_TYPE_BYTE:
        case DBUS_TYPE_BOOLEAN:
                element_size = 1;
                break;
        case DBUS_TYPE_INT16:
        case DBUS_TYPE_UINT16:
                element_size = sizeof(uint16_t);
                break;
       case DBUS_TYPE_INT32:
        case DBUS_TYPE_UINT32:
                element_size = sizeof(uint32_t);
                break;
        case DBUS_TYPE_INT64:
        case DBUS_TYPE_UINT64:
                element_size = sizeof(uint64_t);
                break;
        case DBUS_TYPE_DOUBLE:
                element_size = sizeof(double);
                break;
        case DBUS_TYPE_STRING:
        case DBUS_TYPE_OBJECT_PATH:
                element_size = sizeof(char *);
                break;
        default:
                dbus_set_error(error, DBUS_ERROR_FAILED,
                               "%s: unknown element type %d", __func__, type);
                return FALSE;
        }

        for (i = 0; i < array_len; i++) {
                if (!dbus_message_iter_append_basic(&array_iter, type,
                                                    (const char *) array +
                                                    i * element_size)) {
                        dbus_set_error(error, DBUS_ERROR_FAILED,
                                       "%s: failed to construct message 2.5",
                                       __func__);
                        return FALSE;
                }
        }

        if (!dbus_message_iter_close_container(&variant_iter, &array_iter) ||
            !dbus_message_iter_close_container(iter, &variant_iter)) {
                dbus_set_error(error, DBUS_ERROR_FAILED,
                               "%s: failed to construct message 3", __func__);
                return FALSE;
        }

        return TRUE;
}

dbus_bool_t rdkb_dbus_dict_append_str(DBusMessageIter *iter_dict,
                                        const char *key, const char *value)
{
        if (!value)
                return FALSE;
        return rdkb_dbus_add_dict_entry_basic(iter_dict, key, DBUS_TYPE_STRING,
                                              &value);
}

DBusMessage * rdkb_dbus_error_no_memory(DBusMessage *message)
{
        printf("dbus: Failed to allocate memory");
        return dbus_message_new_error(message, DBUS_ERROR_NO_MEMORY, NULL);
}


