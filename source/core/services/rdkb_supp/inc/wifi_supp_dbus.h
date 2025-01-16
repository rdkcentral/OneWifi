#ifndef WIFI_SUPP_H
#define WIFI_SUPP_H

#include <dbus/dbus.h>

const char * rdkb_dbus_type_as_string(const int type);

int rdkb_dbus_reg_obj_per_iface(char *path, char *ifname, rdkb_dbus_wifi_obj_desc_t *obj_desc);

DBusMessage * rdkb_dbus_error_invalid_args(DBusMessage *message, const char *arg);

static int dbus_get_scan_type(DBusMessage *message, DBusMessageIter *var, char **type, DBusMessage **reply);

static dbus_bool_t rdkb_dbus_dict_entry_get_byte_array(DBusMessageIter *iter, rdkb_dbus_dict_entry_t *entry);

static dbus_bool_t rdkb_dbus_dict_entry_get_str_array(DBusMessageIter *iter, int array_type, rdkb_dbus_dict_entry_t *entry);

static dbus_bool_t rdkb_dbus_dict_entry_get_str_array(DBusMessageIter *iter, int array_type, rdkb_dbus_dict_entry_t *entry);

void rdkb_dbus_dict_entry_clear(rdkb_dbus_dict_entry_t *entry);

static dbus_bool_t rdkb_dbus_dict_entry_get_bin_array(DBusMessageIter *iter, rdkb_dbus_dict_entry_t *entry);

static dbus_bool_t rdkb_dbus_dict_entry_get_array(DBusMessageIter *iter_dict_val, rdkb_dbus_dict_entry_t *entry);

static dbus_bool_t rdkb_dbus_dict_fill_value_from_variant(rdkb_dbus_dict_entry_t *entry, DBusMessageIter *iter);

dbus_bool_t rdkb_dbus_dict_get_entry(DBusMessageIter *iter_dict, rdkb_dbus_dict_entry_t * entry);

dbus_bool_t rdkb_dbus_dict_open_read(DBusMessageIter *iter, DBusMessageIter *iter_dict, DBusError *error);

dbus_bool_t rdkb_dbus_dict_has_dict_entry(DBusMessageIter *iter_dict);

static DBusMessage * rdkb_dbus_error_scan_error(DBusMessage *message, const char *error);

static dbus_bool_t rdkb_dbus_add_dict_entry_end(DBusMessageIter *iter_dict, DBusMessageIter *iter_dict_entry, DBusMessageIter *iter_dict_val);

dbus_bool_t rdkb_dbus_dict_end_array(DBusMessageIter *iter_dict, DBusMessageIter *iter_dict_entry, DBusMessageIter *iter_dict_val, DBusMessageIter *iter_array);

dbus_bool_t rdkb_dbus_dict_end_str_array(DBusMessageIter *iter_dict, DBusMessageIter *iter_dict_entry, DBusMessageIter *iter_dict_val, DBusMessageIter *iter_array);

dbus_bool_t rdkb_dbus_dict_str_array_add_elem(DBusMessageIter *iter_array, const char *elem);

static dbus_bool_t rdkb_dbus_add_dict_entry_start(DBusMessageIter *iter_dict, DBusMessageIter *iter_dict_entry, const char *key, const int value_type);

dbus_bool_t rdkb_dbus_dict_begin_array(DBusMessageIter *iter_dict, const char *key, const char *type, DBusMessageIter *iter_dict_entry, DBusMessageIter *iter_dict_val, DBusMessageIter *iter_array);

dbus_bool_t rdkb_dbus_dict_begin_str_array(DBusMessageIter *iter_dict, const char *key, DBusMessageIter *iter_dict_entry, DBusMessageIter *iter_dict_val, DBusMessageIter *iter_array);

dbus_bool_t rdkb_dbus_dict_append_str_array(DBusMessageIter *iter_dict, const char *key, const char **items, const dbus_uint32_t num_items);

static dbus_bool_t rdkb_dbus_add_dict_entry_basic(DBusMessageIter *iter_dict, const char *key, const int value_type, const void *value);

dbus_bool_t rdkb_dbus_dict_append_int32(DBusMessageIter *iter_dict, const char *key, const dbus_int32_t value);

dbus_bool_t rdkb_dbus_simple_prop_getter(DBusMessageIter *iter, const int type, const void *val, DBusError *error);

dbus_bool_t rdkb_dbus_simple_prop_setter(DBusMessageIter *iter, DBusError *error, const int type, void *val);

dbus_bool_t rdkb_dbus_dict_open_write(DBusMessageIter *iter, DBusMessageIter *iter_dict);

dbus_bool_t rdkb_dbus_dict_close_write(DBusMessageIter *iter, DBusMessageIter *iter_dict);

DBusMessage * rdkb_dbus_reply_new_from_error(DBusMessage *message, DBusError *error, const char *fallback_name, const char *fallback_string);

dbus_bool_t rdkb_dbus_simple_array_prop_getter(DBusMessageIter *iter, const int type, const void *array, size_t array_len, DBusError *error);

static void rdkb_send_deprecated_prop_changed_signal(DBusConnection *con, const char *path, const char *interface, const rdkb_dbus_wifi_obj_desc_t *obj_dsc);

dbus_bool_t rdkb_dbus_dict_append_str(DBusMessageIter *iter_dict, const char *key, const char *value);

DBusMessage * rdkb_dbus_error_no_memory(DBusMessage *message);



#endif  /* WIFI_SUPP_H */
