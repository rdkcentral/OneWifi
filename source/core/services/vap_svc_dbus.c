#include <stdio.h>
#include "stdlib.h"
#include <arpa/inet.h>
#include <dbus/dbus.h>
#include "wifi_util.h"
#include "wifi_ctrl.h"
#include "vap_svc.h"
#include "wifi_hal_rdk_framework.h"
#include "rdkb_dbus/dbus_initialize.h"

#if 1
#include "rdkb_dbus/dbus_new_helpers.h"
#include "rdkb_dbus/dbus_new.h"
#else
#include "rdkb_dbus/dbus_common.h"
#include "rdkb_dbus/dbus_common_i.h"
#include "rdkb_dbus/dbus_new_helpers.h"
#include "rdkb_dbus/dbus_new_handlers.h"
#include "rdkb_dbus/dbus_dict_helpers.h"
#endif

#define DBUS_SERVICE_NAME    	"fi.w1.wpa_supplicant1"
#define DBUS_OBJECT_PATH     	"/fi/w1/wpa_supplicant1"
#define DBUS_INTERFACE_NAME  	"fi.w1.wpa_supplicant1"
#define METHOD_NAME     	"message_handler"

#define INTERFACE_DBUS_NEW_IFACE_INTERFACE	DBUS_INTERFACE_NAME	".Interface"
#define INTERFACE_DBUS_SERVICE_NAME 	"fi.w1.wpa_supplicant1.Interfaces.0"
#define INTERFACE_DBUS_SERVICE_PATH 	"/fi/w1/wpa_supplicant1/Interfaces/0"
#define INTERFACE_DBUS_INTERFACE_NAME	"fi.w1.wpa_supplicant1.Interfaces.0"

#define INTERFACE_DBUS_SERVICE_NAME_BSS 	"fi.w1.wpa_supplicant1.Interfaces.0.BSSs"
#define INTERFACE_DBUS_SERVICE_PATH_BSS 	"/fi/w1/wpa_supplicant1/Interfaces/0/BSSs"
#define INTERFACE_DBUS_INTERFACE_NAME_BSS	"fi.w1.wpa_supplicant1.Interfaces.0.BSSs"

#define WPAS_DBUS_NEW_BSSIDS_PART 		"BSSs"
#define WPAS_DBUS_NEW_IFACE_BSS 		DBUS_INTERFACE_NAME ".BSS"

#define WPAS_DBUS_DBUS_OBJECT_PATH_MAX 		150
#define WPAS_DBUS_INTERFACE_MAX 		150
#define WPAS_DBUS_METHOD_SIGNAL_PROP_MAX 	50
#define WPAS_DBUS_AUTH_MODE_MAX 		64
#define WPAS_MAX_SCAN_SSIDS 			16

#define WPA_DBUS_INTROSPECTION_INTERFACE "org.freedesktop.DBus.Introspectable"
#define WPA_DBUS_INTROSPECTION_METHOD "Introspect"
#define WPA_DBUS_PROPERTIES_INTERFACE "org.freedesktop.DBus.Properties"
#define WPA_DBUS_PROPERTIES_GET "Get"
#define WPA_DBUS_PROPERTIES_SET "Set"
#define WPA_DBUS_PROPERTIES_GETALL "GetAll"

// Return number of elements in array
#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x)       ((unsigned int)(sizeof(x) / sizeof(x[0])))
#endif /* ARRAY_SIZE */

enum wpa_states {
	WPA_DISCONNECTED,
	WPA_INTERFACE_DISABLED,
	WPA_INACTIVE,
	WPA_SCANNING,
	WPA_AUTHENTICATING,
	WPA_ASSOCIATING,
	WPA_ASSOCIATED,
	WPA_4WAY_HANDSHAKE,
	WPA_GROUP_HANDSHAKE,
	WPA_COMPLETED
};

enum scan_req_type {
	NORMAL_SCAN_REQ,
	INITIAL_SCAN_REQ,
	MANUAL_SCAN_REQ
}; 

DBusConnection *connection;
DBusError error;

static DBusHandlerResult message_handler(DBusConnection *connection,
                                        DBusMessage *message, void *user_data);
dbus_bool_t dbus_dict_open_write(DBusMessageIter *iter,
                                     DBusMessageIter *iter_dict);
dbus_bool_t dbus_dict_close_write(DBusMessageIter *iter,
                                      DBusMessageIter *iter_dict);

dbus_bool_t dbus_getter_bss_bssid(
        const struct wpa_dbus_property_desc *property_desc,
        DBusMessageIter *iter, DBusError *error, void *user_data);

dbus_bool_t dbus_getter_bss_ssid(
        const struct wpa_dbus_property_desc *property_desc,
        DBusMessageIter *iter, DBusError *error, void *user_data);

dbus_bool_t dbus_getter_state(
        const struct wpa_dbus_property_desc *property_desc,
        DBusMessageIter *iter, DBusError *error, void *user_data);

static dbus_bool_t fill_dict_with_properties(
        DBusMessageIter *dict_iter,
        const struct wpa_dbus_property_desc *props,
        const char *interface, void *user_data, DBusError *error);

const char * dbus_type_as_string(const int type);

struct wpa_dbus_property_desc *all_interface_properties;
struct wpa_dbus_object_desc *obj_desc;
struct wpa_dbus_object_desc *obj_interface_desc;
struct wpa_dbus_object_desc *obj_desc_user_data = NULL;
int scan_done = 0;

DBusMessage *dbus_handler_create_interface(DBusMessage *message, void *global);
DBusMessage *dbus_handler_scan(DBusMessage *message);
DECLARE_ACCESSOR(dbus_getter_capabilities);
DECLARE_ACCESSOR(dbus_getter_debug_levelg);
DECLARE_ACCESSOR(dbus_setter_debug_level);

static const struct wpa_dbus_property_desc wpas_dbus_global_properties[] = {
        { NULL, NULL, NULL, NULL, NULL, NULL }
};

static const struct wpa_dbus_method_desc wpas_dbus_global_methods[] = {
        { "CreateInterface", WPAS_DBUS_NEW_INTERFACE,
          (WPADBusMethodHandler) dbus_handler_create_interface,
          {
                  { "args", "a{sv}", ARG_IN },
                  { "path", "o", ARG_OUT },
                  END_ARGS
          }
        },
        { NULL, NULL, NULL, { END_ARGS } }
};

static const struct wpa_dbus_signal_desc wpas_dbus_global_signals[] = {
        { "InterfaceAdded", WPAS_DBUS_NEW_INTERFACE,
          {
                  { "path", "o", ARG_OUT },
                  { "properties", "a{sv}", ARG_OUT },
                  END_ARGS
          }
        },
        { NULL, NULL, { END_ARGS } }
};

static const struct wpa_dbus_method_desc wpas_dbus_interface_methods[] = {
        { "Scan", WPAS_DBUS_NEW_IFACE_INTERFACE,
          (WPADBusMethodHandler) dbus_handler_scan,
          {
                  { "args", "a{sv}", ARG_IN },
                  END_ARGS
          }
        },
	{ NULL, NULL, NULL, { END_ARGS } }
};

static const struct wpa_dbus_signal_desc wpas_dbus_interface_signals[] = {
        { "ScanDone", WPAS_DBUS_NEW_IFACE_INTERFACE,
          {
                  { "success", "b", ARG_OUT },
                  END_ARGS
          }
        },
        { NULL, NULL, { END_ARGS } }
};


static const struct wpa_dbus_property_desc wpas_dbus_interface_properties[] = {
        { "Capabilities", WPAS_DBUS_NEW_IFACE_INTERFACE, "a{sv}",
          dbus_getter_capabilities,
          NULL,
          NULL
        },
	{ "State", WPAS_DBUS_NEW_IFACE_INTERFACE, "s",
          dbus_getter_state,
          NULL,
          NULL
        },
        { NULL, NULL, NULL, NULL, NULL, NULL }
};

static const struct wpa_dbus_property_desc wpas_dbus_bss_properties[] = {
        { "SSID", WPAS_DBUS_NEW_IFACE_BSS, "ay",
          dbus_getter_bss_ssid,
          NULL,
          NULL
        },
        { "BSSID", WPAS_DBUS_NEW_IFACE_BSS, "ay",
          dbus_getter_bss_bssid,
          NULL,
          NULL
        },
        { NULL, NULL, NULL, NULL, NULL, NULL }
};

static const struct wpa_dbus_signal_desc wpas_dbus_bss_signals[] = {
        /* Deprecated: use org.freedesktop.DBus.Properties.PropertiesChanged */
        { "PropertiesChanged", WPAS_DBUS_NEW_IFACE_BSS,
          {
                  { "properties", "a{sv}", ARG_OUT },
                  END_ARGS
          }
        },
        { NULL, NULL, { END_ARGS } }
};



dbus_bool_t dbus_getter_debug_levelg(
        const struct wpa_dbus_property_desc *property_desc,
        DBusMessageIter *iter, DBusError *error, void *user_data)
{
        const char *str;
        int idx = 1;

        if (idx < 0)
                idx = 0;
        if (idx > 5)
                idx = 5;
        str = "error";
	return;
}

dbus_bool_t dbus_setter_debug_level(
        const struct wpa_dbus_property_desc *property_desc,
        DBusMessageIter *iter, DBusError *error, void *user_data)
{
    return TRUE;
}

struct wpa_dbus_object_desc *initialize_object_desc_param(const char *path,
                                void *user_data, WPADBusArgumentFreeFunction free_func,
                                const struct wpa_dbus_method_desc *methods,
                                const struct wpa_dbus_property_desc *properties,
                                const struct wpa_dbus_signal_desc *signals)
{
    struct wpa_dbus_object_desc *obj_desc = (struct wpa_dbus_object_desc *) malloc (sizeof(struct wpa_dbus_object_desc));

    obj_desc->user_data = user_data;
    obj_desc->user_data_free_func = free_func;
    obj_desc->methods = methods;
    obj_desc->properties = properties;
    obj_desc->signals = signals;
    obj_desc->path = path;

    return obj_desc;
}

int dbus_register_object_per_iface(char *path, char *ifname,
                                       struct wpa_dbus_object_desc *obj_desc)
{
        DBusConnection *con;
        DBusError error;
        DBusObjectPathVTable vtable = {
                NULL, &message_handler,
                NULL, NULL, NULL, NULL 
        };   

        con = obj_desc->connection;
        dbus_error_init(&error);
	printf("%s():%d Register path:%s, ifnmae:%s\n", __func__, __LINE__, path, ifname);
        /* Register the message handler for the interface functions */
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

static void dbus_signal_process(char *obj_path, const char *obj_interface,
					const char *sig_path,  const char *sig_interface, const char *sig_name,
                                       dbus_bool_t properties, DBusConnection *con, const char *bss_path)
{
        DBusMessage *msg;
        DBusMessageIter iter;
	char tmp_path[100] = { 0 };

        if (!obj_path || !obj_interface || !sig_path || !sig_interface || !sig_name) {
		printf("%s():%d: NULL: obj_path:%s, obj_interface:%s, sig_path:%s, sig_interface:%s, sig_name:%s\n", __func__, __LINE__, 
			obj_path, obj_interface, sig_path, sig_interface, sig_name);
                return;
	}

        msg = dbus_message_new_signal(sig_path, sig_interface, sig_name);
        if (msg == NULL) {
		printf("%s():%d: dbus_message_new_signal() failed\n", __func__, __LINE__);	
                return;
	}

	printf("%s():%d NEW SIGNAL: obj_path:%s, obj_interface:%s, sig_path:%s, sig_interface:%s, sig_name:%s, tmp_path:%s, bss_path:%s\n", 
			__func__, __LINE__, obj_path, obj_interface, sig_path, sig_interface, sig_name, tmp_path, bss_path);

	if (bss_path) {
        	dbus_message_iter_init_append(msg, &iter);
	        if (!dbus_message_iter_append_basic(&iter, DBUS_TYPE_OBJECT_PATH, &bss_path) ||
		   (properties && !dbus_get_object_properties(con, bss_path, obj_interface ,&iter))) {
			printf("%s():%d: dbus: Failed to construct signal\n", __func__, __LINE__);
        	} else {
			printf("%s():%d: dbus: signal sent\n", __func__, __LINE__);
	                dbus_connection_send(con, msg, NULL);
		}
	} else {
	        dbus_message_iter_init_append(msg, &iter);
	        if (!dbus_message_iter_append_basic(&iter, DBUS_TYPE_OBJECT_PATH, &obj_path) ||
		   (properties && !dbus_get_object_properties(con, obj_path, obj_interface ,&iter))) {
			printf("%s():%d: dbus: Failed to construct signal\n", __func__, __LINE__);
        	} else {
			printf("%s():%d: dbus: signal sent\n", __func__, __LINE__);
        	        dbus_connection_send(con, msg, NULL);
		}
	}

        dbus_message_unref(msg);
}

DBusMessage * dbus_handler_create_interface(DBusMessage *message, void *global)
{
    DBusMessage *reply = NULL;
    DBusMessageIter iter;
    char *ifname = "wl1";
    char *new_path = INTERFACE_DBUS_SERVICE_PATH;
    struct wpa_dbus_object_desc *obj_desc = NULL;

    dbus_message_iter_init(message, &iter);

    obj_desc = initialize_object_desc_param(INTERFACE_DBUS_SERVICE_PATH, NULL, NULL,
    	wpas_dbus_interface_methods, wpas_dbus_interface_properties, wpas_dbus_interface_signals);

    obj_desc->connection = connection;

    dbus_register_object_per_iface(INTERFACE_DBUS_SERVICE_PATH, ifname, obj_desc);
    dbus_signal_process(INTERFACE_DBUS_SERVICE_PATH, INTERFACE_DBUS_NEW_IFACE_INTERFACE,
    	DBUS_OBJECT_PATH, DBUS_SERVICE_NAME, "InterfaceAdded", TRUE, obj_desc->connection, NULL);

    reply = dbus_message_new_method_return(message);
    dbus_message_append_args(reply, DBUS_TYPE_OBJECT_PATH,
                                                   &obj_desc->path, DBUS_TYPE_INVALID);

    return reply;
}

DBusMessage * dbus_error_invalid_args(DBusMessage *message,
                                          const char *arg)
{
        DBusMessage *reply;

        reply = dbus_message_new_error(
                message, WPAS_DBUS_ERROR_INVALID_ARGS,
                "Did not receive correct message arguments.");
        if (arg != NULL)
                dbus_message_append_args(reply, DBUS_TYPE_STRING, &arg,
                                         DBUS_TYPE_INVALID);

        return reply;
}

void dbus_signal_scan_done(struct wpa_dbus_object_desc *obj_dsc, int success)
{
        DBusMessage *msg;
        dbus_bool_t succ;

        printf("===>dbus_signal_scan_done:%s\r\n", obj_dsc->path);
        msg = dbus_message_new_signal(obj_dsc->path,
                                      WPAS_DBUS_NEW_IFACE_INTERFACE,
                                      "ScanDone");
        if (msg == NULL)
                return;

        succ = success ? TRUE : FALSE;
        if (dbus_message_append_args(msg, DBUS_TYPE_BOOLEAN, &succ,
                                     DBUS_TYPE_INVALID))
                dbus_connection_send(obj_dsc->connection, msg, NULL);
        else 
                printf("dbus: Failed to construct signal\r\n");
        dbus_message_unref(msg);
}

#if 0
static int dbus_get_scan_ssids(DBusMessage *message, DBusMessageIter *var,
                                    struct wpa_driver_scan_params *params,
                                    DBusMessage **reply)
{
        struct wpa_driver_scan_ssid *ssids = params->ssids;
        size_t ssids_num = 0;
        u8 *ssid;
        DBusMessageIter array_iter, sub_array_iter;
        char *val;
        int len;

        if (dbus_message_iter_get_arg_type(var) != DBUS_TYPE_ARRAY) {
                (printf(
                           "%s[dbus]: ssids must be an array of arrays of bytes",
                           __func__);
                *reply = dbus_error_invalid_args(
                        message,
                        "Wrong SSIDs value type. Array of arrays of bytes required");
                return -1;
        }

        dbus_message_iter_recurse(var, &array_iter);

        if (dbus_message_iter_get_arg_type(&array_iter) != DBUS_TYPE_ARRAY ||
            dbus_message_iter_get_element_type(&array_iter) != DBUS_TYPE_BYTE) {
                (printf(
                           "%s[dbus]: ssids must be an array of arrays of bytes",
                           __func__);
                *reply = dbus_error_invalid_args(
                        message,
                        "Wrong SSIDs value type. Array of arrays of bytes required");
                return -1;
        }

        while (dbus_message_iter_get_arg_type(&array_iter) == DBUS_TYPE_ARRAY) {
                if (ssids_num >= WPAS_MAX_SCAN_SSIDS) {
                        (printf(
                                   "%s[dbus]: Too many ssids specified on scan dbus call",
                                   __func__);
                        *reply = dbus_error_invalid_args(
                                message,
                                "Too many ssids specified. Specify at most four");
                        return -1;
                }

                dbus_message_iter_recurse(&array_iter, &sub_array_iter);

                dbus_message_iter_get_fixed_array(&sub_array_iter, &val, &len);

                if (len > SSID_MAX_LEN) {
                        (printf(
                                   "%s[dbus]: SSID too long (len=%d max_len=%d)",
                                   __func__, len, SSID_MAX_LEN);
                        *reply = dbus_error_invalid_args(
                                message, "Invalid SSID: too long");
                        return -1;
                }
                if (len != 0) {
                        ssid = os_memdup(val, len);
                        if (ssid == NULL) {
                                *reply = dbus_error_no_memory(message);
                                return -1;
                        }
                } else {
                        /* Allow zero-length SSIDs */
                        ssid = NULL;
                }

                ssids[ssids_num].ssid = ssid;
                ssids[ssids_num].ssid_len = len;

                dbus_message_iter_next(&array_iter);
                ssids_num++;
        }

        params->num_ssids = ssids_num;
        return 0;

}

static int dbus_get_scan_allow_roam(DBusMessage *message,
                                         DBusMessageIter *var,
                                         dbus_bool_t *allow,
                                         DBusMessage **reply)
{
        if (dbus_message_iter_get_arg_type(var) != DBUS_TYPE_BOOLEAN) {
                printf("%s[dbus]: Type must be a boolean",
                           __func__);
                *reply = dbus_error_invalid_args(
                        message, "Wrong Type value type. Boolean required");
                return -1;
        }
        dbus_message_iter_get_basic(var, allow);
        return 0;
}
#endif

static int dbus_get_scan_type(DBusMessage *message, DBusMessageIter *var,
                                   char **type, DBusMessage **reply)
{
        if (dbus_message_iter_get_arg_type(var) != DBUS_TYPE_STRING) {
                printf("%s[dbus]: Type must be a string",
                           __func__);
                *reply = dbus_error_invalid_args(
                        message, "Wrong Type value type. String required");
                return -1;
        }
        dbus_message_iter_get_basic(var, type);
        return 0;
}

DBusMessage *dbus_handler_scan(DBusMessage *message)
{
        DBusMessage *reply = NULL;
        DBusMessageIter iter, dict_iter, entry_iter, variant_iter;
        char *key = NULL, *type = NULL;
        size_t i;
	wifi_ctrl_t *ctrl;
        vap_svc_t *svc;
        dbus_bool_t allow_roam = 1;

        dbus_message_iter_init(message, &iter);

        dbus_message_iter_recurse(&iter, &dict_iter);

        while (dbus_message_iter_get_arg_type(&dict_iter) == DBUS_TYPE_DICT_ENTRY) {
                dbus_message_iter_recurse(&dict_iter, &entry_iter);
                dbus_message_iter_get_basic(&entry_iter, &key);
                dbus_message_iter_next(&entry_iter);
                dbus_message_iter_recurse(&entry_iter, &variant_iter);

                if (strcmp(key, "Type") == 0) { 
                        if (dbus_get_scan_type(message, &variant_iter,
                                                    &type, &reply) < 0) 
                                goto out;
#if 0

                } else if (os_strcmp(key, "SSIDs") == 0) { 
                        if (dbus_get_scan_ssids(message, &variant_iter,
                                                     &params, &reply) < 0) 
                                goto out; 
                } else if (os_strcmp(key, "IEs") == 0) { 
                        if (dbus_get_scan_ies(message, &variant_iter,
                                                   &params, &reply) < 0) 
                                goto out; 
                } else if (os_strcmp(key, "Channels") == 0) { 
                        if (wpas_dbus_get_scan_channels(message, &variant_iter,
                                                        &params, &reply) < 0) 
                                goto out; 
                } else if (os_strcmp(key, "AllowRoam") == 0) { 
                        if (dbus_get_scan_allow_roam(message,
                                                          &variant_iter,
                                                          &allow_roam,
                                                          &reply) < 0) 
                                goto out; 
#endif
                } else {
                        printf( "%s[dbus]: Unknown argument %s",
                                   __func__, key);
                        reply = dbus_error_invalid_args(message, key);
                        goto out; 
                }    

                dbus_message_iter_next(&dict_iter);
        }

        if (!type) {
                printf( "%s[dbus]: Scan type not specified",
                           __func__);
                reply = dbus_error_invalid_args(message, key);
                goto out;
        }

        if (strcmp(type, "passive") == 0) {
        } else if (strcmp(type, "active") == 0) {
        } else {
                printf( "%s[dbus]: Unknown scan type: %s",
                           __func__, type);
                reply = dbus_error_invalid_args(message,
                                                     "Wrong scan type");
                goto out;
        }

out:
        printf("\n%s():%d, Type:%d\n", __func__, __LINE__, type);
    	ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
	svc = get_svc_by_type(ctrl, vap_svc_type_sta);

	sta_start_scan(svc);

        return reply;
}


static dbus_bool_t dbus_add_dict_entry_end(
        DBusMessageIter *iter_dict, DBusMessageIter *iter_dict_entry,
        DBusMessageIter *iter_dict_val)
{
        if (!dbus_message_iter_close_container(iter_dict_entry, iter_dict_val))
                return FALSE;

        return dbus_message_iter_close_container(iter_dict, iter_dict_entry);
}

dbus_bool_t dbus_dict_end_array(DBusMessageIter *iter_dict,
                                    DBusMessageIter *iter_dict_entry,
                                    DBusMessageIter *iter_dict_val,
                                    DBusMessageIter *iter_array)
{
        if (!iter_dict || !iter_dict_entry || !iter_dict_val || !iter_array ||
            !dbus_message_iter_close_container(iter_dict_val, iter_array))
                return FALSE;

        return dbus_add_dict_entry_end(iter_dict, iter_dict_entry,
                                            iter_dict_val);
}

static inline dbus_bool_t wpa_dbus_dict_end_string_array(DBusMessageIter *iter_dict,
                               DBusMessageIter *iter_dict_entry,
                               DBusMessageIter *iter_dict_val,
                               DBusMessageIter *iter_array)
{
        return dbus_dict_end_array(iter_dict, iter_dict_entry,
                                       iter_dict_val, iter_array);
}

dbus_bool_t dbus_dict_string_array_add_element(DBusMessageIter *iter_array,
                                                   const char *elem)
{
        if (!iter_array || !elem)
                return FALSE;

        return dbus_message_iter_append_basic(iter_array, DBUS_TYPE_STRING,
                                              &elem);
}

static dbus_bool_t dbus_add_dict_entry_start(
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

static inline int snprintf_error(size_t size, int res)
{
        return res < 0 || (unsigned int) res >= size;
}

dbus_bool_t wpa_dbus_dict_begin_array(DBusMessageIter *iter_dict,
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
            !dbus_add_dict_entry_start(iter_dict, iter_dict_entry,
                                            key, DBUS_TYPE_ARRAY) ||
            !dbus_message_iter_open_container(iter_dict_entry,
                                              DBUS_TYPE_VARIANT,
                                              array_type,
                                              iter_dict_val))
                return FALSE;

        return dbus_message_iter_open_container(iter_dict_val, DBUS_TYPE_ARRAY,
                                                type, iter_array);
}

dbus_bool_t dbus_dict_begin_string_array(DBusMessageIter *iter_dict,
                                             const char *key,
                                             DBusMessageIter *iter_dict_entry,
                                             DBusMessageIter *iter_dict_val,
                                             DBusMessageIter *iter_array)
{
        return wpa_dbus_dict_begin_array(
                iter_dict, key,
                DBUS_TYPE_STRING_AS_STRING,
                iter_dict_entry, iter_dict_val, iter_array);
}

dbus_bool_t dbus_dict_append_string_array(DBusMessageIter *iter_dict,
                                              const char *key,
                                              const char **items,
                                              const dbus_uint32_t num_items)
{                                             
        DBusMessageIter iter_dict_entry, iter_dict_val, iter_array;
        dbus_uint32_t i;
                    
        if (!key || (!items && num_items != 0) ||
            !dbus_dict_begin_string_array(iter_dict, key,
                                              &iter_dict_entry, &iter_dict_val,
                                              &iter_array)) 
                return FALSE;
                     
        for (i = 0; i < num_items; i++) {
                if (!dbus_dict_string_array_add_element(&iter_array,
                                                            items[i]))
                        return FALSE;
        }
            
        return wpa_dbus_dict_end_string_array(iter_dict, &iter_dict_entry,
                                              &iter_dict_val, &iter_array);
}


static dbus_bool_t _dbus_add_dict_entry_basic(DBusMessageIter *iter_dict,
                                                  const char *key,
                                                  const int value_type,
                                                  const void *value)
{
        DBusMessageIter iter_dict_entry, iter_dict_val;
        const char *type_as_string = NULL;

        if (key == NULL)
                return FALSE;

        type_as_string = dbus_type_as_string(value_type);
        if (!type_as_string)
                return FALSE;

        if (!dbus_add_dict_entry_start(iter_dict, &iter_dict_entry,
                                            key, value_type) ||
            !dbus_message_iter_open_container(&iter_dict_entry,
                                              DBUS_TYPE_VARIANT,
                                              type_as_string, &iter_dict_val) ||
            !dbus_message_iter_append_basic(&iter_dict_val, value_type, value))
                return FALSE;

        return dbus_add_dict_entry_end(iter_dict, &iter_dict_entry,
                                            &iter_dict_val);
}

dbus_bool_t dbus_dict_append_int32(DBusMessageIter *iter_dict,
                                       const char *key,
                                       const dbus_int32_t value)
{
        return _dbus_add_dict_entry_basic(iter_dict, key, DBUS_TYPE_INT32,
                                              &value);
}


dbus_bool_t get_default_capabilities(const struct wpa_dbus_property_desc *property_desc, DBusMessageIter *iter, DBusError *error, void *user_data) 
{
        struct wpa_supplicant *wpa_s = user_data;
        DBusMessageIter iter_dict, iter_dict_entry, iter_dict_val, iter_array,
                variant_iter;
        const char *scans[] = { "active", "passive", "ssid" };

        if (!dbus_message_iter_open_container(iter, DBUS_TYPE_VARIANT,
                                              "a{sv}", &variant_iter) ||
            !dbus_dict_open_write(&variant_iter, &iter_dict))
                goto nomem;

#ifdef CONFIG_NO_TKIP
	const char *args[] = {"ccmp", "none"};
#else /* CONFIG_NO_TKIP */
	const char *args[] = {"ccmp", "tkip", "none"};
#endif /* CONFIG_NO_TKIP */

	if (!dbus_dict_append_string_array(
		    &iter_dict, "Pairwise", args,
		    ARRAY_SIZE(args))) {
		goto nomem;
	}

	const char *args_grp[] = {
		"ccmp",
#ifndef CONFIG_NO_TKIP
		"tkip",
#endif /* CONFIG_NO_TKIP */
#ifdef CONFIG_WEP
		"wep104", "wep40"
#endif /* CONFIG_WEP */
	};   

	if (!dbus_dict_append_string_array(
		    &iter_dict, "Group", args_grp,
		    ARRAY_SIZE(args_grp))) {
		goto nomem; 
	}

       const char *args_key_mgmt[] = {
		"wpa-psk", "wpa-eap", "ieee8021x", "wpa-none",
#ifdef CONFIG_WPS
		"wps",
#endif /* CONFIG_WPS */
		"none"
	};
	if (!dbus_dict_append_string_array(
		    &iter_dict, "KeyMgmt", args_key_mgmt,
		    ARRAY_SIZE(args_key_mgmt))) {
		goto nomem;
	}

	const char *args_protocol[] = { "rsn", "wpa" };

	if (!dbus_dict_append_string_array(
		    &iter_dict, "Protocol", args_protocol,
		    ARRAY_SIZE(args_protocol))) {
		goto nomem;
	}

	const char *args_auth_algo[] = { "open", "shared", "leap" };

	if (!dbus_dict_append_string_array(
		    &iter_dict, "AuthAlg", args_auth_algo,
		    ARRAY_SIZE(args_auth_algo))) {
		goto nomem;
	}

        /***** Scan */
        if (!dbus_dict_append_string_array(&iter_dict, "Scan", scans,
                                               ARRAY_SIZE(scans))) {
                goto nomem;
	}

        /***** Modes */
        if (!dbus_dict_begin_string_array(&iter_dict, "Modes",
                                              &iter_dict_entry,
                                              &iter_dict_val,
                                              &iter_array) ||
            !dbus_dict_string_array_add_element(
                    &iter_array, "infrastructure") ||
            !wpa_dbus_dict_end_string_array(&iter_dict,
                                            &iter_dict_entry,
                                            &iter_dict_val,
                                            &iter_array)) {
                goto nomem;
	}
        /***** Modes end */

	dbus_int32_t max_scan_ssid = 32;

	if (!dbus_dict_append_int32(&iter_dict, "MaxScanSSID",
                                                max_scan_ssid)) {
                        goto nomem;
	}

        if (!dbus_dict_close_write(&variant_iter, &iter_dict) ||
            !dbus_message_iter_close_container(iter, &variant_iter))
                goto nomem;

        return TRUE;

nomem:
        dbus_set_error_const(error, DBUS_ERROR_NO_MEMORY, "no memory");
        return FALSE;
}

dbus_bool_t dbus_getter_capabilities(
        const struct wpa_dbus_property_desc *property_desc,
        DBusMessageIter *iter, DBusError *error, void *user_data)
{
	return get_default_capabilities(property_desc, iter, error, user_data);
}

const char * dbus_type_as_string(const int type)
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

dbus_bool_t dbus_simple_property_getter(DBusMessageIter *iter,
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

        if (!dbus_message_iter_open_container(iter, DBUS_TYPE_VARIANT,
                                              dbus_type_as_string(type),
                                              &variant_iter) ||
            !dbus_message_iter_append_basic(&variant_iter, type, val) ||
            !dbus_message_iter_close_container(iter, &variant_iter)) {
                dbus_set_error(error, DBUS_ERROR_FAILED,
                               "%s: error constructing reply", __func__);
                return FALSE;
        }

        return TRUE;
}

const char * wpa_supplicant_state_txt(enum wpa_states state)
{
        switch (state) {
        case WPA_DISCONNECTED:
                return "DISCONNECTED";
        case WPA_INACTIVE:
                return "INACTIVE";
        case WPA_INTERFACE_DISABLED:
                return "INTERFACE_DISABLED";
        case WPA_SCANNING:
                return "SCANNING";
        case WPA_AUTHENTICATING:
                return "AUTHENTICATING";
        case WPA_ASSOCIATING:
                return "ASSOCIATING";
        case WPA_ASSOCIATED:
                return "ASSOCIATED";
        case WPA_4WAY_HANDSHAKE:
                return "4WAY_HANDSHAKE";
        case WPA_GROUP_HANDSHAKE:
                return "GROUP_HANDSHAKE";
        case WPA_COMPLETED:
                return "COMPLETED";
        default:
                return "UNKNOWN";
        }
}

dbus_bool_t dbus_getter_state(
        const struct wpa_dbus_property_desc *property_desc,
        DBusMessageIter *iter, DBusError *error, void *user_data)
{
        struct wpa_supplicant *wpa_s = user_data;
        const char *str_state;
        char *state_ls, *tmp;
        dbus_bool_t success = FALSE;

        //str_state = wpa_supplicant_state_txt(wpa_s->wpa_state);
	// TBD - revisit
        str_state = wpa_supplicant_state_txt(WPA_DISCONNECTED);

        /* make state string lowercase to fit new DBus API convention
         */
        state_ls = tmp = strdup(str_state);
        if (!tmp) {
                dbus_set_error_const(error, DBUS_ERROR_NO_MEMORY, "no memory");
                return FALSE;
        }
        while (*tmp) {
                *tmp = tolower(*tmp);
                tmp++;
        }

        success = dbus_simple_property_getter(iter, DBUS_TYPE_STRING,
                                                   &state_ls, error);

        free(state_ls);

        return success;
}

void dbus_register()
{
    DBusConnection *connection1;
    DBusObjectPathVTable vtable = {
        .message_function = message_handler,
    };

    connection1 = dbus_bus_get(DBUS_BUS_SYSTEM, &error);
    if (dbus_error_is_set(&error)) {
        wifi_util_info_print(WIFI_CTRL, "%s:%d: dbus: Could not acquire the system bus: %s - %s", __func__, __LINE__, error.name, error.message);
	dbus_error_free(&error);
    }

    if (!dbus_connection_register_object_path(connection1, INTERFACE_DBUS_SERVICE_PATH, &vtable, NULL)) {
        fprintf(stderr, "Failed to register object path\n");
        exit(1);
    }
}

static DBusMessage * process_msg_method_handler(DBusMessage *message,
                                          struct wpa_dbus_object_desc *obj_dsc)
{
        const struct wpa_dbus_method_desc *method_dsc = obj_dsc->methods;
        const char *method;
        const char *msg_interface;

        method = dbus_message_get_member(message);
        msg_interface = dbus_message_get_interface(message);

        /* try match call to any registered method */
        while (method_dsc && method_dsc->dbus_method) {
                /* compare method names and interfaces */
                if (!strncmp(method_dsc->dbus_method, method,
                                WPAS_DBUS_METHOD_SIGNAL_PROP_MAX) &&
                    !strncmp(method_dsc->dbus_interface, msg_interface,
                                WPAS_DBUS_INTERFACE_MAX))
                        break;

                method_dsc++;
        }    
        if (method_dsc == NULL || method_dsc->dbus_method == NULL) {
                printf("no method handler for %s.%s on %s",
                           msg_interface, method,
                           dbus_message_get_path(message));
                return dbus_message_new_error(message,
                                              DBUS_ERROR_UNKNOWN_METHOD, NULL);
        }    

        return method_dsc->method_handler(message, obj_dsc->user_data);
}

dbus_bool_t dbus_dict_open_write(DBusMessageIter *iter,
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

dbus_bool_t dbus_dict_close_write(DBusMessageIter *iter,
                                      DBusMessageIter *iter_dict)
{       
        if (!iter || !iter_dict)
                return FALSE;

        return dbus_message_iter_close_container(iter, iter_dict);
}

DBusMessage * dbus_reply_new_from_error(DBusMessage *message,
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



dbus_bool_t dbus_simple_array_property_getter(DBusMessageIter *iter,
                                                   const int type,
                                                   const void *array,
                                                   size_t array_len,
                                                   DBusError *error)
{
        DBusMessageIter variant_iter, array_iter;
        char type_str[] = "a?"; /* ? will be replaced with subtype letter; */
        const char *sub_type_str;
        size_t element_size, i;

        if (!dbus_type_is_basic(type)) {
                dbus_set_error(error, DBUS_ERROR_FAILED,
                               "%s: given type is not basic", __func__);
                return FALSE;
        }

        sub_type_str = dbus_type_as_string(type);
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



dbus_bool_t dbus_getter_bss_bssid(
        const struct wpa_dbus_property_desc *property_desc,
        DBusMessageIter *iter, DBusError *error, void *user_data)
{
	
        struct bss_handler_args *args = user_data;
        //    struct wpa_bss *res;

        return dbus_simple_array_property_getter(iter, DBUS_TYPE_BYTE,
                                                      "XFSETUP-D64A", 12, 
                                                      error);

#if 0						    
        return dbus_simple_array_property_getter(iter, DBUS_TYPE_BYTE,
                                                      res->ssid, res->ssid_len,
                                                      error);
#endif

}

int dbus_get_object_properties(DBusConnection *con, const char *path, const char *interface, DBusMessageIter *iter) 
{
    struct wpa_dbus_object_desc *obj_desc = NULL;
    DBusMessageIter dict_iter;
    DBusError error;

    dbus_connection_get_object_path_data(con, path, (void **) &obj_desc);

    if (!obj_desc) {
        printf("dbus: %s: could not obtain object's private data: %s", __func__, path);
    }

    if (!dbus_dict_open_write(iter, &dict_iter)) {
    	printf("dbus: %s: failed to open message dict", __func__);
	return FALSE;
    }

    dbus_error_init(&error);
    if (!fill_dict_with_properties(&dict_iter, obj_desc->properties, interface, obj_desc->user_data, &error)) {
    	printf("dbus: %s: failed to get object properties: (%s) %s", __func__, 
		dbus_error_is_set(&error) ? error.name : "none",
		dbus_error_is_set(&error) ? error.message : "none");
	dbus_error_free(&error);
	dbus_dict_close_write(iter, &dict_iter);
	return FALSE;
    }

    return dbus_dict_close_write(iter, &dict_iter);
}


void wpas_dbus_signal_prop_changed(DBusConnection *connection, char *path, enum wpas_dbus_prop property)
{
        char *prop;
        dbus_bool_t flush;
	struct wpa_dbus_object_desc *obj_desc = NULL;

        if (path == NULL )
                return; /* Skip signal since D-Bus setup is not yet ready */

        flush = FALSE;
        switch (property) {
        case WPAS_DBUS_PROP_AP_SCAN:
                prop = "ApScan";
                break;
        case WPAS_DBUS_PROP_SCANNING:
                prop = "Scanning";
                break;
        case WPAS_DBUS_PROP_STATE:
                prop = "State";
                break;
        case WPAS_DBUS_PROP_CURRENT_BSS:
                prop = "CurrentBSS";
                break;
        case WPAS_DBUS_PROP_CURRENT_NETWORK:
                prop = "CurrentNetwork";
                break;
        case WPAS_DBUS_PROP_BSSS:
                prop = "BSSs";
                break;
        case WPAS_DBUS_PROP_STATIONS:
                prop = "Stations";
                break;
        case WPAS_DBUS_PROP_CURRENT_AUTH_MODE:
                prop = "CurrentAuthMode";
                break;
        case WPAS_DBUS_PROP_DISCONNECT_REASON:
                prop = "DisconnectReason";
                flush = TRUE;
                break;
        case WPAS_DBUS_PROP_AUTH_STATUS_CODE:
                prop = "AuthStatusCode";
                flush = TRUE;
                break;
        case WPAS_DBUS_PROP_ASSOC_STATUS_CODE:
                prop = "AssocStatusCode";
                flush = TRUE;
                break;
        case WPAS_DBUS_PROP_ROAM_TIME:
                prop = "RoamTime";
                break;
       case WPAS_DBUS_PROP_ROAM_COMPLETE:
                prop = "RoamComplete";
                break;
        case WPAS_DBUS_PROP_SESSION_LENGTH:
                prop = "SessionLength";
                break;
        case WPAS_DBUS_PROP_BSS_TM_STATUS:
                prop = "BSSTMStatus";
                break;
        default:
                printf( "dbus: %s: Unknown Property value %d",
                           __func__, property);
                return;
        }

	dbus_connection_get_object_path_data(connection, path, &obj_desc);

#if 0
        if (flush) {
                wpa_dbus_flush_object_changed_properties(
                        wpa_s->global->dbus->con, wpa_s->dbus_new_path);
        }
#endif
}


dbus_bool_t dbus_getter_bss_ssid(
        const struct wpa_dbus_property_desc *property_desc,
        DBusMessageIter *iter, DBusError *error, void *user_data)
{
	
        struct bss_handler_args *args = user_data;
        //struct wpa_bss *res;

	//res = get_bss_helper(args, error, __func__);
	//if (!res) return FALSE;

	printf("In dbus_getter_bss_ssid \n");
        return dbus_simple_array_property_getter(iter, DBUS_TYPE_BYTE,
                                                      "XFSETUP-D64A", 12, 
                                                      error);
}

static dbus_bool_t fill_dict_with_properties(
        DBusMessageIter *dict_iter,
        const struct wpa_dbus_property_desc *props,
        const char *interface, void *user_data, DBusError *error)
{
        DBusMessageIter entry_iter;
        const struct wpa_dbus_property_desc *dsc;

        for (dsc = props; dsc && dsc->dbus_property; dsc++) {
		printf("\nIN ====> dbus_property:%s, dbus_interface:%s, type:%s\n", dsc->dbus_property, dsc->dbus_interface, dsc->type);
                /* Only return properties for the requested D-Bus interface */
                if (strncmp(dsc->dbus_interface, interface,
                               WPAS_DBUS_INTERFACE_MAX) != 0)
                        continue;

                /* Skip write-only properties */
                if (dsc->getter == NULL)
                        continue;

                if (!dbus_message_iter_open_container(dict_iter,
                                                      DBUS_TYPE_DICT_ENTRY,
                                                      NULL, &entry_iter) ||
                    !dbus_message_iter_append_basic(&entry_iter,
                                                    DBUS_TYPE_STRING,
                                                    &dsc->dbus_property))
                        goto error;

                /* An error getting a property fails the request entirely */
                if (!dsc->getter(dsc, &entry_iter, error, user_data)) {
                        printf(
                                   "dbus: %s dbus_interface=%s dbus_property=%s getter failed",
                                   __func__, dsc->dbus_interface,
                                   dsc->dbus_property);
                        return FALSE;
                }

                if (!dbus_message_iter_close_container(dict_iter, &entry_iter))
                        goto error;
        }
        return TRUE;

error:
        dbus_set_error_const(error, DBUS_ERROR_NO_MEMORY, "no memory");
        return FALSE;
}

DBusMessage * dbus_error_no_memory(DBusMessage *message)
{
        printf("dbus: Failed to allocate memory");
        return dbus_message_new_error(message, DBUS_ERROR_NO_MEMORY, NULL);
}

static DBusMessage * get_all_properties(DBusMessage *message, char *interface,
                                        struct wpa_dbus_object_desc *obj_dsc)
{
        DBusMessage *reply;
        DBusMessageIter iter, dict_iter;
        DBusError error;

        reply = dbus_message_new_method_return(message);
        if (reply == NULL)
                return dbus_error_no_memory(message);

        dbus_message_iter_init_append(reply, &iter);
        if (!dbus_dict_open_write(&iter, &dict_iter)) {
                dbus_message_unref(reply);
                return dbus_error_no_memory(message);
        }

        dbus_error_init(&error);
        if (!fill_dict_with_properties(&dict_iter, obj_dsc->properties,
                                       interface, obj_dsc->user_data, &error)) {
                dbus_dict_close_write(&iter, &dict_iter);
                dbus_message_unref(reply);
                reply = dbus_reply_new_from_error(
                        message, &error, DBUS_ERROR_INVALID_ARGS,
                        "No readable properties in this interface");
                dbus_error_free(&error);
                return reply;
        }

        if (!dbus_dict_close_write(&iter, &dict_iter)) {
                dbus_message_unref(reply);
                return dbus_error_no_memory(message);
        }

        return reply;
}

static DBusMessage * properties_get_all(DBusMessage *message, char *interface,
                                        struct wpa_dbus_object_desc *obj_dsc)
{
        if (strcmp(dbus_message_get_signature(message), "s") != 0)
                return dbus_message_new_error(message, DBUS_ERROR_INVALID_ARGS,
                                              NULL);

        return get_all_properties(message, interface, obj_dsc);
}

DBusMessage *process_properties_msg_handler(DBusMessage *message, struct wpa_dbus_object_desc *obj_dsc) 
{
        DBusMessageIter iter;
        char *interface;
        const char *method;

        method = dbus_message_get_member(message);
        dbus_message_iter_init(message, &iter);

        if (!strncmp(WPA_DBUS_PROPERTIES_GET, method,
                        WPAS_DBUS_METHOD_SIGNAL_PROP_MAX) ||
            !strncmp(WPA_DBUS_PROPERTIES_SET, method,
                        WPAS_DBUS_METHOD_SIGNAL_PROP_MAX) ||
            !strncmp(WPA_DBUS_PROPERTIES_GETALL, method,
                        WPAS_DBUS_METHOD_SIGNAL_PROP_MAX)) {
                /* First argument: interface name (DBUS_TYPE_STRING) */
                if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING) {
                        return dbus_message_new_error(message,
                                                      DBUS_ERROR_INVALID_ARGS,
                                                      NULL);
                }    

                dbus_message_iter_get_basic(&iter, &interface);

                if (!strncmp(WPA_DBUS_PROPERTIES_GETALL, method,
                                WPAS_DBUS_METHOD_SIGNAL_PROP_MAX)) {
                        /* GetAll */
                        return properties_get_all(message, interface, obj_dsc);
                }    
                /* Get or Set */
                // return properties_get_or_set(message, &iter, interface, obj_dsc);
        }    
        printf("\n END: %s:%d: dbus_prop_msg_handler\n", __func__, __LINE__); 
        return dbus_message_new_error(message, DBUS_ERROR_UNKNOWN_METHOD, NULL);

}

int dbus_register_bss(unsigned int bss_id) {

    DBusMessageIter iter;
    char *ifname = "wl1";
    char bss_obj_path[WPAS_DBUS_OBJECT_PATH_MAX];
    struct bss_handler_args {
	struct tmp_handler *tmp;
	unsigned int id;
   } *arg;

    snprintf(bss_obj_path, WPAS_DBUS_OBJECT_PATH_MAX, "%s/" WPAS_DBUS_NEW_BSSIDS_PART "/%u", INTERFACE_DBUS_SERVICE_PATH, bss_id);

    arg = (struct bss_handler_args *) malloc(sizeof(struct bss_handler_args));
    arg->tmp = NULL;
    arg->id = bss_id;

    struct wpa_dbus_object_desc *wpa_obj_desc =  initialize_object_desc_param(bss_obj_path, arg, NULL, NULL, wpas_dbus_bss_properties, wpas_dbus_bss_signals);
    wpa_obj_desc->connection = connection;

    dbus_register_object_per_iface(bss_obj_path, ifname, wpa_obj_desc);
    dbus_signal_process(INTERFACE_DBUS_NEW_IFACE_INTERFACE, WPAS_DBUS_NEW_IFACE_BSS, INTERFACE_DBUS_SERVICE_PATH,
    	DBUS_SERVICE_NAME, "BSSAdded", TRUE, wpa_obj_desc->connection, bss_obj_path);
    
    wpas_dbus_signal_prop_changed(wpa_obj_desc->connection, bss_obj_path, WPAS_DBUS_PROP_BSSS);
    return 0;
}

#if 0
int dbus_register_bss(int bss_id) 
{
    printf("%s():%d\n", __func__, __LINE__);
    
    obj_interface_desc = obj_desc;
    dbus_signal_scan_done(obj_desc, TRUE);
    return TRUE;
}
#endif

static DBusHandlerResult message_handler(DBusConnection *connection,
                                        DBusMessage *message, void *user_data)
{
    DBusMessage *reply;
    const char *msg_interface;
    const char *method;
    const char *path;

    obj_desc_user_data = (struct wpa_dbus_object_desc *)user_data;

    method = dbus_message_get_member(message);
    path = dbus_message_get_path(message);
    msg_interface = dbus_message_get_interface(message);

    if (!strncmp(WPA_DBUS_PROPERTIES_INTERFACE, msg_interface, WPAS_DBUS_INTERFACE_MAX)) {
    	printf("\n **************> %s():%d: dbus_prop: %s.%s (%s) [%s]", __func__, __LINE__,
	   msg_interface, method, path,
	   dbus_message_get_signature(message));

        reply = process_properties_msg_handler(message, obj_desc_user_data);

    } else {
    	printf("\n **************> %s():%d: dbus_method: %s.  %s (%s) [%s]", __func__, __LINE__,
	   msg_interface, method, path,
	   dbus_message_get_signature(message));

        reply = process_msg_method_handler(message, obj_desc_user_data);
    }

    if (!dbus_message_get_no_reply(message)) {
        if (!dbus_connection_send(connection, reply, NULL)) {
            printf("%s():%d: dbus_connection_send failed.\n", __func__, __LINE__);
            dbus_message_unref(reply);
            return DBUS_HANDLER_RESULT_NEED_MEMORY;
        }
    }

    dbus_message_unref(reply);
    return DBUS_HANDLER_RESULT_HANDLED;

}

void* dbus_initialize(void* arg) 
{
    int *global=NULL;
    int *dbus=NULL;

    //wifi_util_info_print(WIFI_CTRL, "%s:%d: calling wpa_dbus_init API\n", __func__, __LINE__);
    //dbus = wpas_dbus_init(global);

    DBusObjectPathVTable vtable = {
        .message_function = message_handler,
    };

    static call = 0;

    const struct wpa_dbus_method_desc *methods;
    const struct wpa_dbus_property_desc *properties;
    const struct wpa_dbus_signal_desc *signals;
    int no_of_prop = sizeof(wpas_dbus_interface_properties) / sizeof(wpas_dbus_interface_properties[0]);

    obj_desc = (struct wpa_dbus_object_desc *) malloc (sizeof(struct wpa_dbus_object_desc));

    obj_desc->user_data = NULL;
    obj_desc->user_data_free_func = NULL;
    obj_desc->methods = wpas_dbus_global_methods;
    obj_desc->properties = wpas_dbus_global_properties;
    obj_desc->signals = wpas_dbus_global_signals;
    obj_desc->connection = dbus_bus_get(DBUS_BUS_SYSTEM, &error);
    obj_desc->path = WPAS_DBUS_NEW_PATH;

    wifi_util_info_print(WIFI_CTRL, "%s:%d DBUS service start\n", __func__, __LINE__);
    dbus_error_init(&error);

    dbus_error_init(&error);
    connection = dbus_bus_get(DBUS_BUS_SYSTEM, &error);
    if (dbus_error_is_set(&error)) {
        wifi_util_info_print(WIFI_CTRL, "%s:%d: dbus: Could not acquire the system bus: %s - %s", __func__, __LINE__, error.name, error.message);
	dbus_error_free(&error);
    }

    if (!dbus_connection_register_object_path(connection, DBUS_OBJECT_PATH, &vtable, obj_desc)) {
        fprintf(stderr, "Failed to register object path\n");
        exit(1);
    }

    if (dbus_bus_request_name(connection, DBUS_SERVICE_NAME, DBUS_NAME_FLAG_REPLACE_EXISTING, &error) != DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER) {
        wifi_util_info_print(WIFI_CTRL, "%s:%d: dbus: Error requesting name: %s\n", __func__, __LINE__, error.message);
	dbus_error_free(&error);
    }


    while (dbus_connection_read_write_dispatch(connection, -1)) {
    }

    dbus_connection_unref(connection);
    dbus_error_free(&error);

    return 0;
}
