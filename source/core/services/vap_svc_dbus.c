#include <stdio.h>
#include "stdlib.h"
#include <arpa/inet.h>
#include <dbus/dbus.h>
#include "wifi_util.h"
#include "wifi_ctrl.h"
#include "vap_svc.h"
#include "wifi_hal_rdk_framework.h"
#include "rdkb_dbus/dbus_initialize.h"
#include "rdkb_dbus/dbus_new_helpers.h"
#include "rdkb_dbus/dbus_new.h"
#include "rdkb_dbus/list.h"

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

#define WPAS_DBUS_NEW_NETWORKS_PART 		"Networks"
#define WPAS_DBUS_NEW_IFACE_NETWORK 		DBUS_INTERFACE_NAME ".Network"

#define WPAS_DBUS_OBJECT_PATH_MAX 		150
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

#ifndef MAC2STR
#define MAC2STR(a) (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5]
#define MACSTR "%02x:%02x:%02x:%02x:%02x:%02x"
#endif

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

static struct wpa_bss * get_bss_helper(struct bss_handler_args *args,
                                       DBusError *error, const char *func_name);

dbus_bool_t wpas_dbus_getter_bss_privacy(
        const struct wpa_dbus_property_desc *property_desc,
        DBusMessageIter *iter, DBusError *error, void *user_data);

dbus_bool_t wpas_dbus_getter_bss_mode(
        const struct wpa_dbus_property_desc *property_desc,
        DBusMessageIter *iter, DBusError *error, void *user_data);

dbus_bool_t wpas_dbus_getter_bss_signal(
        const struct wpa_dbus_property_desc *property_desc,
        DBusMessageIter *iter, DBusError *error, void *user_data);

dbus_bool_t wpas_dbus_getter_bss_frequency(
        const struct wpa_dbus_property_desc *property_desc,
        DBusMessageIter *iter, DBusError *error, void *user_data);

dbus_bool_t wpas_dbus_getter_bss_rates(
        const struct wpa_dbus_property_desc *property_desc,
        DBusMessageIter *iter, DBusError *error, void *user_data);

DBusMessage *dbus_handler_add_network(DBusMessage *message,
                                            struct wpa_supplicant *wpa_s);

DBusMessage * dbus_handler_select_network(DBusMessage *message,
                                               struct wpa_supplicant *wpa_s);

DBusMessage * dbus_reply_new_from_error(DBusMessage *message,
                                             DBusError *error,
                                             const char *fallback_name,
                                             const char *fallback_string);

dbus_bool_t dbus_simple_array_property_getter(DBusMessageIter *iter,
                                                   const int type,
                                                   const void *array,
                                                   size_t array_len,
                                                   DBusError *error);

dbus_bool_t dbus_simple_property_setter(DBusMessageIter *iter,
                                             DBusError *error,
                                             const int type, void *val);

dbus_bool_t wpas_dbus_getter_bss_rsn(
        const struct wpa_dbus_property_desc *property_desc,
        DBusMessageIter *iter, DBusError *error, void *user_data);

dbus_bool_t dbus_getter_iface_global(
        const struct wpa_dbus_property_desc *property_desc,
        DBusMessageIter *iter, DBusError *error, void *user_data);

dbus_bool_t dbus_setter_iface_global(
        const struct wpa_dbus_property_desc *property_desc,
        DBusMessageIter *iter, DBusError *error, void *user_data);

dbus_bool_t dbus_getter_scanning(
        const struct wpa_dbus_property_desc *property_desc,
        DBusMessageIter *iter, DBusError *error, void *user_data);

dbus_bool_t dbus_getter_ap_scan(
        const struct wpa_dbus_property_desc *property_desc,
        DBusMessageIter *iter, DBusError *error, void *user_data);

dbus_bool_t dbus_setter_ap_scan(
        const struct wpa_dbus_property_desc *property_desc,
        DBusMessageIter *iter, DBusError *error, void *user_data);
	
dbus_bool_t dbus_getter_bss_expire_age(
        const struct wpa_dbus_property_desc *property_desc,
        DBusMessageIter *iter, DBusError *error, void *user_data);


dbus_bool_t dbus_setter_bss_expire_age(
        const struct wpa_dbus_property_desc *property_desc,
        DBusMessageIter *iter, DBusError *error, void *user_data);

dbus_bool_t dbus_getter_bss_expire_count(
        const struct wpa_dbus_property_desc *property_desc,
        DBusMessageIter *iter, DBusError *error, void *user_data);

dbus_bool_t dbus_setter_bss_expire_count(
        const struct wpa_dbus_property_desc *property_desc,
        DBusMessageIter *iter, DBusError *error, void *user_data);

dbus_bool_t dbus_getter_country(
        const struct wpa_dbus_property_desc *property_desc,
        DBusMessageIter *iter, DBusError *error, void *user_data);

dbus_bool_t dbus_setter_country(
        const struct wpa_dbus_property_desc *property_desc,
        DBusMessageIter *iter, DBusError *error, void *user_data);

dbus_bool_t dbus_getter_ifname(
        const struct wpa_dbus_property_desc *property_desc,
        DBusMessageIter *iter, DBusError *error, void *user_data);

dbus_bool_t dbus_getter_driver(
        const struct wpa_dbus_property_desc *property_desc,
        DBusMessageIter *iter, DBusError *error, void *user_data);

dbus_bool_t dbus_getter_bridge_ifname(
        const struct wpa_dbus_property_desc *property_desc,
        DBusMessageIter *iter, DBusError *error, void *user_data);

dbus_bool_t dbus_setter_bridge_ifname(
        const struct wpa_dbus_property_desc *property_desc,
        DBusMessageIter *iter, DBusError *error, void *user_data);

dbus_bool_t dbus_getter_config_file(
        const struct wpa_dbus_property_desc *property_desc,
        DBusMessageIter *iter, DBusError *error, void *user_data);

dbus_bool_t dbus_getter_current_bss(
        const struct wpa_dbus_property_desc *property_desc,
        DBusMessageIter *iter, DBusError *error, void *user_data);

dbus_bool_t dbus_getter_current_network(
        const struct wpa_dbus_property_desc *property_desc,
        DBusMessageIter *iter, DBusError *error, void *user_data);

dbus_bool_t dbus_getter_current_auth_mode(
        const struct wpa_dbus_property_desc *property_desc,
        DBusMessageIter *iter, DBusError *error, void *user_data);

dbus_bool_t dbus_getter_blobs(
        const struct wpa_dbus_property_desc *property_desc,
        DBusMessageIter *iter, DBusError *error, void *user_data);

dbus_bool_t dbus_getter_bsss(
        const struct wpa_dbus_property_desc *property_desc,
        DBusMessageIter *iter, DBusError *error, void *user_data);

dbus_bool_t dbus_getter_networks(
        const struct wpa_dbus_property_desc *property_desc,
        DBusMessageIter *iter, DBusError *error, void *user_data);

static void wpas_dbus_signal_network(struct wpa_supplicant *wpa_s,
                                       int id, const char *sig_name,
                                       dbus_bool_t properties);

DBusMessage * dbus_error_no_memory(DBusMessage *message);

const char *dbus_type_as_string(const int type);

struct wpa_dbus_property_desc *all_interface_properties;
struct wpa_dbus_object_desc *obj_desc;
struct wpa_dbus_object_desc *obj_interface_desc;
struct wpa_dbus_object_desc *obj_desc_user_data = NULL;
struct wpa_supplicant *wpa_s = NULL;
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
        { "CreateInterface", DBUS_INTERFACE_NAME,
          (WPADBusMethodHandler) dbus_handler_create_interface,
          {
                  { "args", "a{sv}", ARG_IN },
                  { "path", "o", ARG_OUT },
                  END_ARGS
          }
        },
        { NULL, NULL, NULL, { END_ARGS } }
};

static const struct wpa_dbus_property_desc wpas_dbus_network_properties[] = {
#if 0
        { "Properties", WPAS_DBUS_NEW_IFACE_NETWORK, "a{sv}",
          wpas_dbus_getter_network_properties,
          wpas_dbus_setter_network_properties,
          NULL
        },
        { "Enabled", WPAS_DBUS_NEW_IFACE_NETWORK, "b",
          wpas_dbus_getter_enabled,
          wpas_dbus_setter_enabled,
          NULL
        },
#endif
        { NULL, NULL, NULL, NULL, NULL, NULL }
};


static const struct wpa_dbus_signal_desc wpas_dbus_network_signals[] = {
        /* Deprecated: use org.freedesktop.DBus.Properties.PropertiesChanged */
        { "PropertiesChanged", WPAS_DBUS_NEW_IFACE_NETWORK,
          {
                  { "properties", "a{sv}", ARG_OUT },
                  END_ARGS
          }
        },
        { NULL, NULL, { END_ARGS } }
};


static const struct wpa_dbus_signal_desc wpas_dbus_global_signals[] = {
        { "InterfaceAdded", DBUS_INTERFACE_NAME,
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
#if 0
        { "SignalPoll", WPAS_DBUS_NEW_IFACE_INTERFACE,
          (WPADBusMethodHandler) wpas_dbus_handler_signal_poll,
          {    
                  { "args", "a{sv}", ARG_OUT },
                  END_ARGS
          }    
        },   
        { "Disconnect", WPAS_DBUS_NEW_IFACE_INTERFACE,
          (WPADBusMethodHandler) wpas_dbus_handler_disconnect,
          {    
                  END_ARGS
          }    
        },
#endif
        { "AddNetwork", WPAS_DBUS_NEW_IFACE_INTERFACE,
          (WPADBusMethodHandler) dbus_handler_add_network,
          {    
                  { "args", "a{sv}", ARG_IN },
                  { "path", "o", ARG_OUT },
                  END_ARGS
          }    
        },
#if 0
        { "Reassociate", WPAS_DBUS_NEW_IFACE_INTERFACE,
          (WPADBusMethodHandler) wpas_dbus_handler_reassociate,
          {    
                  END_ARGS
          }    
        },   
        { "Reattach", WPAS_DBUS_NEW_IFACE_INTERFACE,
          (WPADBusMethodHandler) wpas_dbus_handler_reattach,
          {    
                  END_ARGS
          }    
        },   
        { "Reconnect", WPAS_DBUS_NEW_IFACE_INTERFACE,
          (WPADBusMethodHandler) wpas_dbus_handler_reconnect,
          {    
                  END_ARGS
          }    
        },   
        { "RemoveNetwork", WPAS_DBUS_NEW_IFACE_INTERFACE,
          (WPADBusMethodHandler) wpas_dbus_handler_remove_network,
          {    
                  { "path", "o", ARG_IN },
                  END_ARGS
          }    
        },   
        { "RemoveAllNetworks", WPAS_DBUS_NEW_IFACE_INTERFACE,
          (WPADBusMethodHandler) wpas_dbus_handler_remove_all_networks,
          {
                  END_ARGS
          }
        },
#endif
        { "SelectNetwork", WPAS_DBUS_NEW_IFACE_INTERFACE,
          (WPADBusMethodHandler) dbus_handler_select_network,
          {
                  { "path", "o", ARG_IN },
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
#if 0
	{ "Scanning", WPAS_DBUS_NEW_IFACE_INTERFACE, "b",
          dbus_getter_scanning,
          NULL,
          NULL
        },
#endif
        { "ApScan", WPAS_DBUS_NEW_IFACE_INTERFACE, "u",
          dbus_getter_ap_scan,
          dbus_setter_ap_scan,
          NULL
        },
#if 0
        { "BSSExpireAge", WPAS_DBUS_NEW_IFACE_INTERFACE, "u",
          dbus_getter_bss_expire_age,
          dbus_setter_bss_expire_age,
          NULL
        },
        { "BSSExpireCount", WPAS_DBUS_NEW_IFACE_INTERFACE, "u",
          dbus_getter_bss_expire_count,
          dbus_setter_bss_expire_count,
          NULL
        },
        { "Country", WPAS_DBUS_NEW_IFACE_INTERFACE, "s",
          dbus_getter_country,
          dbus_setter_country,
          NULL
        },
        { "Ifname", WPAS_DBUS_NEW_IFACE_INTERFACE, "s",
          dbus_getter_ifname,
          NULL,
          NULL
        },
        { "Driver", WPAS_DBUS_NEW_IFACE_INTERFACE, "s",
          dbus_getter_driver,
          NULL,
          NULL
        },
        { "BridgeIfname", WPAS_DBUS_NEW_IFACE_INTERFACE, "s",
          dbus_getter_bridge_ifname,
          dbus_setter_bridge_ifname,
          NULL
        },
        { "ConfigFile", WPAS_DBUS_NEW_IFACE_INTERFACE, "s",
          dbus_getter_config_file,
          NULL,
          NULL
        },
        { "CurrentBSS", WPAS_DBUS_NEW_IFACE_INTERFACE, "o",
          dbus_getter_current_bss,
          NULL,
          NULL
        },
        { "CurrentNetwork", WPAS_DBUS_NEW_IFACE_INTERFACE, "o",
          dbus_getter_current_network,
          NULL,
          NULL
        },
        { "CurrentAuthMode", WPAS_DBUS_NEW_IFACE_INTERFACE, "s",
          dbus_getter_current_auth_mode,
          NULL,
          NULL
        },
        { "Blobs", WPAS_DBUS_NEW_IFACE_INTERFACE, "a{say}",
          dbus_getter_blobs,
          NULL,
          NULL
        },
        { "BSSs", WPAS_DBUS_NEW_IFACE_INTERFACE, "ao",
          dbus_getter_bsss,
          NULL,
          NULL
        },
        { "Networks", WPAS_DBUS_NEW_IFACE_INTERFACE, "ao",
          dbus_getter_networks,
          NULL,
          NULL
        },
#endif
#if 0
        { "Dot11RSNAConfigPMKLifetime", WPAS_DBUS_NEW_IFACE_INTERFACE, "s",
          dbus_getter_iface_global,
          dbus_setter_iface_global,
          "dot11RSNAConfigPMKLifetime"
        },		
        { "ApIsolate", WPAS_DBUS_NEW_IFACE_INTERFACE, "s",
          dbus_getter_iface_global,
          dbus_setter_iface_global,
          "ap_isolate"
        },		
#else
        { "Dot11RSNAConfigPMKLifetime", WPAS_DBUS_NEW_IFACE_INTERFACE, "s",
          NULL,
          dbus_setter_iface_global,
          "dot11RSNAConfigPMKLifetime"
        },		
        { "ApIsolate", WPAS_DBUS_NEW_IFACE_INTERFACE, "s",
          NULL,
          dbus_setter_iface_global,
          "ap_isolate"
        },		
#endif
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
        { "Privacy", WPAS_DBUS_NEW_IFACE_BSS, "b",
          wpas_dbus_getter_bss_privacy,
          NULL,
          NULL
        },
        { "Mode", WPAS_DBUS_NEW_IFACE_BSS, "s",
          wpas_dbus_getter_bss_mode,
          NULL,
          NULL
        },
	{ "Signal", WPAS_DBUS_NEW_IFACE_BSS, "n",
          wpas_dbus_getter_bss_signal,
          NULL,
          NULL
        },
        { "Frequency", WPAS_DBUS_NEW_IFACE_BSS, "q",
          wpas_dbus_getter_bss_frequency,
          NULL,
          NULL
        },
        { "Rates", WPAS_DBUS_NEW_IFACE_BSS, "au",
          wpas_dbus_getter_bss_rates,
          NULL,
          NULL
        },
#if 0 
        { "WPA", WPAS_DBUS_NEW_IFACE_BSS, "a{sv}",
          wpas_dbus_getter_bss_wpa,
          NULL,
          NULL
        },
#endif
        { "RSN", WPAS_DBUS_NEW_IFACE_BSS, "a{sv}",
          wpas_dbus_getter_bss_rsn,
          NULL,
          NULL
        },
#if 0 
        { "WPS", WPAS_DBUS_NEW_IFACE_BSS, "a{sv}",
          wpas_dbus_getter_bss_wps,
          NULL,
          NULL
        },
        { "IEs", WPAS_DBUS_NEW_IFACE_BSS, "ay",
          wpas_dbus_getter_bss_ies,
          NULL,
          NULL
        },
        { "Age", WPAS_DBUS_NEW_IFACE_BSS, "u",
          wpas_dbus_getter_bss_age,
          NULL,
          NULL
        },
#endif
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


	printf("%s()%d: NEW_SIGNAL: bss_obj_path:%s, wpa_s->dbus_new_path:%s, WPAS_DBUS_NEW_IFACE_INTERFACE:%s"
		"  WPAS_DBUS_NEW_IFACE_BSS:%s, sig_name:%s\n",
		__func__, __LINE__, bss_path, sig_path, sig_interface, obj_interface, sig_name);

	if (bss_path) {
        	msg = dbus_message_new_signal(sig_path, obj_path, sig_name);
	        if (msg == NULL) {
			printf("%s():%d: dbus_message_new_signal() failed\n", __func__, __LINE__);	
                	return;
		}

        	dbus_message_iter_init_append(msg, &iter);
	        if (!dbus_message_iter_append_basic(&iter, DBUS_TYPE_OBJECT_PATH, &bss_path) ||
		   (properties && !dbus_get_object_properties(con, bss_path, obj_interface ,&iter))) {
			printf("%s():%d: dbus: Failed to construct signal\n", __func__, __LINE__);
        	} else {
			printf("%s():%d: dbus: signal sent\n", __func__, __LINE__);
	                dbus_connection_send(con, msg, NULL);
		}
	} else {
        	msg = dbus_message_new_signal(sig_path, sig_interface, sig_name);
	        if (msg == NULL) {
			printf("%s():%d: dbus_message_new_signal() failed\n", __func__, __LINE__);	
                	return;
		}

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

    obj_desc = initialize_object_desc_param(INTERFACE_DBUS_SERVICE_PATH, wpa_s, NULL,
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
        uint8_t *ssid;
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

char * wpas_dbus_new_decompose_object_path(const char *path, const char *sep,
                                           char **item)
{
        const unsigned int dev_path_prefix_len = strlen(WPAS_DBUS_NEW_PATH_INTERFACES "/");
        char *obj_path_only;
        char *pos;
        size_t sep_len;

        *item = NULL;

        /* Verify that this starts with our interface prefix */
        if (strncmp(path, WPAS_DBUS_NEW_PATH_INTERFACES "/",
                       dev_path_prefix_len) != 0)
                return NULL; /* not our path */

        /* Ensure there's something at the end of the path */
        if ((path + dev_path_prefix_len)[0] == '\0')
                return NULL;

        obj_path_only = strdup(path);
        if (obj_path_only == NULL)
                return NULL;

        pos = obj_path_only + dev_path_prefix_len;
        pos = strchr(pos, '/');
        if (pos == NULL)
                return obj_path_only; /* no next item on the path */

         /* Separate network interface prefix from the path */
        *pos++ = '\0';

        sep_len = strlen(sep);
        if (strncmp(pos, sep, sep_len) != 0 || pos[sep_len] != '/')
                return obj_path_only; /* no match */

         /* return a pointer to the requested item */
        *item = pos + sep_len + 1;
        return obj_path_only;
}

void dbus_signal_network_selected(struct wpa_supplicant *wpa_s, int id)
{
    wpas_dbus_signal_network(wpa_s, id, "NetworkSelected", FALSE);
}

DBusMessage * dbus_handler_select_network(DBusMessage *message,
                                               struct wpa_supplicant *wpa_s)
{
        DBusMessage *reply = NULL;
        const char *op;
        char *iface, *net_id;
        int id;
        struct wpa_ssid *ssid;

	printf("dbus_handler_select_network.....\n");
        dbus_message_get_args(message, NULL, DBUS_TYPE_OBJECT_PATH, &op,
                              DBUS_TYPE_INVALID);

        /* Extract the network ID and ensure the network */
        /* is actually a child of this interface */
        iface = wpas_dbus_new_decompose_object_path(op,
                                                    WPAS_DBUS_NEW_NETWORKS_PART,
                                                    &net_id);
        if (iface == NULL || net_id == NULL || !wpa_s->dbus_new_path ||
            strcmp(iface, wpa_s->dbus_new_path) != 0) {
                reply = dbus_error_invalid_args(message, op);
                goto out;
        }

        errno = 0;
        id = strtoul(net_id, NULL, 10);
        if (errno != 0) {
                reply = dbus_error_invalid_args(message, op);
                goto out;
        }

#if 0
        ssid = wpa_config_get_network(wpa_s->conf, id);
        if (ssid == NULL) {
                reply = wpas_dbus_error_network_unknown(message);
                goto out;
        }

        /* Finally, associate with the network */
        wpa_supplicant_select_network(wpa_s, ssid);
#else
        if (wpa_s->p_scan_bss_info != NULL) {
            uint32_t vap_index = wpa_s->p_scan_bss_info->vap_index;
	    wifi_bss_info_t *p_external_ap = &wpa_s->p_scan_bss_info->external_ap;
            printf("%s:%d sta connect for vap index: %d\n", __func__, __LINE__, vap_index);
            printf("1  =====>wpa_s:%p, net_id:%s, id:%d, p_external_ap: ssid:%s, sec_mode:%d, rssi:%d, caps:%x, password:%s!\n",
	    wpa_s, net_id, id, p_external_ap->ssid, p_external_ap->sec_mode, p_external_ap->rssi, p_external_ap->caps, wpa_s->p_scan_bss_info->password);
#if 1
            wifi_vap_security_t l_recv_security = { 0 };

            strcpy(l_recv_security.u.key.key, wpa_s->p_scan_bss_info->password);

	    set_sta_wifi_security_cfg(vap_index, &l_recv_security);
#endif
            if (wifi_hal_connect(vap_index, p_external_ap) == RETURN_ERR) {
                printf("%s:%d sta connect failed for vap index: %d\n", __func__, __LINE__, vap_index);
            } else {
                printf("%s:%d sta connected for ssid_id:%d\n", __func__, __LINE__, wpa_s->p_scan_bss_info->network_ssid_id);
	    }
	}
        dbus_signal_network_selected(wpa_s, wpa_s->p_scan_bss_info->network_ssid_id);
#endif

out:
        free(iface);
        return reply;
}

static void wpas_dbus_signal_network(struct wpa_supplicant *wpa_s,
                                     int id, const char *sig_name,
                                     dbus_bool_t properties)
{
        DBusMessage *msg;
        DBusMessageIter iter;
        char net_obj_path[WPAS_DBUS_OBJECT_PATH_MAX], *path;


        /* Do nothing if the control interface is not turned on */
	if (!wpa_s->dbus_new_path)
                return;

        os_snprintf(net_obj_path, WPAS_DBUS_OBJECT_PATH_MAX,
                    "%s/" WPAS_DBUS_NEW_NETWORKS_PART "/%u",
                    wpa_s->dbus_new_path, id);

        msg = dbus_message_new_signal(wpa_s->dbus_new_path,
                                      WPAS_DBUS_NEW_IFACE_INTERFACE,
                                      sig_name);
        if (msg == NULL)
                return;

        dbus_message_iter_init_append(msg, &iter);
        path = net_obj_path;
        if (!dbus_message_iter_append_basic(&iter, DBUS_TYPE_OBJECT_PATH,
                                            &path) ||
            (properties &&
             !dbus_get_object_properties(connection, net_obj_path, WPAS_DBUS_NEW_IFACE_NETWORK, &iter)))
                wpa_printf(MSG_ERROR, "dbus: Failed to construct signal");
        else
                dbus_connection_send(connection, msg, NULL);
        dbus_message_unref(msg);
}

static void wpas_dbus_signal_network_added(struct wpa_supplicant *wpa_s, int id)
{
        wpas_dbus_signal_network(wpa_s, id, "NetworkAdded", TRUE);
}

int wpas_dbus_register_network(struct wpa_supplicant *wpa_s,
                               //struct wpa_ssid *ssid)
                               scan_list_bss_info_t *arg_scan_bss_info)
{       
        struct wpas_dbus_priv *ctrl_iface;
        struct wpa_dbus_object_desc *obj_desc;
        struct network_handler_args *arg;
        char net_obj_path[WPAS_DBUS_OBJECT_PATH_MAX];

        /* Do nothing if the control interface is not turned on */
        if (wpa_s == NULL || !wpa_s->dbus_new_path)
                return 0;
        
        snprintf(net_obj_path, WPAS_DBUS_OBJECT_PATH_MAX,
                    "%s/" WPAS_DBUS_NEW_NETWORKS_PART "/%u",
                    wpa_s->dbus_new_path, arg_scan_bss_info->network_ssid_id);
        
        printf("dbus: Register network object '%s'", net_obj_path);

        obj_desc = malloc(sizeof(struct wpa_dbus_object_desc));
        if (!obj_desc) {
                printf(MSG_ERROR,
                           "Not enough memory to create object description");
                goto err;
        }
        
        /* allocate memory for handlers arguments */
        arg = malloc(sizeof(struct network_handler_args));
        if (!arg) {
                wpa_printf(MSG_ERROR,
                           "Not enough memory to create arguments for method");
                goto err;
        }
        
        arg->wpa_s = wpa_s;
        //arg->ssid = ssid;
        arg->scan_bss_info = arg_scan_bss_info;
      
        printf("In %s():%d: wpa_s:%p \n", __func__, __LINE__, wpa_s);
        struct wpa_dbus_object_desc *wpa_obj_desc = initialize_object_desc_param(net_obj_path, arg, NULL, NULL, wpas_dbus_network_properties, wpas_dbus_network_signals);

        wpa_obj_desc->connection = connection;

        dbus_register_object_per_iface(net_obj_path, wpa_s->ifname, wpa_obj_desc);
 
        wpas_dbus_signal_network_added(wpa_s, arg_scan_bss_info->network_ssid_id);
        return 0;

err:
        //free_dbus_object_desc(obj_desc);
	free(wpa_obj_desc);
        return -1;
}

void wpas_notify_network_added(struct wpa_supplicant *wpa_s,
                               //struct wpa_ssid *ssid)
                               scan_list_bss_info_t *scan_bss_info)
{
	//wpas_dbus_register_network(wpa_s, ssid);
	wpas_dbus_register_network(wpa_s, scan_bss_info);
	printf("==================================================IN wpas_notify_network_added():0\n");

//	wpa_msg_ctrl(wpa_s, MSG_INFO, WPA_EVENT_NETWORK_ADDED "%d", ssid->id);
}

void wpa_config_set_network_defaults(struct wpa_ssid *ssid)
{
        ssid->proto = DEFAULT_PROTO;
        ssid->pairwise_cipher = DEFAULT_PAIRWISE;
        ssid->group_cipher = DEFAULT_GROUP;
        ssid->key_mgmt = DEFAULT_KEY_MGMT;
        // ssid->wpa_deny_ptk0_rekey = PTK0_REKEY_ALLOW_ALWAYS;
        ssid->bg_scan_period = DEFAULT_BG_SCAN_PERIOD;
        ssid->ht = 1;
        ssid->vht = 1;
        ssid->he = 1;
#if 0
#ifdef IEEE8021X_EAPOL
        ssid->eapol_flags = DEFAULT_EAPOL_FLAGS;
        ssid->eap_workaround = DEFAULT_EAP_WORKAROUND;
        ssid->eap.fragment_size = DEFAULT_FRAGMENT_SIZE;
        ssid->eap.sim_num = DEFAULT_USER_SELECTED_SIM;
#endif /* IEEE8021X_EAPOL */
#endif

#ifdef CONFIG_MESH
        ssid->dot11MeshMaxRetries = DEFAULT_MESH_MAX_RETRIES;
        ssid->dot11MeshRetryTimeout = DEFAULT_MESH_RETRY_TIMEOUT;
        ssid->dot11MeshConfirmTimeout = DEFAULT_MESH_CONFIRM_TIMEOUT;
        ssid->dot11MeshHoldingTimeout = DEFAULT_MESH_HOLDING_TIMEOUT;
        ssid->mesh_fwding = DEFAULT_MESH_FWDING;
        ssid->mesh_rssi_threshold = DEFAULT_MESH_RSSI_THRESHOLD;
#endif /* CONFIG_MESH */
#ifdef CONFIG_HT_OVERRIDES
        ssid->disable_ht = DEFAULT_DISABLE_HT;
        ssid->disable_ht40 = DEFAULT_DISABLE_HT40;
        ssid->disable_sgi = DEFAULT_DISABLE_SGI;
        ssid->disable_ldpc = DEFAULT_DISABLE_LDPC;
        ssid->tx_stbc = DEFAULT_TX_STBC;
        ssid->rx_stbc = DEFAULT_RX_STBC;
        ssid->disable_max_amsdu = DEFAULT_DISABLE_MAX_AMSDU;
        ssid->ampdu_factor = DEFAULT_AMPDU_FACTOR;
        ssid->ampdu_density = DEFAULT_AMPDU_DENSITY;
#endif /* CONFIG_HT_OVERRIDES */
#ifdef CONFIG_VHT_OVERRIDES
        ssid->vht_rx_mcs_nss_1 = -1;
        ssid->vht_rx_mcs_nss_2 = -1;
        ssid->vht_rx_mcs_nss_3 = -1;
        ssid->vht_rx_mcs_nss_4 = -1;
        ssid->vht_rx_mcs_nss_5 = -1;
        ssid->vht_rx_mcs_nss_6 = -1;
        ssid->vht_rx_mcs_nss_7 = -1;
        ssid->vht_rx_mcs_nss_8 = -1;
        ssid->vht_tx_mcs_nss_1 = -1;
        ssid->vht_tx_mcs_nss_2 = -1;
        ssid->vht_tx_mcs_nss_3 = -1;
        ssid->vht_tx_mcs_nss_4 = -1;
        ssid->vht_tx_mcs_nss_5 = -1;
        ssid->vht_tx_mcs_nss_6 = -1;
        ssid->vht_tx_mcs_nss_7 = -1;
        ssid->vht_tx_mcs_nss_8 = -1;
#endif /* CONFIG_VHT_OVERRIDES */
        ssid->proactive_key_caching = -1;
//        ssid->ieee80211w = MGMT_FRAME_PROTECTION_DEFAULT;
        ssid->sae_pwe = DEFAULT_SAE_PWE;
#ifdef CONFIG_MACSEC
        ssid->mka_priority = DEFAULT_PRIO_NOT_KEY_SERVER;
#endif /* CONFIG_MACSEC */
        ssid->mac_addr = -1;
        ssid->max_oper_chwidth = DEFAULT_MAX_OPER_CHWIDTH;
}

scan_list_bss_info_t* wpa_supplicant_add_network(struct wpa_supplicant *wpa_s, scan_list_bss_info_t *scan_bss_info)
{
#if 0
        struct wpa_ssid *ssid = NULL;

        //ssid = wpa_config_add_network(wpa_s->conf);
        if (!ssid)
                return NULL;
        wpas_notify_network_added(wpa_s, ssid);
        ssid->disabled = 1;
        wpa_config_set_network_defaults(ssid);

#endif
        scan_list_bss_info_t *arg_scan_bss_info = malloc(sizeof(scan_list_bss_info_t));
	if (arg_scan_bss_info == NULL) {
            return NULL;
	}

        memcpy(arg_scan_bss_info, scan_bss_info, sizeof(scan_list_bss_info_t));

        wpas_notify_network_added(wpa_s, arg_scan_bss_info);
        //wpa_config_set_network_defaults(ssid);

        return arg_scan_bss_info;
}

DBusMessage *dbus_error_unknown_error(DBusMessage *message,
                                            const char *arg)
{
        return dbus_message_new_error(message, WPAS_DBUS_ERROR_UNKNOWN_ERROR,
                                      arg);
}

int hex_to_string(const char *hex_str, char *str) {
    int len = strlen(hex_str);
    if (len % 2 != 0) {
        // Handle invalid input (odd number of hex digits)
        return RETURN_ERR;
    }

    int i, j;
    for (i = 0, j = 0; i < len; i += 2) {
        char hex_byte[3] = {hex_str[i], hex_str[i+1], '\0'}; 
        char byte = (char)strtol(hex_byte, NULL, 16); // Convert hex pair to byte
        str[j++] = byte;
    }
    str[j] = '\0'; // Null-terminate the string

    return RETURN_OK;
}

#define BYTE_ARRAY_CHUNK_SIZE 34
#define BYTE_ARRAY_ITEM_SIZE (sizeof(char))

static dbus_bool_t _wpa_dbus_dict_entry_get_byte_array(
        DBusMessageIter *iter, struct wpa_dbus_dict_entry *entry)
{
        dbus_uint32_t count = 0;
        dbus_bool_t success = FALSE;
        char *buffer, *nbuffer;

        entry->bytearray_value = NULL;
        entry->array_type = DBUS_TYPE_BYTE;

        buffer = os_calloc(BYTE_ARRAY_CHUNK_SIZE, BYTE_ARRAY_ITEM_SIZE);
        if (!buffer)
                return FALSE;

        entry->array_len = 0;
        while (dbus_message_iter_get_arg_type(iter) == DBUS_TYPE_BYTE) {
                char byte;

                if ((count % BYTE_ARRAY_CHUNK_SIZE) == 0 && count != 0) {
                        nbuffer = os_realloc_array(
                                buffer, count + BYTE_ARRAY_CHUNK_SIZE,
                                BYTE_ARRAY_ITEM_SIZE);
                        if (nbuffer == NULL) {
                                os_free(buffer);
                                wpa_printf(MSG_ERROR,
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

#define STR_ARRAY_CHUNK_SIZE 8
#define STR_ARRAY_ITEM_SIZE (sizeof(char *))

static dbus_bool_t dbus_dict_entry_get_string_array(
        DBusMessageIter *iter, int array_type,
        struct wpa_dbus_dict_entry *entry)
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
                                wpa_printf(MSG_ERROR,
                                           "dbus: %s out of memory trying to retrieve the string array",
                                           __func__);
                                goto fail;
                        }
                        buffer = nbuffer;
                }

                dbus_message_iter_get_basic(iter, &value);
                wpa_printf(MSG_MSGDUMP, "%s: string_array value: %s",
                           __func__, wpa_debug_show_keys ? value : "[omitted]");
                str = os_strdup(value);
                if (str == NULL) {
                        wpa_printf(MSG_ERROR,
                                   "dbus: %s out of memory trying to duplicate the string array",
                                   __func__);
                        goto fail;
                }
                buffer[count++] = str;
                dbus_message_iter_next(iter);
        }
        entry->strarray_value = buffer;
        entry->array_len = count;
        wpa_printf(MSG_MSGDUMP, "%s: string_array length %u",
                   __func__, entry->array_len);

        /* Zero-length arrays are valid. */
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

#define BIN_ARRAY_CHUNK_SIZE 10
#define BIN_ARRAY_ITEM_SIZE (sizeof(struct wpabuf *))

void dbus_dict_entry_clear(struct wpa_dbus_dict_entry *entry)
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
                case WPAS_DBUS_TYPE_BINARRAY:
                        for (i = 0; i < entry->array_len; i++)
                                wpabuf_free(entry->binarray_value[i]);
                        os_free(entry->binarray_value);
                        break;
                }
                break;
        }

        os_memset(entry, 0, sizeof(struct wpa_dbus_dict_entry));
}

static dbus_bool_t dbus_dict_entry_get_binarray(
        DBusMessageIter *iter, struct wpa_dbus_dict_entry *entry)
{
        struct wpa_dbus_dict_entry tmpentry;
        size_t buflen = 0;
        int i, type;

        entry->array_type = WPAS_DBUS_TYPE_BINARRAY;
        entry->array_len = 0;
        entry->binarray_value = NULL;

        type = dbus_message_iter_get_arg_type(iter);
        wpa_printf(MSG_MSGDUMP, "%s: parsing binarray type %c", __func__, type);
        if (type == DBUS_TYPE_INVALID) {
                /* Likely an empty array of arrays */
                return TRUE;
        }
        if (type != DBUS_TYPE_ARRAY) {
                wpa_printf(MSG_DEBUG, "%s: not an array type: %c",
                           __func__, type);
                return FALSE;
        }

        type = dbus_message_iter_get_element_type(iter);
        if (type != DBUS_TYPE_BYTE) {
                wpa_printf(MSG_DEBUG, "%s: unexpected element type %c",
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
                if (_wpa_dbus_dict_entry_get_byte_array(&iter_array, &tmpentry)
                    == FALSE)
                        goto cleanup;

                entry->binarray_value[entry->array_len] =
                        wpabuf_alloc_ext_data((uint8_t *) tmpentry.bytearray_value,
                                              tmpentry.array_len);
                if (entry->binarray_value[entry->array_len] == NULL) {
                        dbus_dict_entry_clear(&tmpentry);
                        goto cleanup;
                }
                entry->array_len++;
                dbus_message_iter_next(iter);
        }
        wpa_printf(MSG_MSGDUMP, "%s: binarray length %u",
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

static dbus_bool_t dbus_dict_entry_get_array(
        DBusMessageIter *iter_dict_val, struct wpa_dbus_dict_entry *entry)
{
        int array_type = dbus_message_iter_get_element_type(iter_dict_val);
        dbus_bool_t success = FALSE;
        DBusMessageIter iter_array;

        wpa_printf(MSG_MSGDUMP, "%s: array_type %c", __func__, array_type);

        dbus_message_iter_recurse(iter_dict_val, &iter_array);

        switch (array_type) {
        case DBUS_TYPE_BYTE:
                success = _wpa_dbus_dict_entry_get_byte_array(&iter_array,
                                                              entry);
                break;
        case DBUS_TYPE_STRING:
                success = dbus_dict_entry_get_string_array(&iter_array,
                                                                array_type,
                                                                entry);
                break;
        case DBUS_TYPE_ARRAY:
                success = dbus_dict_entry_get_binarray(&iter_array, entry);
                break;
        default:
                wpa_printf(MSG_MSGDUMP, "%s: unsupported array type %c",
                           __func__, array_type);
                break;
        }

        return success;
}

static dbus_bool_t dbus_dict_fill_value_from_variant(
        struct wpa_dbus_dict_entry *entry, DBusMessageIter *iter)
{
        const char *v;

        switch (entry->type) {
        case DBUS_TYPE_OBJECT_PATH:
                dbus_message_iter_get_basic(iter, &v);
                wpa_printf(MSG_MSGDUMP, "%s: object path value: %s",
                           __func__, v);
                entry->str_value = os_strdup(v);
                if (entry->str_value == NULL)
                        return FALSE;
                break;
        case DBUS_TYPE_STRING:
                dbus_message_iter_get_basic(iter, &v);
                wpa_printf(MSG_MSGDUMP, "%s: string value: %s",
                           __func__, wpa_debug_show_keys ? v : "[omitted]");
                entry->str_value = os_strdup(v);
                if (entry->str_value == NULL)
                        return FALSE;
                break;
        case DBUS_TYPE_BOOLEAN:
                dbus_message_iter_get_basic(iter, &entry->bool_value);
                wpa_printf(MSG_MSGDUMP, "%s: boolean value: %d",
                           __func__, entry->bool_value);
                break;
        case DBUS_TYPE_BYTE:
                dbus_message_iter_get_basic(iter, &entry->byte_value);
                wpa_printf(MSG_MSGDUMP, "%s: byte value: %d",
                           __func__, entry->byte_value);
                break;
        case DBUS_TYPE_INT16:
                dbus_message_iter_get_basic(iter, &entry->int16_value);
                wpa_printf(MSG_MSGDUMP, "%s: int16 value: %d",
                           __func__, entry->int16_value);
                break;
        case DBUS_TYPE_UINT16:
                dbus_message_iter_get_basic(iter, &entry->uint16_value);
                wpa_printf(MSG_MSGDUMP, "%s: uint16 value: %d",
                           __func__, entry->uint16_value);
                break;
        case DBUS_TYPE_INT32:
                dbus_message_iter_get_basic(iter, &entry->int32_value);
                wpa_printf(MSG_MSGDUMP, "%s: int32 value: %d",
                           __func__, entry->int32_value);
                break;
        case DBUS_TYPE_UINT32:
                dbus_message_iter_get_basic(iter, &entry->uint32_value);
                wpa_printf(MSG_MSGDUMP, "%s: uint32 value: %d",
                           __func__, entry->uint32_value);
                break;
        case DBUS_TYPE_INT64:
                dbus_message_iter_get_basic(iter, &entry->int64_value);
                wpa_printf(MSG_MSGDUMP, "%s: int64 value: %lld",
                           __func__, (long long int) entry->int64_value);
                break;
        case DBUS_TYPE_UINT64:
                dbus_message_iter_get_basic(iter, &entry->uint64_value);
                wpa_printf(MSG_MSGDUMP, "%s: uint64 value: %llu",
                           __func__,
                           (unsigned long long int) entry->uint64_value);
                break;
        case DBUS_TYPE_DOUBLE:
                dbus_message_iter_get_basic(iter, &entry->double_value);
                wpa_printf(MSG_MSGDUMP, "%s: double value: %f",
                           __func__, entry->double_value);
                break;
        case DBUS_TYPE_ARRAY:
                return dbus_dict_entry_get_array(iter, entry);
        default:
                wpa_printf(MSG_MSGDUMP, "%s: unsupported type %c",
                           __func__, entry->type);
                return FALSE;
        }

        return TRUE;
}

dbus_bool_t wpa_dbus_dict_get_entry(DBusMessageIter *iter_dict,
                                    struct wpa_dbus_dict_entry * entry)
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
        if (!dbus_dict_fill_value_from_variant(entry, &iter_dict_val)) {
                printf(
                           "%s: failed to fetch dict values from variant",
                           __func__);
                goto error;
        }

        dbus_message_iter_next(iter_dict);
        return TRUE;

error:
        if (entry) {
                dbus_dict_entry_clear(entry);
                entry->type = DBUS_TYPE_INVALID;
                entry->array_type = DBUS_TYPE_INVALID;
        }

        return FALSE;
}

dbus_bool_t dbus_dict_open_read(DBusMessageIter *iter,
                                    DBusMessageIter *iter_dict,
                                    DBusError *error)
{
        int type;

        wpa_printf(MSG_MSGDUMP, "%s: start reading a dict entry", __func__);
        if (!iter || !iter_dict) {
                dbus_set_error_const(error, DBUS_ERROR_FAILED,
                                     "[internal] missing message iterators");
                return FALSE;
        }

        type = dbus_message_iter_get_arg_type(iter);
        if (type != DBUS_TYPE_ARRAY ||
            dbus_message_iter_get_element_type(iter) != DBUS_TYPE_DICT_ENTRY) {
                wpa_printf(MSG_DEBUG,
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

static const char * const dont_quote[] = {
        "key_mgmt", "proto", "pairwise", "auth_alg", "group", "eap",
        "bssid", "scan_freq", "freq_list", "scan_ssid", "bssid_hint",
        "bssid_ignore", "bssid_accept", /* deprecated aliases */
        "bssid_blacklist", "bssid_whitelist",
        "group_mgmt",
        "ignore_broadcast_ssid",
#ifdef CONFIG_MESH
        "mesh_basic_rates",
#endif /* CONFIG_MESH */
#ifdef CONFIG_P2P
        "go_p2p_dev_addr", "p2p_client_list", "psk_list",
#endif /* CONFIG_P2P */
#ifdef CONFIG_INTERWORKING
        "roaming_consortium", "required_roaming_consortium",
#endif /* CONFIG_INTERWORKING */
        NULL
};

static dbus_bool_t should_quote_opt(const char *key)
{
        int i = 0;

        while (dont_quote[i] != NULL) {
                if (os_strcmp(key, dont_quote[i]) == 0)
                        return FALSE;
                i++;
        }
        return TRUE;
}

dbus_bool_t dbus_dict_has_dict_entry(DBusMessageIter *iter_dict)
{
        if (!iter_dict)
                return FALSE;
        return dbus_message_iter_get_arg_type(iter_dict) ==
                DBUS_TYPE_DICT_ENTRY;
}

/* 
 * IMP: 
 * THIS IS CUSTOMIZED CODE COMPARED TO WPA_SUPPLICANT
*/
dbus_bool_t set_network_properties(struct wpa_supplicant *wpa_s,
                                   //struct wpa_ssid *ssid,
                                   network_mgr_cfg_t *scan_ssid_info,
                                   DBusMessageIter *iter,
                                   DBusError *error)
{
        struct wpa_dbus_dict_entry entry = { .type = DBUS_TYPE_STRING };
        DBusMessageIter iter_dict;
        char *value = NULL;

        if (!dbus_dict_open_read(iter, &iter_dict, error))
                return FALSE;

        while (dbus_dict_has_dict_entry(&iter_dict)) {
                size_t size = 50;
                int ret;

                if (!wpa_dbus_dict_get_entry(&iter_dict, &entry))
                        goto error;

                value = NULL;
                if (entry.type == DBUS_TYPE_ARRAY &&
                    entry.array_type == DBUS_TYPE_BYTE) {
                        if (entry.array_len <= 0)
                                goto error;

                        size = entry.array_len * 2 + 1;
                        value = os_zalloc(size);
                        if (value == NULL)
                                goto error;

                        ret = wpa_snprintf_hex(value, size,
                                               (uint8_t *) entry.bytearray_value,
                                               entry.array_len);
                        if (ret <= 0)
                                goto error;
                } else if (entry.type == DBUS_TYPE_STRING) {
                        if (should_quote_opt(entry.key)) {
                                size = os_strlen(entry.str_value);

                                size += 3;
                                value = os_zalloc(size);
                                if (value == NULL)
                                        goto error;

                                ret = os_snprintf(value, size, "\"%s\"",
                                                  entry.str_value);
                                if (os_snprintf_error(size, ret))
                                        goto error;
                        } else {
                                value = os_strdup(entry.str_value);
                                if (value == NULL)
                                        goto error;
                        }
                } else if (entry.type == DBUS_TYPE_UINT32) {
                        value = os_zalloc(size);
                        if (value == NULL)
                                goto error;

                        ret = os_snprintf(value, size, "%u",
                                          entry.uint32_value);
                        if (os_snprintf_error(size, ret))
                                goto error;
                } else if (entry.type == DBUS_TYPE_INT32) {
                        value = os_zalloc(size);
                        if (value == NULL)
                                goto error;

                        ret = os_snprintf(value, size, "%d",
                                          entry.int32_value);
                        if (os_snprintf_error(size, ret))
                                goto error;
                } else
                        goto error;

#if 0
                ret = wpa_config_set(ssid, entry.key, value, 0);
                if (ret < 0)
                        goto error;
                if (ret == 1)
                        goto skip_update;
#ifdef CONFIG_BGSCAN
                if (os_strcmp(entry.key, "bgscan") == 0) {
                        /*
                         * Reset the bgscan parameters for the current network
                         * and continue. There's no need to flush caches for
                         * bgscan parameter changes.
                         */
                        if (wpa_s->current_ssid == ssid &&
                            wpa_s->wpa_state == WPA_COMPLETED)
                                wpa_supplicant_reset_bgscan(wpa_s);
                        os_free(value);
                        value = NULL;
                        dbus_dict_entry_clear(&entry);
                        continue;
                }
#endif /* CONFIG_BGSCAN */

                if (os_strcmp(entry.key, "bssid") != 0 &&
                    os_strcmp(entry.key, "priority") != 0)
                        wpa_sm_pmksa_cache_flush(wpa_s->wpa, ssid);

                if (wpa_s->current_ssid == ssid ||
                    wpa_s->current_ssid == NULL) {
                        /*
                         * Invalidate the EAP session cache if anything in the
                         * current or previously used configuration changes.
                         */
                        eapol_sm_invalidate_cached_session(wpa_s->eapol);
                }

                if ((os_strcmp(entry.key, "psk") == 0 &&
                     value[0] == '"' && ssid->ssid_len) ||
                    (os_strcmp(entry.key, "ssid") == 0 && ssid->passphrase))
                        wpa_config_update_psk(ssid);
                else if (os_strcmp(entry.key, "priority") == 0)
                        wpa_config_update_prio_list(wpa_s->conf);
#else
		if (entry.type == DBUS_TYPE_ARRAY) {
                    char buff[64] = { 0 };
			hex_to_string(value, buff);

                     if (!strcmp(entry.key, "ssid")) {
                         strcpy(scan_ssid_info->ssid , buff);
		     } else if (!strcmp(entry.key, "bgscan")) {
                         strcpy(scan_ssid_info->bgscan , buff);
		     }
                } else if (entry.type == DBUS_TYPE_STRING) {
                    if (!strcmp(entry.key, "key_mgmt")) {
                        strcpy(scan_ssid_info->security_type, value);
		    } else if (!strcmp(entry.key, "psk")) {
			strcpy(scan_ssid_info->password, value);
		    }
		} else if (entry.type == DBUS_TYPE_INT32) {
                    if (!strcmp(entry.key, "scan_ssid")) {
                        scan_ssid_info->scan_ssid = atoi(value);
		        printf("scan_ssid_info->scan_ssid:%d\r\n", scan_ssid_info->scan_ssid);
		    }
		} else {
                    printf("unknown event type:%d\r\n", entry.type);
		}
#endif
	
        skip_update:
                os_free(value);
                value = NULL;
                dbus_dict_entry_clear(&entry);
        }

        return TRUE;

error:
        os_free(value);
        dbus_dict_entry_clear(&entry);
        dbus_set_error_const(error, DBUS_ERROR_INVALID_ARGS,
                             "invalid message format");
        return FALSE;
}

int fetch_bss_info(struct wpa_supplicant *wpa_s, network_mgr_cfg_t *add_ssid_cfg, scan_list_bss_info_t *scan_bss_info)
{
        struct wpa_bss *bss;
        dl_list_for_each(bss, &wpa_s->bss, struct wpa_bss, list) {
		printf("In fetch_bss_info for ssid:%s, cfg_ssid:%s\n", bss->ssid, add_ssid_cfg->ssid);
                if (strcmp(bss->ssid, add_ssid_cfg->ssid) == 0) {
                    memcpy(scan_bss_info, &bss->scan_bss_info, sizeof(scan_list_bss_info_t));
		    strcpy(scan_bss_info->password, add_ssid_cfg->password);
                    return RETURN_OK;
		}
        }  

        return RETURN_ERR;
}

/* 
 * IMP: 
 * THIS IS CUSTOMIZED CODE COMPARED TO WPA_SUPPLICANT
*/
DBusMessage * dbus_handler_add_network(DBusMessage *message,
                                            struct wpa_supplicant *wpa_s)
{
        DBusMessage *reply = NULL;
        DBusMessageIter iter;
        struct wpa_ssid *ssid = NULL;
        char path_buf[WPAS_DBUS_OBJECT_PATH_MAX], *path = path_buf;
        DBusError error;
        network_mgr_cfg_t add_ssid_cfg = { 0 };
        scan_list_bss_info_t scan_bss_info = { 0 };
        scan_list_bss_info_t *p_arg_scan_bss_info = NULL;

	if (!wpa_s) {
		printf("wpa_s is NULL\n");
		return;
	} else {
	        printf("\n\nIn dbus_handler_add_network---->dbus_new_path:%s\n", wpa_s->dbus_new_path);
	}

        dbus_message_iter_init(message, &iter);

        dbus_error_init(&error);
        if (!set_network_properties(wpa_s, &add_ssid_cfg, &iter, &error)) {
                 printf("\r\n%s[dbus]: control interface couldn't set network properties\r\n", __func__);
                 reply = dbus_reply_new_from_error(message, &error,
                                                        DBUS_ERROR_INVALID_ARGS,
                                                        "Failed to add network");
                 dbus_error_free(&error);
                 goto err; 
         }

        fetch_bss_info(wpa_s, &add_ssid_cfg, &scan_bss_info);

        if (wpa_s->dbus_new_path)
                p_arg_scan_bss_info = wpa_supplicant_add_network(wpa_s, &scan_bss_info);
#if 0
        if (ssid == NULL) {
                wpa_printf(MSG_ERROR, "%s[dbus]: can't add new interface.",
                           __func__);
                reply = dbus_error_unknown_error(
                        message,
                        "wpa_supplicant could not add a network on this interface.");
                goto err; 
        }    
#endif
#if 0
        dbus_error_init(&error);
        if (!set_network_properties(wpa_s, ssid, &iter, &error)) {
                printf(
                           "%s[dbus]: control interface couldn't set network properties",
                           __func__);
                reply = dbus_reply_new_from_error(message, &error,
                                                       DBUS_ERROR_INVALID_ARGS,
                                                       "Failed to add network");
                dbus_error_free(&error);
                goto err; 
        }    
#endif

        /* Construct the object path for this network. */
        os_snprintf(path, WPAS_DBUS_OBJECT_PATH_MAX,
                    "%s/" WPAS_DBUS_NEW_NETWORKS_PART "/%d",
                    wpa_s->dbus_new_path, p_arg_scan_bss_info->network_ssid_id);

        reply = dbus_message_new_method_return(message);
        if (reply == NULL) {
                reply = dbus_error_no_memory(message);
                goto err; 
        }    
        if (!dbus_message_append_args(reply, DBUS_TYPE_OBJECT_PATH, &path,
                                      DBUS_TYPE_INVALID)) {
                dbus_message_unref(reply);
                reply = dbus_error_no_memory(message);
                goto err; 
        }

        p_arg_scan_bss_info->network_ssid_id++;
        wpa_s->p_scan_bss_info = p_arg_scan_bss_info;
	return reply;

err:
        if (ssid) {
//                wpas_notify_network_removed(wpa_s, ssid);
//                wpa_config_remove_network(wpa_s->conf, ssid->id);
        }
        return reply;
}

static DBusMessage * dbus_error_scan_error(DBusMessage *message,
                                                const char *error)
{
        return dbus_message_new_error(message,
                                      WPAS_DBUS_ERROR_IFACE_SCAN_ERROR,
                                      error);
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

                } else if (strcmp(key, "SSIDs") == 0) { 
                        if (dbus_get_scan_ssids(message, &variant_iter,
                                                     &params, &reply) < 0) 
                                goto out; 
                } else if (strcmp(key, "IEs") == 0) { 
                        if (dbus_get_scan_ies(message, &variant_iter,
                                                   &params, &reply) < 0) 
                                goto out; 
                } else if (strcmp(key, "Channels") == 0) { 
                        if (wpas_dbus_get_scan_channels(message, &variant_iter,
                                                        &params, &reply) < 0) 
                                goto out; 
                } else if (strcmp(key, "AllowRoam") == 0) { 
                        if (dbus_get_scan_allow_roam(message,
                                                          &variant_iter,
                                                          &allow_roam,
                                                          &reply) < 0) 
                                goto out; 
#endif
                } else {
                        printf( "%s[dbus]: Unknown argument %s",
                                   __func__, key);
                        // reply = dbus_error_invalid_args(message, key);
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
	static bool scan_flag = 0;

    	ctrl = (wifi_ctrl_t *)get_wifictrl_obj();
	svc = get_svc_by_type(ctrl, vap_svc_type_sta);
	if (scan_flag == 0) {
	   printf("SCAN START...\n");
	   sta_start_scan(svc);
	} else {
	   printf("SCAN IN PRGORESS. REJECT\n");
           reply = dbus_error_scan_error(message, "Scan request rejected");	  
	}
	//scan_flag = 1;
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

	printf("Before crash\n");
        if (!dbus_message_iter_open_container(iter, DBUS_TYPE_VARIANT,
                                              dbus_type_as_string(type),
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


int wpa_config_get_value(const char *name, struct wpa_config *config,
                         char *buf, size_t buflen)
{
        size_t i;

	printf("In wpa_config_get_value!!\n");
#if 0
        for (i = 0; i < NUM_GLOBAL_FIELDS; i++) {
                const struct global_parse_data *field = &global_fields[i];

                if (os_strcmp(name, field->name) != 0)
                        continue;
                if (!field->get)
                        break;
                return field->get(name, config, (long) field->param1,
                                  buf, buflen, 0);
        }
	return field->get(name, config, (long) field->param1, buf, buflen, 0);
#endif
	return 0;
}

void wpa_supplicant_update_config(struct wpa_supplicant *wpa_s)
{
    return 0;
}

int wpa_config_process_global(struct wpa_config *config, char *pos, int line)
{
    return 0;
}

dbus_bool_t dbus_getter_iface_global(
        const struct wpa_dbus_property_desc *property_desc,
        DBusMessageIter *iter, DBusError *error, void *user_data)
{
        struct wpa_supplicant *wpa_s = user_data;
        int ret;
        char buf[250];
        char *p = buf;

#if 1
        if (!property_desc->data) {
                dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
                               "Unhandled interface property %s",
                               property_desc->dbus_property);
                return FALSE;
        }

        ret = wpa_config_get_value(property_desc->data, "hello", buf,
                                   sizeof(buf));

//        ret = wpa_config_get_value(property_desc->data, wpa_s->conf, buf,
  //                                 sizeof(buf));
        if (ret < 0)
                *p = '\0';

        return dbus_simple_property_getter(iter, DBUS_TYPE_STRING, &p,
                                                error);
#else
	return 0;
#endif
}

dbus_bool_t dbus_setter_iface_global(
        const struct wpa_dbus_property_desc *property_desc,
        DBusMessageIter *iter, DBusError *error, void *user_data)
{
        struct wpa_supplicant *wpa_s = user_data;
        const char *new_value = NULL;
        char buf[250];
        size_t combined_len;
        int ret;

        if (!dbus_simple_property_setter(iter, error, DBUS_TYPE_STRING,
                                              &new_value))
                return FALSE;

        combined_len = os_strlen(property_desc->data) + os_strlen(new_value) +
                3;
        if (combined_len >= sizeof(buf)) {
                dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
                               "Interface property %s value too large",
                               property_desc->dbus_property);
                return FALSE;
        }

        if (!new_value[0])
                new_value = "NULL";

        ret = os_snprintf(buf, combined_len, "%s=%s", property_desc->data,
                          new_value);
        if (os_snprintf_error(combined_len, ret)) {
                dbus_set_error(error,  WPAS_DBUS_ERROR_UNKNOWN_ERROR,
                               "Failed to construct new interface property %s",
                               property_desc->dbus_property);
                return FALSE;
        }

        ret = wpa_config_process_global("Hello", buf, -1);
        //ret = wpa_config_process_global(wpa_s->conf, buf, -1);
        if (ret < 0) {
                dbus_set_error(error, DBUS_ERROR_INVALID_ARGS,
                               "Failed to set interface property %s",
                               property_desc->dbus_property);
                return FALSE;
        } else if (ret == 0) {
                wpa_supplicant_update_config(wpa_s);
        }
        return TRUE;
}

#if 0
dbus_bool_t dbus_getter_networks(
        const struct wpa_dbus_property_desc *property_desc,
        DBusMessageIter *iter, DBusError *error, void *user_data)
{
        struct wpa_supplicant *wpa_s = user_data;
        struct wpa_ssid *ssid;
        char **paths;
        unsigned int i = 0, num = 0;
        dbus_bool_t success = FALSE;

        if (!wpa_s->dbus_new_path) {
                dbus_set_error(error, DBUS_ERROR_FAILED,
                               "%s: no D-Bus interface", __func__);
                return FALSE;
        }

#if 0
        for (ssid = wpa_s->conf->ssid; ssid; ssid = ssid->next)
                if (!network_is_persistent_group(ssid))
                        num++;
#endif

        paths = os_calloc(num, sizeof(char *));
        if (!paths) {
                dbus_set_error(error, DBUS_ERROR_NO_MEMORY, "no memory");
                return FALSE;
        }

#if 0
        /* Loop through configured networks and append object path of each */
        for (ssid = wpa_s->conf->ssid; ssid; ssid = ssid->next) {
                if (network_is_persistent_group(ssid))
                        continue;
                paths[i] = os_zalloc(WPAS_DBUS_OBJECT_PATH_MAX);
                if (paths[i] == NULL) {
                        dbus_set_error(error, DBUS_ERROR_NO_MEMORY,
                                       "no memory");
                        goto out;
                }

                /* Construct the object path for this network. */
                os_snprintf(paths[i++], WPAS_DBUS_OBJECT_PATH_MAX,
                            "%s/" WPAS_DBUS_NEW_NETWORKS_PART "/%d",
                            wpa_s->dbus_new_path, ssid->id);
        }
#endif
        success = dbus_simple_array_property_getter(iter,
                                                         DBUS_TYPE_OBJECT_PATH,
                                                         paths, num, error);

out:
        while (i)
                os_free(paths[--i]);
        os_free(paths);
        return success;
}

dbus_bool_t dbus_getter_bsss(
        const struct wpa_dbus_property_desc *property_desc,
        DBusMessageIter *iter, DBusError *error, void *user_data)
{
        struct wpa_supplicant *wpa_s = user_data;
        struct wpa_bss *bss;
        char **paths;
        unsigned int i = 0;
        dbus_bool_t success = FALSE;

        if (!wpa_s->dbus_new_path) {
                dbus_set_error(error, DBUS_ERROR_FAILED,
                               "%s: no D-Bus interface", __func__);
                return FALSE;
        }

        paths = os_calloc(wpa_s->num_bss, sizeof(char *));
        if (!paths) {
                dbus_set_error_const(error, DBUS_ERROR_NO_MEMORY, "no memory");
                return FALSE;
        }

        /* Loop through scan results and append each result's object path */
        dl_list_for_each(bss, &wpa_s->bss_id, struct wpa_bss, list_id) {
                paths[i] = os_zalloc(WPAS_DBUS_OBJECT_PATH_MAX);
                if (paths[i] == NULL) {
                        dbus_set_error_const(error, DBUS_ERROR_NO_MEMORY,
                                             "no memory");
                        goto out;
                }
                /* Construct the object path for this BSS. */
                os_snprintf(paths[i++], WPAS_DBUS_OBJECT_PATH_MAX,
                            "%s/" WPAS_DBUS_NEW_BSSIDS_PART "/%u",
                            wpa_s->dbus_new_path, bss->id);
        }

        success = dbus_simple_array_property_getter(iter,
                                                         DBUS_TYPE_OBJECT_PATH,
                                                         paths, wpa_s->num_bss,
                                                         error);

out:
        while (i)
                os_free(paths[--i]);
        os_free(paths);
        return success;
}

dbus_bool_t dbus_getter_blobs(
        const struct wpa_dbus_property_desc *property_desc,
        DBusMessageIter *iter, DBusError *error, void *user_data)
{
        struct wpa_supplicant *wpa_s = user_data;
        DBusMessageIter variant_iter, dict_iter, entry_iter, array_iter;
        struct wpa_config_blob *blob;

        if (!dbus_message_iter_open_container(iter, DBUS_TYPE_VARIANT,
                                              "a{say}", &variant_iter) ||
            !dbus_message_iter_open_container(&variant_iter, DBUS_TYPE_ARRAY,
                                              "{say}", &dict_iter)) {
                dbus_set_error_const(error, DBUS_ERROR_NO_MEMORY, "no memory");
                return FALSE;
        }

#if 0
        blob = wpa_s->conf->blobs;
        while (blob) {
                if (!dbus_message_iter_open_container(&dict_iter,
                                                      DBUS_TYPE_DICT_ENTRY,
                                                      NULL, &entry_iter) ||
                    !dbus_message_iter_append_basic(&entry_iter,
                                                    DBUS_TYPE_STRING,
                                                    &(blob->name)) ||
                    !dbus_message_iter_open_container(&entry_iter,
                                                      DBUS_TYPE_ARRAY,
                                                      DBUS_TYPE_BYTE_AS_STRING,
                                                      &array_iter) ||
                    !dbus_message_iter_append_fixed_array(&array_iter,
                                                          DBUS_TYPE_BYTE,
                                                          &(blob->data),
                                                          blob->len) ||
                    !dbus_message_iter_close_container(&entry_iter,
                                                       &array_iter) ||
                    !dbus_message_iter_close_container(&dict_iter,
                                                       &entry_iter)) {
                        dbus_set_error_const(error, DBUS_ERROR_NO_MEMORY,
                                             "no memory");
                        return FALSE;
                }

                blob = blob->next;
        }
#endif
        if (!dbus_message_iter_close_container(&variant_iter, &dict_iter) ||
            !dbus_message_iter_close_container(iter, &variant_iter)) {
                dbus_set_error_const(error, DBUS_ERROR_NO_MEMORY, "no memory");
                return FALSE;
        }

        return TRUE;
}

dbus_bool_t dbus_getter_current_auth_mode(
        const struct wpa_dbus_property_desc *property_desc,
        DBusMessageIter *iter, DBusError *error, void *user_data)
{
        struct wpa_supplicant *wpa_s = user_data;
        const char *eap_mode;
        const char *auth_mode;
        char eap_mode_buf[WPAS_DBUS_AUTH_MODE_MAX];

#if 0
        if (wpa_s->wpa_state <= WPA_SCANNING) {
                auth_mode = "INACTIVE";
        } else if (wpa_s->key_mgmt == WPA_KEY_MGMT_IEEE8021X ||
            wpa_s->key_mgmt == WPA_KEY_MGMT_IEEE8021X_NO_WPA) {
                eap_mode = wpa_supplicant_get_eap_mode(wpa_s);
                os_snprintf(eap_mode_buf, WPAS_DBUS_AUTH_MODE_MAX,
                            "EAP-%s", eap_mode);
                auth_mode = eap_mode_buf;

        } else if (wpa_s->current_ssid) {
                auth_mode = wpa_key_mgmt_txt(wpa_s->key_mgmt,
                                             wpa_s->current_ssid->proto);
        } else {
                auth_mode = "UNKNOWN";
        }
#endif
        return dbus_simple_property_getter(iter, DBUS_TYPE_STRING,
                                                &auth_mode, error);
}


dbus_bool_t dbus_getter_current_network(
        const struct wpa_dbus_property_desc *property_desc,
        DBusMessageIter *iter, DBusError *error, void *user_data)
{
        struct wpa_supplicant *wpa_s = user_data;
        char path_buf[WPAS_DBUS_OBJECT_PATH_MAX], *net_obj_path = path_buf;

#if 0
        if (wpa_s->current_ssid && wpa_s->dbus_new_path)
                os_snprintf(net_obj_path, WPAS_DBUS_OBJECT_PATH_MAX,
                            "%s/" WPAS_DBUS_NEW_NETWORKS_PART "/%u",
                            wpa_s->dbus_new_path, wpa_s->current_ssid->id);
        else
                os_snprintf(net_obj_path, WPAS_DBUS_OBJECT_PATH_MAX, "/");
#endif

        return dbus_simple_property_getter(iter, DBUS_TYPE_OBJECT_PATH,
                                                &net_obj_path, error);
}

dbus_bool_t dbus_getter_current_bss(
        const struct wpa_dbus_property_desc *property_desc,
        DBusMessageIter *iter, DBusError *error, void *user_data)
{
        struct wpa_supplicant *wpa_s = user_data;
        char path_buf[WPAS_DBUS_OBJECT_PATH_MAX], *bss_obj_path = path_buf;

#if 0
        if (wpa_s->current_bss && wpa_s->dbus_new_path)
                os_snprintf(bss_obj_path, WPAS_DBUS_OBJECT_PATH_MAX,
                            "%s/" WPAS_DBUS_NEW_BSSIDS_PART "/%u",
                            wpa_s->dbus_new_path, wpa_s->current_bss->id);
        else
                os_snprintf(bss_obj_path, WPAS_DBUS_OBJECT_PATH_MAX, "/");
#endif

        return dbus_simple_property_getter(iter, DBUS_TYPE_OBJECT_PATH,
                                                &bss_obj_path, error);
}

dbus_bool_t dbus_string_property_getter(DBusMessageIter *iter,
                                             const void *val,
                                             DBusError *error)
{
        if (!val)
                val = "";
        return dbus_simple_property_getter(iter, DBUS_TYPE_STRING,
                                                &val, error);
}


dbus_bool_t dbus_getter_config_file(
        const struct wpa_dbus_property_desc *property_desc,
        DBusMessageIter *iter, DBusError *error, void *user_data)
{
        struct wpa_supplicant *wpa_s = user_data;

        return;
        //return dbus_string_property_getter(iter, wpa_s->confname, error);
}
#endif

dbus_bool_t dbus_getter_bridge_ifname(
        const struct wpa_dbus_property_desc *property_desc,
        DBusMessageIter *iter, DBusError *error, void *user_data)
{
	printf("In dbus_getter_bridge_ifname=========\n");
        struct wpa_supplicant *wpa_s = user_data;

        return;
        //return dbus_string_property_getter(iter, wpa_s->bridge_ifname, error);
}

dbus_bool_t dbus_simple_property_setter(DBusMessageIter *iter,
                                             DBusError *error,
                                             const int type, void *val)
{
        DBusMessageIter variant_iter;

	printf("1. In dbus_simple_property_setter\n");
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
	printf("2. In dbus_simple_property_setter\n");

	
        return TRUE;
}

int wpa_supplicant_update_bridge_ifname(struct wpa_supplicant *wpa_s,
                                        const char *bridge_ifname)
{
#if 0
        if (wpa_s->wpa_state > WPA_SCANNING)
                return -EBUSY;

        if (bridge_ifname &&
            os_strlen(bridge_ifname) >= sizeof(wpa_s->bridge_ifname))
                return -EINVAL;

        if (!bridge_ifname)
                bridge_ifname = "";

        if (os_strcmp(wpa_s->bridge_ifname, bridge_ifname) == 0)
                return 0;

        if (wpa_s->l2_br) {
                l2_packet_deinit(wpa_s->l2_br);
                wpa_s->l2_br = NULL;
        }

        os_strlcpy(wpa_s->bridge_ifname, bridge_ifname,
                   sizeof(wpa_s->bridge_ifname));

        if (wpa_s->bridge_ifname[0]) {
                wpa_dbg(wpa_s, MSG_DEBUG,
                        "Receiving packets from bridge interface '%s'",
                        wpa_s->bridge_ifname);
                wpa_s->l2_br = l2_packet_init_bridge(
                        wpa_s->bridge_ifname, wpa_s->ifname, wpa_s->own_addr,
                        ETH_P_EAPOL, wpa_supplicant_rx_eapol_bridge, wpa_s, 1);
                if (!wpa_s->l2_br) {
                        wpa_msg(wpa_s, MSG_ERROR,
                                "Failed to open l2_packet connection for the bridge interface '%s'",
                                wpa_s->bridge_ifname);
                        goto fail;
                }
        }

#ifdef CONFIG_TDLS
        if (!wpa_s->p2p_mgmt && wpa_tdls_init(wpa_s->wpa))
                goto fail;
#endif /* CONFIG_TDLS */

        return 0;
fail:
        wpa_s->bridge_ifname[0] = 0;
        if (wpa_s->l2_br) {
                l2_packet_deinit(wpa_s->l2_br);
                wpa_s->l2_br = NULL;
        }
#ifdef CONFIG_TDLS
        if (!wpa_s->p2p_mgmt)
                wpa_tdls_init(wpa_s->wpa);
#endif /* CONFIG_TDLS */
#endif
	return 0;
        return -EIO;
}


dbus_bool_t dbus_setter_bridge_ifname(
        const struct wpa_dbus_property_desc *property_desc,
        DBusMessageIter *iter, DBusError *error, void *user_data)
{
        struct wpa_supplicant *wpa_s = user_data;
        const char *bridge_ifname = NULL;
        const char *msg;
        int r;

        if (!dbus_simple_property_setter(iter, error, DBUS_TYPE_STRING,
                                              &bridge_ifname))
                return FALSE;

        r = wpa_supplicant_update_bridge_ifname(wpa_s, bridge_ifname);
        if (r != 0) {
                switch (r) {
                case -EINVAL:
                        msg = "invalid interface name";
                        break;
                case -EBUSY:
                        msg = "interface is busy";
                        break;
                case -EIO:
                        msg = "socket error";
                        break;
                default:
                        msg = "unknown error";
                        break;
                }
                dbus_set_error_const(error, DBUS_ERROR_FAILED, msg);
                return FALSE;
        }

        return TRUE;
}

#if 0
dbus_bool_t dbus_getter_driver(
        const struct wpa_dbus_property_desc *property_desc,
        DBusMessageIter *iter, DBusError *error, void *user_data)
{
        struct wpa_supplicant *wpa_s = user_data;

#if 0
        if (wpa_s->driver == NULL || wpa_s->driver->name == NULL) {
                printf( "%s[dbus]: wpa_s has no driver set",
                           __func__);
                dbus_set_error(error, DBUS_ERROR_FAILED, "%s: no driver set",
                               __func__);
                return FALSE;
        }
#endif
	return;
        //return dbus_string_property_getter(iter, wpa_s->driver->name, error);
}


dbus_bool_t dbus_getter_ifname(
        const struct wpa_dbus_property_desc *property_desc,
        DBusMessageIter *iter, DBusError *error, void *user_data)
{
        struct wpa_supplicant *wpa_s = user_data;

        return dbus_string_property_getter(iter, wpa_s->ifname, error);
}


dbus_bool_t dbus_getter_country(
        const struct wpa_dbus_property_desc *property_desc,
        DBusMessageIter *iter, DBusError *error, void *user_data)
{
        struct wpa_supplicant *wpa_s = user_data;
        char country[3];
        char *str = country;
#if 0
        country[0] = wpa_s->conf->country[0];
        country[1] = wpa_s->conf->country[1];
        country[2] = '\0';
#endif

        return dbus_simple_property_getter(iter, DBUS_TYPE_STRING,
                                                &str, error);
}

dbus_bool_t dbus_setter_country(
        const struct wpa_dbus_property_desc *property_desc,
        DBusMessageIter *iter, DBusError *error, void *user_data)
{
        struct wpa_supplicant *wpa_s = user_data;
        const char *country;

        if (!dbus_simple_property_setter(iter, error, DBUS_TYPE_STRING,
                                              &country))
                return FALSE;

        if (!country[0] || !country[1]) {
                dbus_set_error_const(error, DBUS_ERROR_FAILED,
                                     "invalid country code");
                return FALSE;
        }


#if 0
        if (wpa_s->drv_priv != NULL && wpa_drv_set_country(wpa_s, country)) {
                printf( "Failed to set country");
                dbus_set_error_const(error, DBUS_ERROR_FAILED,
                                     "failed to set country code");
                return FALSE;
        }
        wpa_s->conf->country[0] = country[0];
        wpa_s->conf->country[1] = country[1];
#endif
        return TRUE;
}

int wpa_supplicant_set_bss_expiration_count(struct wpa_supplicant *wpa_s,
                                            unsigned int bss_expire_count)
{
        if (bss_expire_count < 1) {
                wpa_msg(wpa_s, MSG_ERROR, "Invalid bss expiration count %u",
                        bss_expire_count);
                return -1;
        }
        wpa_msg(wpa_s, MSG_DEBUG, "Setting bss expiration scan count: %u",
                bss_expire_count);
#if 0
        wpa_s->conf->bss_expiration_scan_count = bss_expire_count;
#endif
        return 0;
}

dbus_bool_t dbus_setter_bss_expire_count(
        const struct wpa_dbus_property_desc *property_desc,
        DBusMessageIter *iter, DBusError *error, void *user_data)
{
        struct wpa_supplicant *wpa_s = user_data;
        dbus_uint32_t expire_count;

        if (!dbus_simple_property_setter(iter, error, DBUS_TYPE_UINT32,
                                              &expire_count))
                return FALSE;

        if (wpa_supplicant_set_bss_expiration_count(wpa_s, expire_count)) {
                dbus_set_error_const(error, DBUS_ERROR_FAILED,
                                     "BSSExpireCount must be > 0");
                return FALSE;
        }
        return TRUE;
}

dbus_bool_t dbus_getter_bss_expire_count(
        const struct wpa_dbus_property_desc *property_desc,
        DBusMessageIter *iter, DBusError *error, void *user_data)
{
        struct wpa_supplicant *wpa_s = user_data;
#if 0
        dbus_uint32_t expire_count = wpa_s->conf->bss_expiration_scan_count;
#else
        dbus_uint32_t expire_count = FALSE;
#endif
        return dbus_simple_property_getter(iter, DBUS_TYPE_UINT32,
                                                &expire_count, error);
}

int wpa_supplicant_set_bss_expiration_age(struct wpa_supplicant *wpa_s,
                                          unsigned int bss_expire_age)
{
        if (bss_expire_age < 10) {
                wpa_msg(wpa_s, MSG_ERROR, "Invalid bss expiration age %u",
                        bss_expire_age);
                return -1;
        }
        wpa_msg(wpa_s, MSG_DEBUG, "Setting bss expiration age: %d sec",
                bss_expire_age);
#if 0
        wpa_s->conf->bss_expiration_age = bss_expire_age;
#endif
        return 0;
}


dbus_bool_t _dbus_setter_bss_expire_age(
        const struct wpa_dbus_property_desc *property_desc,
        DBusMessageIter *iter, DBusError *error, void *user_data)
{
        struct wpa_supplicant *wpa_s = user_data;
        dbus_uint32_t expire_age;

        if (!dbus_simple_property_setter(iter, error, DBUS_TYPE_UINT32,
                                              &expire_age))
                return FALSE;

        if (wpa_supplicant_set_bss_expiration_age(wpa_s, expire_age)) {
                dbus_set_error_const(error, DBUS_ERROR_FAILED,
                                     "BSSExpireAge must be >= 10");
                return FALSE;
        }
        return TRUE;
}

dbus_bool_t dbus_getter_bss_expire_age(
        const struct wpa_dbus_property_desc *property_desc,
        DBusMessageIter *iter, DBusError *error, void *user_data)
{
#if 0
        struct wpa_supplicant *wpa_s = user_data;
        dbus_uint32_t expire_age = wpa_s->conf->bss_expiration_age;

        return dbus_simple_property_getter(iter, DBUS_TYPE_UINT32,
                                                &expire_age, error);
#endif
}

dbus_bool_t dbus_setter_bss_expire_age(
        const struct wpa_dbus_property_desc *property_desc,
        DBusMessageIter *iter, DBusError *error, void *user_data)
{
        struct wpa_supplicant *wpa_s = user_data;
        dbus_uint32_t expire_age;

        if (!dbus_simple_property_setter(iter, error, DBUS_TYPE_UINT32,
                                              &expire_age))
                return FALSE;

        if (wpa_supplicant_set_bss_expiration_age(wpa_s, expire_age)) {
                dbus_set_error_const(error, DBUS_ERROR_FAILED,
                                     "BSSExpireAge must be >= 10");
                return FALSE;
        }
        return TRUE;
}
#endif

dbus_bool_t dbus_getter_ap_scan(
        const struct wpa_dbus_property_desc *property_desc,
        DBusMessageIter *iter, DBusError *error, void *user_data)
{   
        struct wpa_supplicant *wpa_s = user_data;
#if 0
        dbus_uint32_t ap_scan = wpa_s->conf->ap_scan;
#else 
        dbus_uint32_t ap_scan = 1;
#endif    
        return dbus_simple_property_getter(iter, DBUS_TYPE_UINT32,
                                                &ap_scan, error);
}

int wpa_supplicant_set_ap_scan(struct wpa_supplicant *wpa_s, int ap_scan)
{

        int old_ap_scan;

        if (ap_scan < 0 || ap_scan > 2)
                return -1;


#if 0
        if (ap_scan == 2 && os_strcmp(wpa_s->driver->name, "nl80211") == 0) {
                wpa_printf(MSG_INFO,
                           "Note: nl80211 driver interface is not designed to be used with ap_scan=2; this can result in connection failures");
        }
#endif

#ifdef ANDROID
        if (ap_scan == 2 && ap_scan != wpa_s->conf->ap_scan &&
            wpa_s->wpa_state >= WPA_ASSOCIATING &&
            wpa_s->wpa_state < WPA_COMPLETED) {
                wpa_printf(MSG_ERROR, "ap_scan = %d (%d) rejected while "
                           "associating", wpa_s->conf->ap_scan, ap_scan);
                return 0;
        }
#endif /* ANDROID */

#if 0
        old_ap_scan = wpa_s->conf->ap_scan;
        wpa_s->conf->ap_scan = ap_scan;

        if (old_ap_scan != wpa_s->conf->ap_scan)
                wpas_notify_ap_scan_changed(wpa_s);
#endif
        return 0;
}

dbus_bool_t dbus_setter_ap_scan(
        const struct wpa_dbus_property_desc *property_desc,
        DBusMessageIter *iter, DBusError *error, void *user_data)
{
        struct wpa_supplicant *wpa_s = user_data;
        dbus_uint32_t ap_scan;

	printf("In dbus_setter_ap_scan ***\n");
        if (!dbus_simple_property_setter(iter, error, DBUS_TYPE_UINT32,
                                              &ap_scan))
                return FALSE;
#if 1
        if (wpa_supplicant_set_ap_scan(wpa_s, ap_scan)) {
                dbus_set_error_const(error, DBUS_ERROR_FAILED,
                                     "ap_scan must be 0, 1, or 2");
                return FALSE;
        }
#endif
        return TRUE;
}

#if 0
dbus_bool_t dbus_getter_scanning(
        const struct wpa_dbus_property_desc *property_desc,
        DBusMessageIter *iter, DBusError *error, void *user_data)
{
        struct wpa_supplicant *wpa_s = user_data;
#if 0
        dbus_bool_t scanning = wpa_s->scanning ? TRUE : FALSE;
#else 
	dbus_bool_t scanning = TRUE;
#endif
        return dbus_simple_property_getter(iter, DBUS_TYPE_BOOLEAN,
                                                &scanning, error);
}

#endif

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
        str_state = wpa_supplicant_state_txt(WPA_INACTIVE);

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
        struct wpa_bss *res;

        res = get_bss_helper(args, error, __func__);
        if (!res)
                return FALSE;

	printf("In dbus_getter_bss_bssid: " MACSTR, MAC2STR(res->bssid));

        return dbus_simple_array_property_getter(iter, DBUS_TYPE_BYTE,
                                                      res->bssid, ETH_ALEN,
                                                      error);
}

int notify_scanning(int num)
{
    wpa_s = (struct wpa_supplicant *) malloc((sizeof(struct wpa_supplicant)));
    if (!wpa_s) {
        printf("%s():%d wpa_s is NULL\n", __func__, __LINE__);
        return;
    }    

    memset(wpa_s, 0, sizeof(struct wpa_supplicant));

    dl_list_init(&wpa_s->bss);
    dl_list_init(&wpa_s->bss_id);

    strcpy(wpa_s->dbus_new_path, INTERFACE_DBUS_SERVICE_PATH);
    strcpy(wpa_s->ifname, "wl0");

    //dbus_signal_prop_changed(connection, INTERFACE_DBUS_SERVICE_PATH, WPAS_DBUS_PROP_SCANNING);

    return 0;
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

static dbus_bool_t put_changed_properties(
        const struct wpa_dbus_object_desc *obj_dsc, const char *interface,
        DBusMessageIter *dict_iter, int clear_changed)
{
        DBusMessageIter entry_iter;
        const struct wpa_dbus_property_desc *dsc;
        int i;
        DBusError error;

        for (dsc = obj_dsc->properties, i = 0; dsc && dsc->dbus_property;
             dsc++, i++) {
                if (obj_dsc->prop_changed_flags == NULL ||
                    !obj_dsc->prop_changed_flags[i])
                        continue;
                if (strcmp(dsc->dbus_interface, interface) != 0)
                        continue;
                if (clear_changed)
                        obj_dsc->prop_changed_flags[i] = 0;

                if (!dbus_message_iter_open_container(dict_iter,
                                                      DBUS_TYPE_DICT_ENTRY,
                                                      NULL, &entry_iter) ||
                    !dbus_message_iter_append_basic(&entry_iter,
                                                    DBUS_TYPE_STRING,
                                                    &dsc->dbus_property))
                        return FALSE;

                dbus_error_init(&error);
                if (!dsc->getter(dsc, &entry_iter, &error, obj_dsc->user_data))
                {
                        if (dbus_error_is_set(&error)) {
                                printf(
                                           "dbus: %s: Cannot get new value of property %s: (%s) %s",
                                           __func__, dsc->dbus_property,
                                           error.name, error.message);
                        } else {
                                printf(
                                           "dbus: %s: Cannot get new value of property %s",
                                           __func__, dsc->dbus_property);
                        }
                        dbus_error_free(&error);
                        return FALSE;
                }

                if (!dbus_message_iter_close_container(dict_iter, &entry_iter))
                        return FALSE;
        }

        return TRUE;
}

static void do_send_deprecated_prop_changed_signal(
        DBusConnection *con, const char *path, const char *interface,
        const struct wpa_dbus_object_desc *obj_dsc)
{
        DBusMessage *msg;
        DBusMessageIter signal_iter, dict_iter;

        msg = dbus_message_new_signal(path, interface, "PropertiesChanged");
        if (msg == NULL)
                return;

        dbus_message_iter_init_append(msg, &signal_iter);

        if (!dbus_message_iter_open_container(&signal_iter, DBUS_TYPE_ARRAY,
                                              "{sv}", &dict_iter) ||
            !put_changed_properties(obj_dsc, interface, &dict_iter, 1) ||
            !dbus_message_iter_close_container(&signal_iter, &dict_iter)) {
                printf("dbus: %s: Failed to construct signal",
                           __func__);
        } else {
                dbus_connection_send(con, msg, NULL);
        }

        dbus_message_unref(msg);
}



static void do_send_prop_changed_signal(
        DBusConnection *con, const char *path, const char *interface,
        const struct wpa_dbus_object_desc *obj_dsc)
{
        DBusMessage *msg;
        DBusMessageIter signal_iter, dict_iter;

        msg = dbus_message_new_signal(path, DBUS_INTERFACE_PROPERTIES,
                                      "PropertiesChanged");
        if (msg == NULL)
                return;

        dbus_message_iter_init_append(msg, &signal_iter);

        if (!dbus_message_iter_append_basic(&signal_iter, DBUS_TYPE_STRING,
                                            &interface) ||
            /* Changed properties dict */
            !dbus_message_iter_open_container(&signal_iter, DBUS_TYPE_ARRAY,
                                              "{sv}", &dict_iter) ||
            !put_changed_properties(obj_dsc, interface, &dict_iter, 0) ||
            !dbus_message_iter_close_container(&signal_iter, &dict_iter) ||
            /* Invalidated properties array (empty) */
            !dbus_message_iter_open_container(&signal_iter, DBUS_TYPE_ARRAY,
                                              "s", &dict_iter) ||
            !dbus_message_iter_close_container(&signal_iter, &dict_iter)) {
                printf("dbus: %s: Failed to construct signal",
                           __func__);
        } else {
                dbus_connection_send(con, msg, NULL);
        }

        dbus_message_unref(msg);
}

static void send_prop_changed_signal(
        DBusConnection *con, const char *path, const char *interface,
        const struct wpa_dbus_object_desc *obj_dsc)
{
        /*
         * First, send property change notification on the standardized
         * org.freedesktop.DBus.Properties interface. This call will not
         * clear the property change bits, so that they are preserved for
         * the call that follows.
         */
        do_send_prop_changed_signal(con, path, interface, obj_dsc);

        /*
         * Now send PropertiesChanged on our own interface for backwards
         * compatibility. This is deprecated and will be removed in a future
         * release.
         */
        do_send_deprecated_prop_changed_signal(con, path, interface, obj_dsc);

        /* Property change bits have now been cleared. */
}


void wpa_dbus_flush_object_changed_properties(DBusConnection *con,
                                              const char *path)
{
        struct wpa_dbus_object_desc *obj_desc = NULL;
        const struct wpa_dbus_property_desc *dsc;
        int i;

        dbus_connection_get_object_path_data(con, path, (void **) &obj_desc);
        if (!obj_desc) return;

        for (dsc = obj_desc->properties, i = 0; dsc && dsc->dbus_property;
             dsc++, i++) {
                if (obj_desc->prop_changed_flags == NULL ||
                    !obj_desc->prop_changed_flags[i])
                        continue;
                send_prop_changed_signal(con, path, dsc->dbus_interface,
                                         obj_desc);
        }
}

void dbus_signal_prop_changed(DBusConnection *connection, char *path, enum wpas_dbus_prop property)
{
        char *prop;
        dbus_bool_t flush;
	struct wpa_dbus_object_desc *obj_desc = NULL;
	const struct wpa_dbus_property_desc *dsc;
	int i = 0;

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

	for (dsc = obj_desc->properties; dsc && dsc->dbus_property; dsc++, i++)
                if (strcmp(prop, dsc->dbus_property) == 0 &&
                    strcmp(path, dsc->dbus_interface) == 0) {
                        if (obj_desc->prop_changed_flags)
                                obj_desc->prop_changed_flags[i] = 1;
                        break;
                }

	if (!dsc || !dsc->dbus_property) {
             printf("dbus: wpa_dbus_property_changed: no property:%d in object path:%s", property, path);
             return;
        }

        if (flush) {
             wpa_dbus_flush_object_changed_properties(connection, path);
        }
}

struct wpa_bss * wpa_bss_get(struct wpa_supplicant *wpa_s, const uint8_t *bssid, const uint8_t *ssid, size_t ssid_len)
{
        struct wpa_bss *bss;
        dl_list_for_each(bss, &wpa_s->bss, struct wpa_bss, list) {
		if(memcmp(bss->bssid, bssid, ETH_ALEN) == 0 &&
		    bss->ssid_len == ssid_len &&
		    memcmp(bss->ssid, ssid, ssid_len) == 0) {
                        return bss;
		}
        }
        return NULL;
}

struct wpa_bss * bss_get_id(struct wpa_supplicant *wpa_s, unsigned int id)
{
        struct wpa_bss *bss;
        dl_list_for_each(bss, &wpa_s->bss, struct wpa_bss, list) {
                if (bss->id == id)
                        return bss;
        }
        return NULL;
}

static struct wpa_bss * get_bss_helper(struct bss_handler_args *args,
                                       DBusError *error, const char *func_name)
{
        struct wpa_bss *res = bss_get_id(args->wpa_s, args->id);

	//res = args->wpa_s->bss;

        if (!res) {
                printf("%s[dbus]: no bss with id %d found",
                           func_name, args->id);
                dbus_set_error(error, DBUS_ERROR_FAILED,
                               "%s: BSS %d not found",
                               func_name, args->id);
        }

        return res;
}

static inline const uint8_t * wpa_bss_ie_ptr(const struct wpa_bss *bss)
{
        return bss->ies;
}

const uint8_t * wpa_bss_get_ie(const struct wpa_bss *bss, uint8_t ie)
{
	printf("IN =============>wpa_bss_get_ie: ie_len:%d, ie:%d, wpa_bss_ie_ptr(bss):%p!!\n", bss->ie_len, ie, wpa_bss_ie_ptr(bss));
	return wpa_bss_ie_ptr(bss); 

	// TEMP DISABLED BUT ENABLED AGAIN - VIKAS
//        return get_ie(wpa_bss_ie_ptr(bss), bss->ie_len, ie);
}

int wpa_bss_get_bit_rates(const struct wpa_bss *bss, uint8_t **rates)
{
        const uint8_t *ie, *ie2;
        int i, j;
        unsigned int len;
        uint8_t *r;

        ie = wpa_bss_get_ie(bss, WLAN_EID_SUPP_RATES);
        ie2 = wpa_bss_get_ie(bss, WLAN_EID_EXT_SUPP_RATES);

	printf("=======ie:%p, ie2:%p\n", ie, ie2);
        len = (ie ? ie[1] : 0) + (ie2 ? ie2[1] : 0);

        r = malloc(len);
        if (!r)
                return -1;

        for (i = 0; ie && i < ie[1]; i++)
                r[i] = ie[i + 2] & 0x7f;

        for (j = 0; ie2 && j < ie2[1]; j++)
                r[i + j] = ie2[j + 2] & 0x7f;

        *rates = r;
        return len;
}

dbus_bool_t dbus_dict_append_string(DBusMessageIter *iter_dict,
                                        const char *key, const char *value)
{                       
        if (!value)                          
                return FALSE;
        return _dbus_add_dict_entry_basic(iter_dict, key, DBUS_TYPE_STRING,
                                              &value);
}

static dbus_bool_t wpas_dbus_get_bss_security_prop(
        const struct wpa_dbus_property_desc *property_desc,
        DBusMessageIter *iter, struct wpa_ie_data *ie_data, DBusError *error)
{
        DBusMessageIter iter_dict, variant_iter;
        const char *group;
        const char *pairwise[5]; /* max 5 pairwise ciphers is supported */
        const char *key_mgmt[16]; /* max 16 key managements may be supported */
        int n;

        if (!dbus_message_iter_open_container(iter, DBUS_TYPE_VARIANT,
                                              "a{sv}", &variant_iter))
                goto nomem;

        if (!dbus_dict_open_write(&variant_iter, &iter_dict))
                goto nomem;

        /*
         * KeyMgmt
         *
         * When adding a new entry here, please take care to extend key_mgmt[]
         * and keep documentation in doc/dbus.doxygen up to date.
         */
        n = 0;
        if (ie_data->key_mgmt & WPA_KEY_MGMT_PSK)
                key_mgmt[n++] = "wpa-psk";
        if (ie_data->key_mgmt & WPA_KEY_MGMT_FT_PSK)
                key_mgmt[n++] = "wpa-ft-psk";
        if (ie_data->key_mgmt & WPA_KEY_MGMT_PSK_SHA256)
                key_mgmt[n++] = "wpa-psk-sha256";
        if (ie_data->key_mgmt & WPA_KEY_MGMT_IEEE8021X)
                key_mgmt[n++] = "wpa-eap";
        if (ie_data->key_mgmt & WPA_KEY_MGMT_FT_IEEE8021X)
                key_mgmt[n++] = "wpa-ft-eap";
        if (ie_data->key_mgmt & WPA_KEY_MGMT_IEEE8021X_SHA256)
                key_mgmt[n++] = "wpa-eap-sha256";
#ifdef CONFIG_SUITEB
        if (ie_data->key_mgmt & WPA_KEY_MGMT_IEEE8021X_SUITE_B)
                key_mgmt[n++] = "wpa-eap-suite-b";
#endif /* CONFIG_SUITEB */
#ifdef CONFIG_SUITEB192
        if (ie_data->key_mgmt & WPA_KEY_MGMT_IEEE8021X_SUITE_B_192)
                key_mgmt[n++] = "wpa-eap-suite-b-192";
#endif /* CONFIG_SUITEB192 */
#ifdef CONFIG_FILS
        if (ie_data->key_mgmt & WPA_KEY_MGMT_FILS_SHA256)
                key_mgmt[n++] = "wpa-fils-sha256";
        if (ie_data->key_mgmt & WPA_KEY_MGMT_FILS_SHA384)
                key_mgmt[n++] = "wpa-fils-sha384";
        if (ie_data->key_mgmt & WPA_KEY_MGMT_FT_FILS_SHA256)
                key_mgmt[n++] = "wpa-ft-fils-sha256";
        if (ie_data->key_mgmt & WPA_KEY_MGMT_FT_FILS_SHA384)
                key_mgmt[n++] = "wpa-ft-fils-sha384";
#endif /* CONFIG_FILS */
#ifdef CONFIG_SAE
        if (ie_data->key_mgmt & WPA_KEY_MGMT_SAE)
                key_mgmt[n++] = "sae";
        if (ie_data->key_mgmt & WPA_KEY_MGMT_FT_SAE)
                key_mgmt[n++] = "ft-sae";
#endif /* CONFIG_SAE */
#ifdef CONFIG_OWE
        if (ie_data->key_mgmt & WPA_KEY_MGMT_OWE)
                key_mgmt[n++] = "owe";
#endif /* CONFIG_OWE */
        if (ie_data->key_mgmt & WPA_KEY_MGMT_NONE)
                key_mgmt[n++] = "wpa-none";

        if (!dbus_dict_append_string_array(&iter_dict, "KeyMgmt",
                                               key_mgmt, n))
                goto nomem;

        /* Group */
        switch (ie_data->group_cipher) {
#ifdef CONFIG_WEP
        case WPA_CIPHER_WEP40:
                group = "wep40";
                break;
        case WPA_CIPHER_WEP104:
                group = "wep104";
                break;
#endif /* CONFIG_WEP */
#ifndef CONFIG_NO_TKIP
        case WPA_CIPHER_TKIP:
                group = "tkip";
                break;
#endif /* CONFIG_NO_TKIP */
        case WPA_CIPHER_CCMP:
                group = "ccmp";
                break;
        case WPA_CIPHER_GCMP:
                group = "gcmp";
                break;
        case WPA_CIPHER_CCMP_256:
                group = "ccmp-256";
                break;
        case WPA_CIPHER_GCMP_256:
                group = "gcmp-256";
                break;
        default:
                group = "";
                break;
        }

        if (!dbus_dict_append_string(&iter_dict, "Group", group))
                goto nomem;

        /* Pairwise */
        n = 0;
#ifndef CONFIG_NO_TKIP
        if (ie_data->pairwise_cipher & WPA_CIPHER_TKIP)
                pairwise[n++] = "tkip";
#endif /* CONFIG_NO_TKIP */
        if (ie_data->pairwise_cipher & WPA_CIPHER_CCMP)
                pairwise[n++] = "ccmp";
        if (ie_data->pairwise_cipher & WPA_CIPHER_GCMP)
                pairwise[n++] = "gcmp";
        if (ie_data->pairwise_cipher & WPA_CIPHER_CCMP_256)
                pairwise[n++] = "ccmp-256";
        if (ie_data->pairwise_cipher & WPA_CIPHER_GCMP_256)
                pairwise[n++] = "gcmp-256";

        if (!dbus_dict_append_string_array(&iter_dict, "Pairwise",
                                               pairwise, n))
                goto nomem;

        /* Management group (RSN only) */
        if (ie_data->proto == WPA_PROTO_RSN) {
                switch (ie_data->mgmt_group_cipher) {
                case WPA_CIPHER_AES_128_CMAC:
                        group = "aes128cmac";
                        break;
                default:
                        group = "";
                        break;
                }

                if (!dbus_dict_append_string(&iter_dict, "MgmtGroup",
                                                 group))
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

#if 0
static inline void WPA_PUT_BE32(uint8_t *a, u32 val)
{
        a[0] = (val >> 24) & 0xff;
        a[1] = (val >> 16) & 0xff;
        a[2] = (val >> 8) & 0xff;
        a[3] = val & 0xff;
}

static inline u32 WPA_GET_BE32(const uint8_t *a)
{
        return ((u32) a[0] << 24) | (a[1] << 16) | (a[2] << 8) | a[3];
}
#endif

#define RSN_SELECTOR_PUT(a, val) WPA_PUT_BE32((uint8_t *) (a), (val))
#define RSN_SELECTOR_GET(a) WPA_GET_BE32((const uint8_t *) (a))


static int rsn_selector_to_bitfield(const uint8_t *s)
{
        if (RSN_SELECTOR_GET(s) == RSN_CIPHER_SUITE_NONE)
                return WPA_CIPHER_NONE;
        if (RSN_SELECTOR_GET(s) == RSN_CIPHER_SUITE_TKIP)
                return WPA_CIPHER_TKIP;
        if (RSN_SELECTOR_GET(s) == RSN_CIPHER_SUITE_CCMP)
                return WPA_CIPHER_CCMP;
        if (RSN_SELECTOR_GET(s) == RSN_CIPHER_SUITE_AES_128_CMAC)
                return WPA_CIPHER_AES_128_CMAC;
        if (RSN_SELECTOR_GET(s) == RSN_CIPHER_SUITE_GCMP)
                return WPA_CIPHER_GCMP;
        if (RSN_SELECTOR_GET(s) == RSN_CIPHER_SUITE_CCMP_256)
                return WPA_CIPHER_CCMP_256;
        if (RSN_SELECTOR_GET(s) == RSN_CIPHER_SUITE_GCMP_256)
                return WPA_CIPHER_GCMP_256;
        if (RSN_SELECTOR_GET(s) == RSN_CIPHER_SUITE_BIP_GMAC_128)
                return WPA_CIPHER_BIP_GMAC_128;
        if (RSN_SELECTOR_GET(s) == RSN_CIPHER_SUITE_BIP_GMAC_256)
                return WPA_CIPHER_BIP_GMAC_256;
        if (RSN_SELECTOR_GET(s) == RSN_CIPHER_SUITE_BIP_CMAC_256)
                return WPA_CIPHER_BIP_CMAC_256;
        if (RSN_SELECTOR_GET(s) == RSN_CIPHER_SUITE_NO_GROUP_ADDRESSED)
                return WPA_CIPHER_GTK_NOT_USED;
        return 0;
}

static int rsn_key_mgmt_to_bitfield(const uint8_t *s)
{
        if (RSN_SELECTOR_GET(s) == RSN_AUTH_KEY_MGMT_UNSPEC_802_1X)
                return WPA_KEY_MGMT_IEEE8021X;
        if (RSN_SELECTOR_GET(s) == RSN_AUTH_KEY_MGMT_PSK_OVER_802_1X)
                return WPA_KEY_MGMT_PSK;
#ifdef CONFIG_IEEE80211R
        if (RSN_SELECTOR_GET(s) == RSN_AUTH_KEY_MGMT_FT_802_1X)
                return WPA_KEY_MGMT_FT_IEEE8021X;
        if (RSN_SELECTOR_GET(s) == RSN_AUTH_KEY_MGMT_FT_PSK)
                return WPA_KEY_MGMT_FT_PSK;
#ifdef CONFIG_SHA384
        if (RSN_SELECTOR_GET(s) == RSN_AUTH_KEY_MGMT_FT_802_1X_SHA384)
                return WPA_KEY_MGMT_FT_IEEE8021X_SHA384;
#endif /* CONFIG_SHA384 */
#endif /* CONFIG_IEEE80211R */
        if (RSN_SELECTOR_GET(s) == RSN_AUTH_KEY_MGMT_802_1X_SHA256)
                return WPA_KEY_MGMT_IEEE8021X_SHA256;
        if (RSN_SELECTOR_GET(s) == RSN_AUTH_KEY_MGMT_PSK_SHA256)
                return WPA_KEY_MGMT_PSK_SHA256;
#ifdef CONFIG_SAE
        if (RSN_SELECTOR_GET(s) == RSN_AUTH_KEY_MGMT_SAE)
                return WPA_KEY_MGMT_SAE;
        if (RSN_SELECTOR_GET(s) == RSN_AUTH_KEY_MGMT_FT_SAE)
                return WPA_KEY_MGMT_FT_SAE;
#endif /* CONFIG_SAE */
        if (RSN_SELECTOR_GET(s) == RSN_AUTH_KEY_MGMT_802_1X_SUITE_B)
                return WPA_KEY_MGMT_IEEE8021X_SUITE_B;
        if (RSN_SELECTOR_GET(s) == RSN_AUTH_KEY_MGMT_802_1X_SUITE_B_192)
                return WPA_KEY_MGMT_IEEE8021X_SUITE_B_192;
        if (RSN_SELECTOR_GET(s) == RSN_AUTH_KEY_MGMT_FILS_SHA256)
                return WPA_KEY_MGMT_FILS_SHA256;
        if (RSN_SELECTOR_GET(s) == RSN_AUTH_KEY_MGMT_FILS_SHA384)
                return WPA_KEY_MGMT_FILS_SHA384;
        if (RSN_SELECTOR_GET(s) == RSN_AUTH_KEY_MGMT_FT_FILS_SHA256)
                return WPA_KEY_MGMT_FT_FILS_SHA256;
        if (RSN_SELECTOR_GET(s) == RSN_AUTH_KEY_MGMT_FT_FILS_SHA384)
                return WPA_KEY_MGMT_FT_FILS_SHA384;
#ifdef CONFIG_OWE
        if (RSN_SELECTOR_GET(s) == RSN_AUTH_KEY_MGMT_OWE)
                return WPA_KEY_MGMT_OWE;
#endif /* CONFIG_OWE */
#ifdef CONFIG_DPP
        if (RSN_SELECTOR_GET(s) == RSN_AUTH_KEY_MGMT_DPP)
                return WPA_KEY_MGMT_DPP;
#endif /* CONFIG_DPP */
        if (RSN_SELECTOR_GET(s) == RSN_AUTH_KEY_MGMT_OSEN)
                return WPA_KEY_MGMT_OSEN;
#ifdef CONFIG_PASN
        if (RSN_SELECTOR_GET(s) == RSN_AUTH_KEY_MGMT_PASN)
                return WPA_KEY_MGMT_PASN;
#endif /* CONFIG_PASN */
        return 0;
}

int parse_wpa_ie_rsn(const uint8_t *rsn_ie, size_t rsn_ie_len,
                         struct wpa_ie_data *data)
{
        const uint8_t *pos;
        int left;
        int i, count;

        os_memset(data, 0, sizeof(*data));
        data->proto = WPA_PROTO_RSN;
        data->pairwise_cipher = WPA_CIPHER_CCMP;
        data->group_cipher = WPA_CIPHER_CCMP;
        data->key_mgmt = WPA_KEY_MGMT_IEEE8021X;
        data->capabilities = 0;
        data->pmkid = NULL;
        data->num_pmkid = 0;
        data->mgmt_group_cipher = WPA_CIPHER_AES_128_CMAC;

        if (rsn_ie_len == 0) {
                /* No RSN IE - fail silently */
                return -1;
        }

        if (rsn_ie_len < sizeof(struct rsn_ie_hdr)) {
                wpa_printf(MSG_DEBUG, "%s: ie len too short %lu",
                           __func__, (unsigned long) rsn_ie_len);
                return -1;
        }

        if (rsn_ie_len >= 6 && rsn_ie[1] >= 4 &&
            rsn_ie[1] == rsn_ie_len - 2 &&
            WPA_GET_BE32(&rsn_ie[2]) == OSEN_IE_VENDOR_TYPE) {
                pos = rsn_ie + 6;
                left = rsn_ie_len - 6;

                data->group_cipher = WPA_CIPHER_GTK_NOT_USED;
                data->has_group = 1;
                data->key_mgmt = WPA_KEY_MGMT_OSEN;
                data->proto = WPA_PROTO_OSEN;
        } else {
                const struct rsn_ie_hdr *hdr;

                hdr = (const struct rsn_ie_hdr *) rsn_ie;
                if (hdr->elem_id != WLAN_EID_RSN ||
                    hdr->len != rsn_ie_len - 2 ||
                    WPA_GET_LE16(hdr->version) != RSN_VERSION) {
                        wpa_printf(MSG_DEBUG, "%s: malformed ie or unknown version",
                                   __func__);
                        return -2;
                }

                pos = (const uint8_t *) (hdr + 1);
                left = rsn_ie_len - sizeof(*hdr);
        }

        if (left >= RSN_SELECTOR_LEN) {
                data->group_cipher = rsn_selector_to_bitfield(pos);
                data->has_group = 1;
                if (!wpa_cipher_valid_group(data->group_cipher)) {
                        wpa_printf(MSG_DEBUG,
                                   "%s: invalid group cipher 0x%x (%08x)",
                                   __func__, data->group_cipher,
                                   WPA_GET_BE32(pos));
#ifdef CONFIG_NO_TKIP
                        if (RSN_SELECTOR_GET(pos) == RSN_CIPHER_SUITE_TKIP) {
                                wpa_printf(MSG_DEBUG,
                                           "%s: TKIP as group cipher not supported in CONFIG_NO_TKIP=y build",
                                           __func__);
                        }
#endif /* CONFIG_NO_TKIP */
                        return -1;
                }
                pos += RSN_SELECTOR_LEN;
                left -= RSN_SELECTOR_LEN;
        } else if (left > 0) {
                wpa_printf(MSG_DEBUG, "%s: ie length mismatch, %u too much",
                           __func__, left);
                return -3;
        }

        if (left >= 2) {
                data->pairwise_cipher = 0;
                count = WPA_GET_LE16(pos);
                pos += 2;
                left -= 2;
                if (count == 0 || count > left / RSN_SELECTOR_LEN) {
                        wpa_printf(MSG_DEBUG, "%s: ie count botch (pairwise), "
                                   "count %u left %u", __func__, count, left);
                        return -4;
                }
                if (count)
                        data->has_pairwise = 1;
                for (i = 0; i < count; i++) {
                        data->pairwise_cipher |= rsn_selector_to_bitfield(pos);
                        pos += RSN_SELECTOR_LEN;
                        left -= RSN_SELECTOR_LEN;
                }
                if (data->pairwise_cipher & WPA_CIPHER_AES_128_CMAC) {
                        wpa_printf(MSG_DEBUG, "%s: AES-128-CMAC used as "
                                   "pairwise cipher", __func__);
                        return -1;
                }
        } else if (left == 1) {
                wpa_printf(MSG_DEBUG, "%s: ie too short (for key mgmt)",
                           __func__);
                return -5;
        }

        if (left >= 2) {
                data->key_mgmt = 0;
                count = WPA_GET_LE16(pos);
                pos += 2;
                left -= 2;
                if (count == 0 || count > left / RSN_SELECTOR_LEN) {
                        wpa_printf(MSG_DEBUG, "%s: ie count botch (key mgmt), "
                                   "count %u left %u", __func__, count, left);
                        return -6;
                }
                for (i = 0; i < count; i++) {
                        data->key_mgmt |= rsn_key_mgmt_to_bitfield(pos);
                        pos += RSN_SELECTOR_LEN;
                        left -= RSN_SELECTOR_LEN;
                }
        } else if (left == 1) {
                wpa_printf(MSG_DEBUG, "%s: ie too short (for capabilities)",
                           __func__);
                return -7;
        }

        if (left >= 2) {
                data->capabilities = WPA_GET_LE16(pos);
                pos += 2;
                left -= 2;
        }

        if (left >= 2) {
                u16 num_pmkid = WPA_GET_LE16(pos);
                pos += 2;
                left -= 2;
                if (num_pmkid > (unsigned int) left / PMKID_LEN) {
                        wpa_printf(MSG_DEBUG, "%s: PMKID underflow "
                                   "(num_pmkid=%u left=%d)",
                                   __func__, num_pmkid, left);
                        data->num_pmkid = 0;
                        return -9;
                } else {
                        data->num_pmkid = num_pmkid;
                        data->pmkid = pos;
                        pos += data->num_pmkid * PMKID_LEN;
                        left -= data->num_pmkid * PMKID_LEN;
                }
        }

        if (left >= 4) {
                data->mgmt_group_cipher = rsn_selector_to_bitfield(pos);
                if (!wpa_cipher_valid_mgmt_group(data->mgmt_group_cipher)) {
                        wpa_printf(MSG_DEBUG,
                                   "%s: Unsupported management group cipher 0x%x (%08x)",
                                   __func__, data->mgmt_group_cipher,
                                   WPA_GET_BE32(pos));
                        return -10;
                }
                pos += RSN_SELECTOR_LEN;
                left -= RSN_SELECTOR_LEN;
        }

        if (left > 0) {
                wpa_hexdump(MSG_DEBUG,
                            "parse_wpa_ie_rsn: ignore trailing bytes",
                            pos, left);
        }

        return 0;
}

int parse_wpa_ie(const uint8_t *wpa_ie, size_t wpa_ie_len,
                     struct wpa_ie_data *data)
{
        if (wpa_ie_len >= 1 && wpa_ie[0] == WLAN_EID_RSN)
                return parse_wpa_ie_rsn(wpa_ie, wpa_ie_len, data);
        if (wpa_ie_len >= 6 && wpa_ie[0] == WLAN_EID_VENDOR_SPECIFIC &&
            wpa_ie[1] >= 4 && WPA_GET_BE32(&wpa_ie[2]) == OSEN_IE_VENDOR_TYPE) {
                return parse_wpa_ie_rsn(wpa_ie, wpa_ie_len, data);
        } else {
                // return wpa_parse_wpa_ie_wpa(wpa_ie, wpa_ie_len, data);
	}
}

dbus_bool_t wpas_dbus_getter_bss_rsn(
        const struct wpa_dbus_property_desc *property_desc,
        DBusMessageIter *iter, DBusError *error, void *user_data)
{
        struct bss_handler_args *args = user_data;
        struct wpa_bss *res;
        struct wpa_ie_data wpa_data;
        const uint8_t *ie;

        res = get_bss_helper(args, error, __func__);
        if (!res)
                return FALSE;

        os_memset(&wpa_data, 0, sizeof(wpa_data));
        ie = wpa_bss_get_ie(res, WLAN_EID_RSN);
	printf("IE_PTR:%p\n", ie); 
        if (ie && parse_wpa_ie(ie, 2 + ie[1], &wpa_data) < 0) {
                dbus_set_error_const(error, DBUS_ERROR_FAILED,
                                     "failed to parse RSN IE");
                return FALSE;
        }

        return wpas_dbus_get_bss_security_prop(property_desc, iter, &wpa_data, error);
}

static int cmp_unsigned_char(const void *a, const void *b)
{
        return (*(uint8_t *) b - *(uint8_t *) a);
}

dbus_bool_t wpas_dbus_getter_bss_rates(
        const struct wpa_dbus_property_desc *property_desc,
        DBusMessageIter *iter, DBusError *error, void *user_data)
{
        struct bss_handler_args *args = user_data;
        struct wpa_bss *res;
        uint8_t *ie_rates = NULL;
        uint32_t *real_rates;
        int rates_num, i;
        dbus_bool_t success = FALSE;

        res = get_bss_helper(args, error, __func__);
        if (!res)
                return FALSE;

        rates_num = wpa_bss_get_bit_rates(res, &ie_rates);
        if (rates_num < 0)
                return FALSE;

        qsort(ie_rates, rates_num, 1, cmp_unsigned_char);

        real_rates = malloc(sizeof(uint32_t) * rates_num);
        if (!real_rates) {
                free(ie_rates);
                dbus_set_error_const(error, DBUS_ERROR_NO_MEMORY, "no memory");
                return FALSE;
        }

        for (i = 0; i < rates_num; i++)
                real_rates[i] = ie_rates[i] * 500000;

        success = dbus_simple_array_property_getter(iter, DBUS_TYPE_UINT32,
                                                         real_rates, rates_num,
                                                         error);

        free(ie_rates);
        free(real_rates);
        return success;
}

dbus_bool_t wpas_dbus_getter_bss_frequency(
        const struct wpa_dbus_property_desc *property_desc,
        DBusMessageIter *iter, DBusError *error, void *user_data)
{
        struct bss_handler_args *args = user_data;
        struct wpa_bss *res;
        uint16_t freq;

        res = get_bss_helper(args, error, __func__);
        if (!res)
                return FALSE;

        freq = (uint16_t) res->freq;
        return dbus_simple_property_getter(iter, DBUS_TYPE_UINT16,
                                                &freq, error);
}

dbus_bool_t wpas_dbus_getter_bss_signal(
        const struct wpa_dbus_property_desc *property_desc,
        DBusMessageIter *iter, DBusError *error, void *user_data)
{
        struct bss_handler_args *args = user_data;
        struct wpa_bss *res;
        int16_t level;

        res = get_bss_helper(args, error, __func__);
        if (!res)
                return FALSE;

        level = (int16_t) res->level;
        return dbus_simple_property_getter(iter, DBUS_TYPE_INT16,
                                                &level, error);
}

dbus_bool_t wpas_dbus_getter_bss_mode(
        const struct wpa_dbus_property_desc *property_desc,
        DBusMessageIter *iter, DBusError *error, void *user_data)
{
        struct bss_handler_args *args = user_data;
        struct wpa_bss *res;
        const char *mode;
        const uint8_t *mesh;

        res = get_bss_helper(args, error, __func__);
        if (!res) return FALSE;

        return dbus_simple_property_getter(iter, DBUS_TYPE_STRING,
                                                &mode, error);
}


dbus_bool_t wpas_dbus_getter_bss_privacy(
        const struct wpa_dbus_property_desc *property_desc,
        DBusMessageIter *iter, DBusError *error, void *user_data)
{            
        struct bss_handler_args *args = user_data;
        struct wpa_bss *res;
        dbus_bool_t privacy;
    
        res = get_bss_helper(args, error, __func__);
        if (!res)
                return FALSE;
    
        privacy = (res->caps & IEEE80211_CAP_PRIVACY) ? TRUE : FALSE;
        return dbus_simple_property_getter(iter, DBUS_TYPE_BOOLEAN,
                                                &privacy, error);
}

dbus_bool_t dbus_getter_bss_ssid(
        const struct wpa_dbus_property_desc *property_desc,
        DBusMessageIter *iter, DBusError *error, void *user_data)
{
        struct bss_handler_args *args = user_data;
        struct wpa_bss *res;

//    	printf("GETTER ====>arg.wpa_s:%p, id:%d\n", args->wpa_s, args->id);

	res = get_bss_helper(args, error, __func__);
	if (!res) return FALSE;
    
//	printf("In dbus_getter_bss_ssid:%s, res->ssid_len:%d\n", res->ssid, res->ssid_len);

        return dbus_simple_array_property_getter(iter, DBUS_TYPE_BYTE,
						res->ssid, res->ssid_len,
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
static DBusMessage * properties_get(DBusMessage *message,
                                    const struct wpa_dbus_property_desc *dsc,
                                    void *user_data)
{
        DBusMessage *reply;
        DBusMessageIter iter;
        DBusError error;

        if (os_strcmp(dbus_message_get_signature(message), "ss")) {
                return dbus_message_new_error(message, DBUS_ERROR_INVALID_ARGS,
                                              NULL);
        }

        if (dsc->getter == NULL) {
                return dbus_message_new_error(message, DBUS_ERROR_INVALID_ARGS,
                                              "Property is write-only");
        }

        reply = dbus_message_new_method_return(message);
        dbus_message_iter_init_append(reply, &iter);

        dbus_error_init(&error);
        if (dsc->getter(dsc, &iter, &error, user_data) == FALSE) {
                dbus_message_unref(reply);
                reply = dbus_reply_new_from_error(
                        message, &error, DBUS_ERROR_FAILED,
                        "Failed to read property");
                dbus_error_free(&error);
        }

        return reply;
}


static DBusMessage * properties_set(DBusMessage *message,
                                    const struct wpa_dbus_property_desc *dsc,
                                    void *user_data)
{
        DBusMessage *reply;
        DBusMessageIter iter;
        DBusError error;

        if (os_strcmp(dbus_message_get_signature(message), "ssv")) {
                return dbus_message_new_error(message, DBUS_ERROR_INVALID_ARGS,
                                              NULL);
        }

        if (dsc->setter == NULL) {
                return dbus_message_new_error(message, DBUS_ERROR_INVALID_ARGS,
                                              "Property is read-only");
        }

        dbus_message_iter_init(message, &iter);
        /* Skip the interface name and the property name */
        dbus_message_iter_next(&iter);
        dbus_message_iter_next(&iter);

        /* Iter will now point to the property's new value */
        dbus_error_init(&error);
        if (dsc->setter(dsc, &iter, &error, user_data) == TRUE) {
                /* Success */
                reply = dbus_message_new_method_return(message);
        } else {
                reply = dbus_reply_new_from_error(
                        message, &error, DBUS_ERROR_FAILED,
                        "Failed to set property");
                dbus_error_free(&error);
        }

        return reply;
}

static DBusMessage *
properties_get_or_set(DBusMessage *message, DBusMessageIter *iter,
                      char *interface,
                      struct wpa_dbus_object_desc *obj_dsc)
{
        const struct wpa_dbus_property_desc *property_dsc;
        char *property;
        const char *method;

        method = dbus_message_get_member(message);
        property_dsc = obj_dsc->properties;

        /* Second argument: property name (DBUS_TYPE_STRING) */
        if (!dbus_message_iter_next(iter) ||
            dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_STRING) {
                return dbus_message_new_error(message, DBUS_ERROR_INVALID_ARGS,
                                              NULL);
        }
        dbus_message_iter_get_basic(iter, &property);

        while (property_dsc && property_dsc->dbus_property) {
        	printf("\n**==============> Loop for property handler for %s.%s on %s, property_dsc->dbus_property:%s\n\n",
                           interface, property,
                           dbus_message_get_path(message), property_dsc->dbus_property);
                /* compare property names and
                 * interfaces */
                if (!os_strncmp(property_dsc->dbus_property, property,
                                WPAS_DBUS_METHOD_SIGNAL_PROP_MAX) &&
                    !os_strncmp(property_dsc->dbus_interface, interface,
                                WPAS_DBUS_INTERFACE_MAX))
                        break;

                property_dsc++;
        }
        if (property_dsc == NULL || property_dsc->dbus_property == NULL) {
                printf( "no property handler for %s.%s on %s",
                           interface, property,
                           dbus_message_get_path(message));
                return dbus_message_new_error(message, DBUS_ERROR_INVALID_ARGS,
                                              "No such property");
        }

        if (os_strncmp(WPA_DBUS_PROPERTIES_GET, method,
                       WPAS_DBUS_METHOD_SIGNAL_PROP_MAX) == 0) {
                printf( "%s: Get(%s)", __func__, property);
                return properties_get(message, property_dsc,
                                      obj_dsc->user_data);
        }

        printf( "%s: Set(%s)", __func__, property);
        return properties_set(message, property_dsc, obj_dsc->user_data);
}

DBusMessage *process_properties_msg_handler(DBusMessage *message, struct wpa_dbus_object_desc *obj_dsc) 
{
        DBusMessageIter iter;
        char *interface;
        const char *method;

        method = dbus_message_get_member(message);
        dbus_message_iter_init(message, &iter);

        printf("\n START: %s:%d: dbus_prop_msg_handler\n", __func__, __LINE__); 

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
                return properties_get_or_set(message, &iter, interface, obj_dsc);
        }    
        printf("\n END: %s:%d: dbus_prop_msg_handler\n", __func__, __LINE__); 
        return dbus_message_new_error(message, DBUS_ERROR_UNKNOWN_METHOD, NULL);

}


static void wpa_bss_copy_res(struct wpa_bss *dst, struct wpa_bss *src)
{
        dst->flags = src->flags;
        memcpy(dst->bssid, src->bssid, ETH_ALEN);
        dst->freq = src->freq;
        dst->beacon_int = src->beacon_int;
        dst->caps = src->caps;
        dst->qual = src->qual;
        dst->noise = src->noise;
        dst->level = src->level;
        dst->tsf = src->tsf;
        dst->beacon_newer = src->beacon_newer;
        dst->est_throughput = src->est_throughput;
        dst->snr = src->snr;

        memcpy(&dst->scan_bss_info.external_ap, &src->scan_bss_info.external_ap, sizeof(src->scan_bss_info.external_ap));
	dst->scan_bss_info.vap_index = src->scan_bss_info.vap_index;
	dst->scan_bss_info.radio_index = src->scan_bss_info.radio_index;
//        calculate_update_time(fetch_time, src->age, &dst->last_update);
}

static struct wpa_bss * wpa_bss_add(struct wpa_supplicant *wpa_s,
                                    const uint8_t *ssid, size_t ssid_len,
                                    struct wpa_bss *res, int bss_id)
{
        struct wpa_bss *bss = malloc(sizeof(*bss) + res->beacon_ie_len);

        if (bss == NULL) {
	    perror("malloc failed\n");
            return NULL;
	}
	memset(bss, 0, sizeof(struct wpa_bss));

        bss->id = bss_id;
        bss->last_update_idx = wpa_s->bss_update_idx;
        wpa_bss_copy_res(bss, res);
        strcpy(bss->ssid, ssid);
        bss->ssid_len = ssid_len;
        bss->ie_len = res->ie_len;
        bss->beacon_ie_len = res->beacon_ie_len;

	bss->ies = (uint8_t *)malloc(res->ie_len);
        memcpy(bss->ies, res->ies, res->ie_len);
        //wpa_bss_set_hessid(bss);

        dl_list_add_tail(&wpa_s->bss, &bss->list);
        dl_list_add_tail(&wpa_s->bss_id, &bss->list_id);

	printf("BSS LIST:%d, bss_id_list:%d\n", dl_list_len(&wpa_s->bss), dl_list_len(&wpa_s->bss_id));

        wpa_s->num_bss++;

	printf("\n@@@@@@@@@@@@@@@@@@@@@@@@@@@ In wpa_bss_add to add new SSID:%s\n", ssid);

        return bss;
}


const uint8_t * wpa_scan_get_ie(const struct wpa_bss *res, uint8_t ie)
{
        size_t ie_len = res->ie_len;

        /* Use the Beacon frame IEs if res->ie_len is not available */
        if (!ie_len)
                ie_len = res->beacon_ie_len;

        return (res->ies);
        //return get_ie((const uint8_t *) (res + 1), ie_len, ie);
}

static struct wpa_bss * wpa_bss_update(struct wpa_supplicant *wpa_s, struct wpa_bss *res)
{
        struct wpa_bss *bss = NULL;
    	printf("\n In UPDATE SCAN RESULT: %s:%d\n", __func__, __LINE__);
	return bss;
}

void update_scan_results(struct wpa_bss *res, int bss_id) {
    struct wpa_bss *bss;
    const uint8_t *ssid;

    ssid = wpa_scan_get_ie(res, WLAN_EID_SSID);
    if (ssid == NULL) {
    	printf("%s:%d: SSID IS NULL\n", __func__, __LINE__);
	return;
    }

    printf("%s:%d: wpa_s:%p, ssid:%s\n", __func__, __LINE__, wpa_s, res->ssid);

    bss = wpa_bss_get(wpa_s, res->bssid, res->ssid, strlen(res->ssid));
    if (bss == NULL) {
        bss = wpa_bss_add(wpa_s, res->ssid, strlen(res->ssid), res, bss_id);
	//dbus_register_bss(res, bss_id);
	dbus_register_bss(wpa_s, bss_id);
    } else {
	bss = wpa_bss_update(wpa_s, res);
    }
}

//int dbus_register_bss(struct wpa_bss *wpa_s, unsigned int bss_id) {
int dbus_register_bss(struct wpa_supplicant *wpa_s, unsigned int bss_id) {

    DBusMessageIter iter;
    char bss_obj_path[WPAS_DBUS_OBJECT_PATH_MAX];
    struct bss_handler_args *arg;

    snprintf(bss_obj_path, WPAS_DBUS_OBJECT_PATH_MAX, "%s/" WPAS_DBUS_NEW_BSSIDS_PART "/%u", INTERFACE_DBUS_SERVICE_PATH, bss_id);

//    printf("dbus_register_bss for BSS_ID:%d, bss_obj_path:%s\n", bss_id, bss_obj_path);

    arg = (struct bss_handler_args *) malloc(sizeof(struct bss_handler_args));
    arg->wpa_s = wpa_s;
    arg->id = bss_id;

    printf("====>arg.wpa_s:%p, id:%d\n", arg->wpa_s, arg->id);

    struct wpa_dbus_object_desc *wpa_obj_desc =  initialize_object_desc_param(bss_obj_path, arg, NULL, NULL, wpas_dbus_bss_properties, wpas_dbus_bss_signals);
    wpa_obj_desc->connection = connection;

    dbus_register_object_per_iface(bss_obj_path, wpa_s->ifname, wpa_obj_desc);
    dbus_signal_process(INTERFACE_DBUS_NEW_IFACE_INTERFACE, WPAS_DBUS_NEW_IFACE_BSS, INTERFACE_DBUS_SERVICE_PATH,
    	DBUS_SERVICE_NAME, "BSSAdded", TRUE, wpa_obj_desc->connection, bss_obj_path);
    
    dbus_signal_prop_changed(wpa_obj_desc->connection, INTERFACE_DBUS_SERVICE_PATH, WPAS_DBUS_PROP_BSSS);

    return 0;
}

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

        /* If handler succeed returning NULL, reply empty message */
        if (!reply)
                reply = dbus_message_new_method_return(message);
        if (reply) {
                if (!dbus_message_get_no_reply(message)) {
			printf("IN %s():%d calling dbus_connection_send\n", __func__, __LINE__);
                        dbus_connection_send(connection, reply, NULL);
		}
                dbus_message_unref(reply);
        }

    //dbus_message_unref(reply);
    return DBUS_HANDLER_RESULT_HANDLED;

}

void* dbus_initialize(void* arg) 
{
    int *global=NULL;
    int *dbus=NULL;

    printf("%s:%d: calling wpa_dbus_init API\n", __func__, __LINE__);

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

    notify_scanning(0);

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
