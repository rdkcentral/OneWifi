#ifndef WIFI_SUPP_H
#define WIFI_SUPP_H

#include <dbus/dbus.h>
#include "wifi_util.h"
#include "list.h"
#include "ssid.h"
#include "common/ieee802_11_defs.h"
#include "common/wpa_common.h"

#define IEEE80211_CAP_ESS       0x0001
#define IEEE80211_CAP_IBSS      0x0002
#define IEEE80211_CAP_PRIVACY   0x0010
#define IEEE80211_CAP_RRM       0x1000

/* DMG (60 GHz) IEEE 802.11ad */
/* type - bits 0..1 */
#define IEEE80211_CAP_DMG_MASK  0x0003
#define IEEE80211_CAP_DMG_IBSS  0x0001 /* Tx by: STA */
#define IEEE80211_CAP_DMG_PBSS  0x0002 /* Tx by: PCP */
#define IEEE80211_CAP_DMG_AP    0x0003 /* Tx by: AP */

#define RDKB_DBUS_TYPE_BIN_ARRAY ((int) '@')

#define END_ARGS { NULL, NULL, ARG_IN }

#define ETH_ALEN 		6
#define SSID_MAX_LEN            32

#define BYTE_ARRAY_CHUNK_SIZE 34
#define BYTE_ARRAY_ITEM_SIZE (sizeof(char))
#define STR_ARRAY_CHUNK_SIZE 8
#define STR_ARRAY_ITEM_SIZE (sizeof(char *))
#define BIN_ARRAY_CHUNK_SIZE 10
#define BIN_ARRAY_ITEM_SIZE (sizeof(struct wpabuf *))

#define RDKB_DBUS_SERVICE_NAME    	"fi.w1.wpa_supplicant1"
#define RDKB_DBUS_OBJ_PATH 	    	"/fi/w1/wpa_supplicant1"
#define RDKB_DBUS_INTERFACE_NAME  	"fi.w1.wpa_supplicant1"

#define RDKB_DBUS_NEW_INTERFACE		RDKB_DBUS_INTERFACE_NAME	".Interface"
#define RDKB_DBUS_NEW_PATH_INTERFACES   RDKB_DBUS_OBJ_PATH 		"/Interfaces"
#define RDKB_DBUS_NEW_INTERFACE_PATH 	"/fi/w1/wpa_supplicant1/Interfaces/0"

#define RDKB_DBUS_ERROR_INVALID_ARGS    RDKB_DBUS_INTERFACE_NAME ".InvalidArgs"
#define RDKB_DBUS_UNKNOWN_ERROR 	RDKB_DBUS_INTERFACE_NAME ".UnknownError"

#define RDKB_DBUS_IFACE_SCAN_ERROR 	RDKB_DBUS_NEW_INTERFACE ".ScanError"

#define RDKB_DBUS_NEW_BSSIDS_PART 		"BSSs"
#define RDKB_DBUS_NEW_IFACE_BSS 		RDKB_DBUS_INTERFACE_NAME ".BSS"

#define RDKB_DBUS_NEW_NETWORKS_PART 		"Networks"
#define RDKB_DBUS_NEW_IFACE_NETWORK 		RDKB_DBUS_INTERFACE_NAME ".Network"

#define RDKB_DBUS_OBJ_PATH_MAX 		150
#define RDKB_DBUS_INTERFACE_MAX 		150
#define RDKB_DBUS_METHOD_SIGNAL_PROP_MAX 	50

#define RDKB_DBUS_PROP_INTERFACE "org.freedesktop.DBus.Properties"
#define RDKB_DBUS_PROP_GET "Get"
#define RDKB_DBUS_PROP_SET "Set"
#define RDKB_DBUS_PROP_GETALL "GetAll"


typedef enum rdkb_dbus_wifi_prop {
        RDKB_DBUS_WIFI_PROP_AP_SCAN,
        RDKB_DBUS_WIFI_PROP_SCANNING,
        RDKB_DBUS_WIFI_PROP_STATE,
        RDKB_DBUS_WIFI_PROP_CURRENT_BSS,
        RDKB_DBUS_WIFI_PROP_CURRENT_NETWORK,
        RDKB_DBUS_WIFI_PROP_CURRENT_AUTH_MODE,
        RDKB_DBUS_WIFI_PROP_BSSS,
        RDKB_DBUS_WIFI_PROP_STATIONS,
        RDKB_DBUS_WIFI_PROP_DISCONNECT_REASON,
        RDKB_DBUS_WIFI_PROP_AUTH_STATUS_CODE,
        RDKB_DBUS_WIFI_PROP_ASSOC_STATUS_CODE,
        RDKB_DBUS_WIFI_PROP_ROAM_TIME,
        RDKB_DBUS_WIFI_PROP_ROAM_COMPLETE,
        RDKB_DBUS_WIFI_PROP_SESSION_LENGTH,
        RDKB_DBUS_WIFI_PROP_BSS_TM_STATUS,
} rdkb_dbus_wifi_prop_t;

enum sta_states {
	STA_DISCONNECTED,
	STA_INTERFACE_DISABLED,
	STA_INACTIVE,
	STA_SCANNING,
	STA_AUTHENTICATING,
	STA_ASSOCIATING,
	STA_ASSOCIATED,
	STA_4WAY_HANDSHAKE,
	STA_GROUP_HANDSHAKE,
	STA_COMPLETED
};

typedef enum rdkb_supp_dbus_obj {
    global_supp_dbus_obj,
    interface_supp_dbus_obj,
    bss_supp_dbus_obj,
    network_supp_dbus_obj,
    max_supp_dbus_obj
} rdkb_supp_dbus_obj_t;

typedef DBusMessage * (*rdkb_dBus_method_handler)(DBusMessage *message,
                                              void *user_data);
typedef void (*rdkb_dbus_arg_free_func)(void *handler_arg);

typedef struct rdkb_dbus_wifi_prop_desc rdkb_dbus_wifi_prop_desc_t;

typedef dbus_bool_t (*rdkb_dbus_wifi_prop_accessor)(
        const rdkb_dbus_wifi_prop_desc_t *property_desc,
        DBusMessageIter *iter, DBusError *error, void *user_data);

typedef enum rdkb_dbus_arg_dir {
    ARG_IN,
    ARG_OUT
} rdkb_dbus_arg_dir_t;
    
typedef struct rdkb_dbus_arg {
        char *name;
        char *type;
        rdkb_dbus_arg_dir_t dir;   
} rdkb_dbus_arg_t;

typedef struct rdkb_dbus_wifi_method_desc {
        const char *dbus_method;
        const char *dbus_interface;
        rdkb_dBus_method_handler method_handler;
        rdkb_dbus_arg_t args[4];
} rdkb_dbus_wifi_method_desc_t;

typedef struct rdkb_dbus_wifi_signal_desc {
        const char *dbus_signal;
        const char *dbus_interface;
        rdkb_dbus_arg_t args[4];
} rdkb_dbus_wifi_signal_desc_t;

typedef struct rdkb_dbus_wifi_prop_desc {
        const char *dbus_property;
        const char *dbus_interface;
        const char *type;
        rdkb_dbus_wifi_prop_accessor getter;
        rdkb_dbus_wifi_prop_accessor setter;
        const char *data;
} rdkb_dbus_wifi_prop_desc_t;

typedef struct rdkb_dbus_wifi_obj_desc {
        DBusConnection *connection;
        char *path;

        /* list of methods, properties and signals registered with object */
        const rdkb_dbus_wifi_method_desc_t *methods;
        const rdkb_dbus_wifi_signal_desc_t *signals;
        const rdkb_dbus_wifi_prop_desc_t *properties;

        /* property changed flags */
        unsigned int *prop_changed_flags;

        /* argument for method handlers and properties
         * getter and setter functions */
        void *user_data;
        /* function used to free above argument */
        rdkb_dbus_arg_free_func user_data_free_func;
} rdkb_dbus_wifi_obj_desc_t;

typedef struct scan_list_bss_info {
    uint32_t network_ssid_id;
    int vap_index;
    int radio_index;
    wifi_bss_info_t external_ap;
    char password[64];
} scan_list_bss_info_t;


typedef struct network_mgr_cfg {
    uint32_t scan_ssid;
    char ssid[32];
    char security_type[32];
    char password[64];
    char bgscan[64];
} network_mgr_cfg_t;

typedef struct rdkb_wifi_bss {
        struct dl_list list;
        struct dl_list list_id;
        unsigned int id;
        unsigned int scan_miss_count;
        unsigned int last_update_idx;
        unsigned int flags;
        uint8_t bssid[ETH_ALEN];
        uint8_t hessid[ETH_ALEN];
        uint8_t ssid[SSID_MAX_LEN];
        size_t ssid_len;
        int freq;
        uint16_t beacon_int;
        uint16_t caps;
        int qual;
        int noise;
        int level;
        uint64_t tsf;
        bool beacon_newer;
        unsigned int est_throughput;
        int snr;
        size_t ie_len;
        size_t beacon_ie_len;
        uint8_t *ies;
        scan_list_bss_info_t  scan_bss_info;
} rdkb_wifi_bss_t;

typedef struct rdkb_wifi_supp_param_t {
	char dbus_new_path[RDKB_DBUS_OBJ_PATH_MAX];
	char ifname[32];
        unsigned int bss_next_id;
        unsigned int bss_update_idx;
        struct dl_list bss; /* rdkb_wifi_bss_t::list */
        struct dl_list bss_id; /* rdkb_wifi_bss_t::list_id */
        size_t num_bss;
        scan_list_bss_info_t  *p_scan_bss_info;
} rdkb_wifi_supp_param_t;

struct network_handler_args {
        rdkb_wifi_supp_param_t *wpa_s;
        scan_list_bss_info_t  *scan_bss_info;
};

struct bss_handler_args {
        rdkb_wifi_supp_param_t *wpa_s;
        unsigned int id;
};

struct sta_handler_args {
        rdkb_wifi_supp_param_t *wpa_s;
        const u8 *sta;
};

typedef struct rdkb_dbus_dict_entry {
        int type;         /** the dbus type of the dict entry's value */
        int array_type;   /** the dbus type of the array elements if the dict
                              entry value contains an array, or the special
                              RDKB_DBUS_TYPE_BIN_ARRAY */
        const char *key;  /** key of the dict entry */

        /** Possible values of the property */
        union {
                char *str_value;
                char byte_value;
                dbus_bool_t bool_value;
                dbus_int16_t int16_value;
                dbus_uint16_t uint16_value;
                dbus_int32_t int32_value;
                dbus_uint32_t uint32_value;
                dbus_int64_t int64_value;
                dbus_uint64_t uint64_value;
                double double_value;
                char *bytearray_value;
                char **strarray_value;
                struct wpabuf **binarray_value;
        };
        dbus_uint32_t array_len; /** length of the array if the dict entry's
                                     value contains an array */
} rdkb_dbus_dict_entry_t;

typedef struct rdkb_wifi_supp_info {
    rdkb_dbus_wifi_obj_desc_t wifi_dbus_obj_desc[max_supp_dbus_obj];
    rdkb_wifi_supp_param_t    supp_info;
} rdkb_wifi_supp_info_t;

void* dbus_initialize(void* arg);
int notify_scanning(int num);

int snprintf_error(size_t size, int res);

DBusHandlerResult rdkb_dbus_message_handler(DBusConnection *connection, DBusMessage *message, void *user_data);

dbus_bool_t rdkb_dbus_dict_open_write(DBusMessageIter *iter,
                                     DBusMessageIter *iter_dict);
dbus_bool_t rdkb_dbus_dict_close_write(DBusMessageIter *iter,
                                      DBusMessageIter *iter_dict);

dbus_bool_t rdkb_dbus_getter_bss_bssid(
        const rdkb_dbus_wifi_prop_desc_t *property_desc,
        DBusMessageIter *iter, DBusError *error, void *user_data);

dbus_bool_t rdkb_dbus_getter_bss_ssid(
        const rdkb_dbus_wifi_prop_desc_t *property_desc,
        DBusMessageIter *iter, DBusError *error, void *user_data);

dbus_bool_t rdkb_dbus_getter_state(
        const rdkb_dbus_wifi_prop_desc_t *property_desc,
        DBusMessageIter *iter, DBusError *error, void *user_data);

static dbus_bool_t fill_dict_with_prop(
        DBusMessageIter *dict_iter,
        const rdkb_dbus_wifi_prop_desc_t *props,
        const char *interface, void *user_data, DBusError *error);

static rdkb_wifi_bss_t *rdkb_get_bss_helper(struct bss_handler_args *args,
                                       DBusError *error, const char *func_name);

dbus_bool_t rdkb_dbus_getter_bss_privacy(
        const rdkb_dbus_wifi_prop_desc_t *property_desc,
        DBusMessageIter *iter, DBusError *error, void *user_data);

dbus_bool_t rdkb_dbus_getter_bss_mode(
        const rdkb_dbus_wifi_prop_desc_t *property_desc,
        DBusMessageIter *iter, DBusError *error, void *user_data);

dbus_bool_t rdkb_dbus_getter_bss_signal(
        const rdkb_dbus_wifi_prop_desc_t *property_desc,
        DBusMessageIter *iter, DBusError *error, void *user_data);

dbus_bool_t rdkb_dbus_getter_bss_freq(
        const rdkb_dbus_wifi_prop_desc_t *property_desc,
        DBusMessageIter *iter, DBusError *error, void *user_data);

dbus_bool_t rdkb_dbus_getter_bss_rates(
        const rdkb_dbus_wifi_prop_desc_t *property_desc,
        DBusMessageIter *iter, DBusError *error, void *user_data);

DBusMessage *rdkb_dbus_handler_add_network(DBusMessage *message,
                                            rdkb_wifi_supp_param_t *wpa_s);

DBusMessage * rdkb_dbus_handler_select_network(DBusMessage *message,
                                               rdkb_wifi_supp_param_t *wpa_s);

DBusMessage * rdkb_dbus_reply_new_from_error(DBusMessage *message,
                                             DBusError *error,
                                             const char *fallback_name,
                                             const char *fallback_string);

dbus_bool_t rdkb_dbus_simple_array_prop_getter(DBusMessageIter *iter,
                                                   const int type,
                                                   const void *array,
                                                   size_t array_len,
                                                   DBusError *error);

dbus_bool_t rdkb_dbus_simple_prop_setter(DBusMessageIter *iter,
                                             DBusError *error,
                                             const int type, void *val);

dbus_bool_t rdkb_dbus_getter_bss_rsn(
        const rdkb_dbus_wifi_prop_desc_t *property_desc,
        DBusMessageIter *iter, DBusError *error, void *user_data);

dbus_bool_t rdkb_dbus_setter_iface_global(
        const rdkb_dbus_wifi_prop_desc_t *property_desc,
        DBusMessageIter *iter, DBusError *error, void *user_data);

dbus_bool_t rdkb_dbus_getter_ap_scan(
        const rdkb_dbus_wifi_prop_desc_t *property_desc,
        DBusMessageIter *iter, DBusError *error, void *user_data);

dbus_bool_t rdkb_dbus_setter_ap_scan(
        const rdkb_dbus_wifi_prop_desc_t *property_desc,
        DBusMessageIter *iter, DBusError *error, void *user_data);

static void rdkb_dbus_signal_network(rdkb_wifi_supp_param_t *wpa_s,
                                       int id, const char *sig_name,
                                       dbus_bool_t properties);

DBusMessage * rdkb_dbus_error_no_memory(DBusMessage *message);

const char *rdkb_dbus_type_as_string(const int type);

DBusMessage *rdkb_dbus_handler_create_interface(DBusMessage *message, void *global);
DBusMessage *rdkb_dbus_handler_scan(DBusMessage *message);
dbus_bool_t rdkb_dbus_getter_wifi_cap(const rdkb_dbus_wifi_prop_desc_t *property_desc,
              DBusMessageIter *iter, DBusError *error, void *user_data);

#endif /* WIFI_SUPP_H */
