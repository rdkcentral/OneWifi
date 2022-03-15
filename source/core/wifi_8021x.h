#ifndef WIFI_8021X_H
#define WIFI_8021X_H

typedef struct {
       hash_map_t      *sta_map;
       unsigned int eap_success;
       unsigned int eap_failure;
       unsigned int eap_timeout;
       unsigned int eap_retries;
       unsigned int wpa_msg_1_of_4;
       unsigned int wpa_msg_2_of_4;
       unsigned int wpa_msg_3_of_4;
       unsigned int wpa_msg_4_of_4;
       unsigned int wpa_failure;
       unsigned int wpa_success;
} bssid_8021x_t;

typedef struct {
       bssid_8021x_t   bssid[MAX_VAP];
       
} wifi_8021x_t;

typedef struct {
       unsigned int vap;
       mac_address_t mac;
       wifi_eapol_type_t type;
       void *data;
       unsigned int len;
       wifi_direction_t dir;   
       struct timeval      packet_time;
} wifi_8021x_data_t;

typedef struct {
    unsigned int vap;
    mac_address_t mac;
    wifi_direction_t    dir;
    void *data;
    unsigned int len;
    struct timeval      packet_time;
} wifi_assoc_req_data_t;

typedef struct {
    unsigned int vap;
    mac_address_t mac;
    wifi_direction_t    dir;
    void *data;
    unsigned int len;
    struct timeval      packet_time;
} wifi_assoc_rsp_data_t;

typedef struct {
    unsigned int vap;
    mac_address_t mac;
    wifi_direction_t    dir;
    void *data;
    unsigned int len;
    struct timeval      packet_time;
} wifi_auth_data_t;

#ifndef BIT
#define BIT(x) (1 << (x))
#endif
#define WPA_KEY_INFO_KEY_TYPE BIT(3)

void process_8021x_data_timeout(wifi_8021x_t *module);
void process_8021x_packet(wifi_8021x_data_t *data, wifi_8021x_t *module);
void process_auth_packet(wifi_auth_data_t *auth_data, wifi_8021x_t *module);
void process_assoc_req_packet(wifi_assoc_req_data_t *assoc_data, wifi_8021x_t *module);
void process_assoc_rsp_packet(wifi_assoc_rsp_data_t *assoc_data, wifi_8021x_t *module);
void deinit_8021x(wifi_8021x_t *module);
int init_8021x(wifi_8021x_t *module);


#endif // WIFI_8021X_H
