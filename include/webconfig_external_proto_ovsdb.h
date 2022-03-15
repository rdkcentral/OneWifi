#ifndef EXTERNAL_PROTO_OVSDB_H
#define EXTERNAL_PROTO_OVSDB_H

typedef struct {
    const struct schema_Wifi_Radio_Config **radio_config;
    const struct schema_Wifi_VIF_Config **vif_config;
    const struct schema_Wifi_Credential_Config **cred_config;
    const struct schema_Wifi_Radio_State **radio_state;
    const struct schema_Wifi_VIF_State   **vif_state;

    const unsigned int radio_config_row_count;
    const unsigned int vif_config_row_count;
    const unsigned int radio_state_row_count;
    const unsigned int vif_state_row_count;

/* TBD: place for next arrays and other data, in particular
 *
 * * the supplementary STATE data read from OneWifi Manager
 * */

} webconfig_external_ovsdb_t;

#endif //EXTERNAL_PROTO_OVSDB_H
