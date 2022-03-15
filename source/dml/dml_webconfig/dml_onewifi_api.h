#ifndef WIFI_WEBCONFIG_DML_H
#define WIFI_WEBCONFIG_DML_H

#include "rbus.h"
#include "wifi_webconfig.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    hash_map_t  *acl_dev_map[MAX_NUM_RADIOS][MAX_NUM_VAP_PER_RADIO];
    void    *acl_vap_context;
    queue_t* new_entry_queue[MAX_NUM_RADIOS][MAX_NUM_VAP_PER_RADIO];
} acl_data_t;

typedef struct {
    webconfig_t		webconfig;
    wifi_global_config_t    config;
    wifi_hal_capability_t   hal_cap;
    rdk_wifi_radio_t    radios[MAX_NUM_RADIOS];
    active_msmt_t blaster;
    queue_t    *assoc_dev_queue[MAX_NUM_RADIOS][MAX_NUM_VAP_PER_RADIO];
    acl_data_t acl_data;
    rbusHandle_t	rbus_handle;
    instant_measurement_config_t harvester;
} webconfig_dml_t;

typedef struct {
    BOOL    kick_assoc_devices;
    BOOL    multicast_rate;
    ULONG   associated_devices_highwatermark_threshold;
    ULONG   retry_limit;
    ULONG   long_retry_limit;
    BOOL    bss_count_sta_as_cpe;
}dml_vap_default;

typedef struct {
    BOOL    AutoChannelSupported;
    BOOL    DCSSupported;
    CHAR    Alias[32];
    ULONG   SupportedFrequencyBands;
    CHAR    PossibleChannels[32];
    CHAR    TransmitPowerSupported[32];
    ULONG   SupportedDataTransmitRates;
    ULONG   BasicRate;
    ULONG   MaxBitRate;
    ULONG   ExtensionChannel;
    ULONG   SupportedStandards;
    CHAR    ChannelsInUse[32];
    INT     ThresholdRange;
    INT     ThresholdInUse;
} dml_radio_default;

#ifdef __cplusplus
}
#endif

#endif // WIFI_WEBCONFIG__DML_H
