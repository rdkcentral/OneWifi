#ifndef WIFI_CSI_ANALYTICS_H
#define WIFI_CSI_ANALYTICS_H

#include "wifi_hal.h"
#include "wifi_csi.h"
#include "collection.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_LOG_MSG_PRINT_TIME_SEC 5

typedef struct csi_analytics_data {
    uint32_t num_sc;
    uint32_t decimation;
    uint32_t skip_mismatch_data_num;
    long long int csi_data_capture_time_sec;
} csi_analytics_data_t;

typedef struct csi_analytics_info {
    hash_map_t *csi_analytics_map;
} csi_analytics_info_t;

#ifdef __cplusplus
}
#endif
#endif
