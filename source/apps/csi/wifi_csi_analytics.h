#ifndef WIFI_CSI_ANALYTICS_H
#define WIFI_CSI_ANALYTICS_H

#include "bus.h"
#include "collection.h"
#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_LOG_MSG_PRINT_TIME_SEC 10
#define MAX_MACLIST_SIZE 512
#define MAX_MAC_STR_SIZE 18
#define STA_MAC_LIST_DELIMITER ','
#define CSI_ENABLE_TRIGGER_SEC 2
#define CSI_STA_MACLIST_SET_SEC 3
#define CSI_ANALYTICS_INTERVAL 300

#define CSI_CLIENT_MACLIST "Device.WiFi.X_RDK_CSI.%d.ClientMaclist"
#define CSI_ENABLE_NAME "Device.WiFi.X_RDK_CSI.%d.Enable"
#define CSI_SUB_DATA "Device.WiFi.X_RDK_CSI.%d.data"

typedef struct csi_analytics_data {
    uint32_t num_sc;
    uint32_t decimation;
    uint32_t skip_mismatch_data_num;
    long long int csi_data_capture_time_sec;
} csi_analytics_data_t;

typedef struct csi_analytics_info {
    int32_t pipe_read_fd;
    bool is_read_oper_thread_enabled;
    uint32_t csi_session_index;
    bool is_csi_capture_enabled;
    pthread_mutex_t maclist_lock;
    char sta_mac[MAX_MACLIST_SIZE];
    int sta_maclist_sched_id;
    int csi_analytics_enable_sched_id;
    hash_map_t *csi_analytics_map;
} csi_analytics_info_t;

#ifdef __cplusplus
}
#endif
#endif
