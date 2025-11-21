#ifndef WIFI_UAHF_H
#define WIFI_UAHF_H

#include <pthread.h>
#include "wifi_base.h"

typedef struct {
    void *data;
// Thread Management
    pthread_t worker_tid;
    bool worker_running;
    bool worker_done;

    // Data Buffers
    char input_cmd_data[1024];   // Data going INTO the system command
    char output_server_data[2048]; // Data coming OUT of the server
} uahf_data_t;

//typedef struct wifi_app wifi_app_t;

#endif
