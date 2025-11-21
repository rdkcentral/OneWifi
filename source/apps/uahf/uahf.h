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

    // Result Data
    char username[200]; // To store captured username
    char password[200]; // To store captured password
} uahf_data_t;
#define GET_UAHF(app) (&((app)->data.u.uahf_data))
//typedef struct wifi_app wifi_app_t;

#endif
