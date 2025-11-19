#ifndef WIFI_UAHF_SERVER_H
#define WIFI_UAHF_SERVER_H

typedef struct {
    void *data;
} uahf_server_data_t;

int uahf_start_server(void);

#endif
