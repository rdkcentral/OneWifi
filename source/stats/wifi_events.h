#ifndef _WIFI_EVENTS_H_
#define _WIFI_EVENTS_H_

#include "wifi_hal.h"
#include "collection.h"
#include "wifi_monitor.h"


#define MAX_CSI_INTERVAL    30000
#define MIN_CSI_INTERVAL    100

#define MIN_DIAG_INTERVAL    5000
int events_init(void);
int events_publish(wifi_monitor_data_t data);
int events_deinit(void);
void events_update_clientdiagdata(unsigned int num_devs, int vap_idx, wifi_associated_dev3_t *dev_array);


#endif
