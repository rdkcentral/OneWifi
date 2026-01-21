//
//  main.cpp
//  wifi_telemetry
//
//  Created by Munshi, Soumya on 9/27/25.
//

#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <errno.h>
#include "web.h"
#include "vector.h"
#include "sequence.h"
#include "wifi_hal.h"
#include "wifi_util.h"
#include "qmgr.h"
#include "run_qmgr.h"
static qmgr_report_cb_t g_qmgr_cb = NULL;

void qmgr_register_callback(qmgr_report_cb_t cb)
{
    g_qmgr_cb = cb;
}

/* Called internally from qmgr_t::run() */
extern "C" void qmgr_invoke_callback( const report_batch_t* batch)
{
    wifi_util_error_print(WIFI_CTRL,"%s:%d \n",__func__,__LINE__); 
    if (g_qmgr_cb) 
        g_qmgr_cb(batch);
    wifi_util_error_print(WIFI_CTRL,"%s:%d \n",__func__,__LINE__); 
}
int run_web_server()
{
    web_t *web;
    char path[64] = "/www/data";
    wifi_util_info_print(WIFI_APPS,"%s:%d \n",__func__,__LINE__); 
    web = web_t::get_instance(path);
    web->start();
    wifi_util_info_print(WIFI_APPS,"%s:%d \n",__func__,__LINE__); 
    return 0;
}

int stop_web_server(const char *path)
 {
    wifi_util_info_print(WIFI_APPS,"stoping web_server %s:%d \n",__func__,__LINE__);
    web_t *web;
    web = web_t::get_instance(path);   // always returns SAME instance
    wifi_util_info_print(WIFI_APPS,"Got web instance\n");
    web->stop();
    wifi_util_info_print(WIFI_APPS,"stopped web_server\n");
    return 0;
  }

int reinit_link_metrics(server_arg_t *ser_arg)
{
    wifi_util_info_print(WIFI_APPS,"started add_stats stats->\n"); 
    server_arg_t arg;
    memset(&arg, 0, sizeof(server_arg_t));
    strcpy(arg.path, "/www/data");
    snprintf(arg.output_file, sizeof(arg.output_file), "%s/telemetry.json", arg.path);
    arg.sampling =  SAMPLING_INTERVAL;
    arg.reporting = ser_arg->reporting;
    arg.threshold = ser_arg->threshold;

    qmgr_t *mgr;
    mgr = qmgr_t::get_instance(&arg);   // always returns SAME instance
    wifi_util_info_print(WIFI_APPS,"%s:%d reporting=%d threshold =%f\n",__func__,__LINE__,arg.reporting,arg.threshold); 

    mgr->reinit(&arg); 
    wifi_util_info_print(WIFI_APPS,"%s:%d \n",__func__,__LINE__); 
    return 0;
}

int start_link_metrics()
{
    wifi_util_info_print(WIFI_APPS,"started add_stats stats->\n"); 
    server_arg_t arg;
    memset(&arg, 0, sizeof(server_arg_t));
    strcpy(arg.path, "/www/data");
    snprintf(arg.output_file, sizeof(arg.output_file), "%s/telemetry.json", arg.path);
    arg.sampling =  SAMPLING_INTERVAL;
    arg.reporting = REPORTING_INTERVAL;
    arg.threshold = THRESHOLD;

    qmgr_t *mgr;
    mgr = qmgr_t::get_instance(&arg);   // always returns SAME instance
    wifi_util_info_print(WIFI_APPS,"%s:%d \n",__func__,__LINE__); 

    mgr->start_background_run(); 
    wifi_util_info_print(WIFI_APPS,"%s:%d \n",__func__,__LINE__); 
    return 0;
}


int add_stats_metrics(stats_arg_t *stats)
{
    qmgr_t *mgr;
    wifi_util_dbg_print(WIFI_APPS,"%s:%d \n",__func__,__LINE__); 
    server_arg_t arg;
    memset(&arg, 0, sizeof(server_arg_t));
    strcpy(arg.path, "/www/data");
    snprintf(arg.output_file, sizeof(arg.output_file), "%s/telemetry.json", arg.path);
    arg.sampling =  SAMPLING_INTERVAL;
    arg.reporting = REPORTING_INTERVAL;
    arg.threshold = THRESHOLD;
    wifi_util_dbg_print(WIFI_APPS,"mac_address=%s per =%f, snr=%d and phy=%d\n",stats->mac_str,stats->per,stats->snr,stats->phy); 
    
    mgr = qmgr_t::get_instance(&arg);   // always returns SAME instance

    mgr->init(stats,true);
    wifi_util_dbg_print(WIFI_APPS,"Added the stats data->\n"); 
    return 0;
}

int remove_link_stats( stats_arg_t  *stats)
{
    wifi_util_info_print(WIFI_APPS,"started  %s:%d \n",__func__,__LINE__); 
    server_arg_t arg;
    memset(&arg, 0, sizeof(server_arg_t));
    snprintf(arg.output_file, sizeof(arg.output_file), "%s/telemetry.json", arg.path);
    arg.sampling =  SAMPLING_INTERVAL;
    arg.reporting = REPORTING_INTERVAL;
    arg.threshold = THRESHOLD;

    qmgr_t *mgr;
    mgr = qmgr_t::get_instance(&arg);   // always returns SAME instance
    mgr->init(stats,false);
    wifi_util_info_print(WIFI_APPS,"mac_str=%s %s:%d \n",stats->mac_str,__func__,__LINE__); 
    return 0;
}
