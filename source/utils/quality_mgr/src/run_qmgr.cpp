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
#include "vector.h"
#include "sequence.h"
#include "wifi_hal.h"
#include "wifi_util.h"
#include "qmgr.h"
#include "run_qmgr.h"
//Static callback functions
static qmgr_report_batch_cb_t qmgr_batch_cb = NULL;
static qmgr_report_score_cb_t qmgr_score_cb = NULL;

//Register callback functions
void qmgr_register_batch_callback(qmgr_report_batch_cb_t cb)
{
    wifi_util_info_print(WIFI_APPS, "%s:%d\n", __func__, __LINE__);
    qmgr_batch_cb = cb;
}

void qmgr_register_score_callback(qmgr_report_score_cb_t cb)
{
    qmgr_score_cb = cb;
}

//check if callback functions are registered

bool qmgr_is_batch_registered(void)
{
    return (qmgr_batch_cb != NULL);
}

bool qmgr_is_score_registered(void)
{
    return (qmgr_score_cb != NULL);
}

void reset_qmgr_score_cb(void) {
    qmgr_score_cb = NULL;
}
/* Invoking of callbacks  Called internally from qmgr_t::run() */
extern "C" void qmgr_invoke_batch(const report_batch_t *batch)
{
    if (qmgr_batch_cb)
        qmgr_batch_cb(batch);
    wifi_util_dbg_print(WIFI_CTRL,"%s:%d \n",__func__,__LINE__); 
}


extern "C" void qmgr_invoke_score(const char *str, double score,double threshold)
{
    if (qmgr_score_cb)
        qmgr_score_cb(str, score,threshold);
    wifi_util_dbg_print(WIFI_CTRL,"%s:%d \n",__func__,__LINE__); 
}


int reinit_link_metrics(server_arg_t *ser_arg)
{
    wifi_util_info_print(WIFI_APPS,"started add_stats stats->\n"); 
    server_arg_t arg;
    memset(&arg, 0, sizeof(server_arg_t));
    if ( ser_arg->sampling == 0) {
       arg.sampling = SAMPLING_INTERVAL;
    } else { 
       arg.sampling =  ser_arg->sampling;
    }
    if ( ser_arg->reporting == 0) {
        arg.reporting = REPORTING_INTERVAL;
    } else { 
        arg.reporting = ser_arg->reporting;
    }
    if ( ser_arg->threshold == 0.0) {
        arg.threshold = THRESHOLD;
    } else {
        arg.threshold = ser_arg->threshold;
    }
    qmgr_t *qmgr;
    qmgr = qmgr_t::get_instance();   // always returns SAME instance
    wifi_util_info_print(WIFI_APPS,"%s:%d reporting=%d threshold =%f\n",__func__,__LINE__,arg.reporting,arg.threshold); 

    qmgr->reinit(&arg); 
    return 0;
}

int start_link_metrics()
{
    wifi_util_info_print(WIFI_APPS,"%s:%d \n",__func__,__LINE__); 

    qmgr_t *qmgr;
    qmgr = qmgr_t::get_instance();   // always returns SAME instance

    qmgr->start_background_run(); 
    wifi_util_info_print(WIFI_APPS,"%s:%d \n",__func__,__LINE__); 
    return 0;
}

void register_station_mac(const char* str)
{
    wifi_util_info_print(WIFI_APPS,"%s:%d \n",__func__,__LINE__); 

    qmgr_t *qmgr;
    qmgr = qmgr_t::get_instance();   // always returns SAME instance

    qmgr->register_station_mac(str); 
    wifi_util_info_print(WIFI_APPS,"%s:%d \n",__func__,__LINE__); 
    return ;
}

void unregister_station_mac(const char* str)
{
    wifi_util_info_print(WIFI_APPS,"%s:%d \n",__func__,__LINE__); 

    qmgr_t *qmgr;
    qmgr = qmgr_t::get_instance();   // always returns SAME instance

    qmgr->unregister_station_mac(str); 
    qmgr_score_cb = NULL;
    wifi_util_info_print(WIFI_APPS,"%s:%d \n",__func__,__LINE__); 
    return ;
}

char*  get_link_metrics()
{
    wifi_util_info_print(WIFI_APPS,"%s:%d\n",__func__,__LINE__); 

    qmgr_t *qmgr;
    qmgr = qmgr_t::get_instance();   // always returns SAME instance
    return (qmgr->update_graph());

}

int stop_link_metrics()
{
    wifi_util_info_print(WIFI_APPS,"%s:%d\n",__func__,__LINE__); 
    qmgr_t::destroy_instance(); 
    wifi_util_info_print(WIFI_APPS,"%s:%d \n",__func__,__LINE__); 
    return 0;
}

int add_stats_metrics(stats_arg_t *stats)
{
    qmgr_t *qmgr;
    wifi_util_dbg_print(WIFI_APPS,"%s:%d \n",__func__,__LINE__); 
    wifi_util_dbg_print(WIFI_APPS,"mac_address=%s  snr=%d and phy=%d\n",stats->mac_str,stats->dev.cli_SNR,stats->dev.cli_LastDataDownlinkRate); 
    
    qmgr = qmgr_t::get_instance();   // always returns SAME instance

    qmgr->init(stats,true);
    return 0;
}

int disconnect_link_stats( stats_arg_t  *stats)
{
    wifi_util_info_print(WIFI_APPS,"started  %s:%d \n",__func__,__LINE__); 

    qmgr_t *qmgr;
    qmgr = qmgr_t::get_instance();   // always returns SAME instance
    qmgr->rapid_disconnect(stats);
    wifi_util_info_print(WIFI_APPS,"mac_str=%s %s:%d \n",stats->mac_str,__func__,__LINE__); 
    return 0;
}

int remove_link_stats( stats_arg_t  *stats)
{
    wifi_util_info_print(WIFI_APPS,"started  %s:%d \n",__func__,__LINE__); 

    qmgr_t *qmgr;
    qmgr = qmgr_t::get_instance();   // always returns SAME instance
    qmgr->init(stats,false);
    wifi_util_info_print(WIFI_APPS,"mac_str=%s %s:%d \n",stats->mac_str,__func__,__LINE__); 
    return 0;
}

int set_quality_flags(quality_flags_t *flag)
{
    wifi_util_info_print(WIFI_APPS,"%s:%d \n",__func__,__LINE__); 
    qmgr_t::set_quality_flags(flag);
    return 0;
}

int get_quality_flags(quality_flags_t *flag)
{
    wifi_util_info_print(WIFI_APPS,"%s:%d \n",__func__,__LINE__); 
    qmgr_t::get_quality_flags(flag);
    return 0;
}
