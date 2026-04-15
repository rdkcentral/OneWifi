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

//Static callback functions
static qmgr_report_batch_cb_t qmgr_batch_cb = NULL;
static qmgr_report_score_cb_t qmgr_score_cb = NULL;
static qmgr_max_snr_cb_t g_qmgr_snr_cb = NULL;

//Register callback functions
void qmgr_register_batch_callback(qmgr_report_batch_cb_t cb)
{
    qmgr_batch_cb = cb;
}

void qmgr_register_max_snr_callback(qmgr_max_snr_cb_t cb)
{
    g_qmgr_snr_cb = cb;
}

void qmgr_register_score_callback(qmgr_report_score_cb_t cb)
/* Called internally from qmgr_t::run() */
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
}


extern "C" void qmgr_invoke_score(const char *str, double score,double threshold)
{
    if (qmgr_score_cb)
        qmgr_score_cb(str, score,threshold);
    wifi_util_error_print(WIFI_CTRL,"%s:%d \n",__func__,__LINE__); 
}
extern "C" void qmgr_invoke_max_snr_callback(int radio_index,int max_snr)
{
    wifi_util_error_print(WIFI_CTRL,"%s:%d \n",__func__,__LINE__); 
    if (g_qmgr_snr_cb) 
        g_qmgr_snr_cb(radio_index,max_snr);
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

int stop_web_server()
 {
    wifi_util_info_print(WIFI_APPS,"stoping web_server %s:%d \n",__func__,__LINE__);
    char path[64] = "/www/data";
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

    qmgr_t *qmgr;
    qmgr = qmgr_t::get_instance();   // always returns SAME instance

    qmgr->start_background_run(); 
    wifi_util_info_print(WIFI_APPS,"%s:%d \n",__func__,__LINE__); 
    return 0;
}

void register_station_mac(const char* str)
{

    qmgr_t *qmgr;
    qmgr = qmgr_t::get_instance();   // always returns SAME instance

    qmgr->register_station_mac(str); 
    wifi_util_info_print(WIFI_APPS,"%s:%d \n",__func__,__LINE__); 
    return ;
}

void unregister_station_mac(const char* str)
{

    qmgr_t *qmgr;
    qmgr = qmgr_t::get_instance();   // always returns SAME instance

    qmgr->unregister_station_mac(str); 
    qmgr_score_cb = NULL;
    wifi_util_info_print(WIFI_APPS,"%s:%d \n",__func__,__LINE__); 
    return ;
}

char*  get_link_metrics()
{

    qmgr_t *qmgr;
    qmgr = qmgr_t::get_instance();   // always returns SAME instance
    //return (qmgr->update_graph());
    return NULL;
}

int stop_link_metrics()
{
    qmgr_t::destroy_instance(); 
    wifi_util_info_print(WIFI_APPS,"%s:%d \n",__func__,__LINE__); 
    return 0;
}

int add_stats_metrics(stats_arg_t *stats,int len)
{
    qmgr_t *qmgr;
    wifi_util_dbg_print(WIFI_APPS,"mac_address=%s  snr=%d and phy=%d\n",stats->mac_str,stats->dev.cli_SNR,stats->dev.cli_LastDataDownlinkRate); 
    
    qmgr = qmgr_t::get_instance();   // always returns SAME instance
    for (int i =0;i<len;i++) {
        qmgr->init(&stats[i],true);
    }

    return 0;
}

int disconnect_link_stats( stats_arg_t  *stats)
{

    qmgr_t *qmgr;
    qmgr = qmgr_t::get_instance();   // always returns SAME instance
    qmgr->rapid_disconnect(stats);
    wifi_util_info_print(WIFI_APPS,"mac_str=%s %s:%d \n",stats->mac_str,__func__,__LINE__); 
    return 0;
}

int remove_link_stats( stats_arg_t  *stats)
{

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

int set_max_snr_radios(radio_max_snr_t *max_snr_val)
{
    wifi_util_info_print(WIFI_APPS,"started  %s:%d \n",__func__,__LINE__);
    qmgr_t *mgr;
    mgr = qmgr_t::get_instance();   // always returns SAME instance
    mgr->set_max_snr_radios(max_snr_val);
    return 0;
}

int update_affinity_stats(stats_arg_t *arg,bool flag)
{
    wifi_util_info_print(WIFI_APPS,"started  %s:%d \n",__func__,__LINE__);
    qmgr_t *mgr;
    mgr = qmgr_t::get_instance();   // always returns SAME instance
    mgr->update_affinity_stats(arg,flag);
    return 0;
}

int periodic_caffinity_stats_update(stats_arg_t *stats,int len)
{
    wifi_util_info_print(WIFI_APPS,"started  %s:%d mac=%s\n",__func__,__LINE__, stats->mac_str);
    qmgr_t *mgr;
    mgr = qmgr_t::get_instance();   // always returns SAME instance
    for (int i =0;i<len;i++) {
        mgr->caffinity_periodic_stats_update(&stats[i]);
    }
    return 0;
}

bool is_client_connected(const char *mac_str)
{
    qmgr_t *mgr;
    mgr = qmgr_t::get_instance();   // always returns SAME instance
    return mgr->is_client_connected(mac_str);
}

int store_gw_mac(uint8_t *mac)
{
    wifi_util_info_print(WIFI_APPS,"started  %s:%d \n",__func__,__LINE__);
    return qmgr_t::store_gw_mac(mac);
}
int get_gw_mac(uint8_t *mac)
{
    wifi_util_info_print(WIFI_APPS,"started  %s:%d \n",__func__,__LINE__);
    return qmgr_t::get_gw_mac(mac);
}
