#include <stdio.h>
#include <stdbool.h>
#include "stdlib.h"
#include <pthread.h>
#include <ev.h>
#include <sys/time.h>
#include "wifi_data_plane.h"
#include "wifi_monitor.h"
#include "wifi_db.h"
#include "wifi_mgr.h"
#include "wifi_ctrl.h"
#include "ssp_main.h"

#include "wifi_util.h"

#include <execinfo.h>

#include <semaphore.h>
#include <fcntl.h>

wifi_mgr_t g_wifi_mgr;
sem_t *sem;

static void daemonize(void) {
    int fd;

    /* initialize semaphores for shared processes */
    sem = sem_open ("pSemCcspWifi", O_CREAT | O_EXCL, 0644, 0);
    if (SEM_FAILED == sem) {
        wifi_util_dbg_print(WIFI_MGR,"Failed to create semaphore %d - %s\n", errno, strerror(errno));
        _exit(1);
    }
    /* name of semaphore is "pSemCcspWifi", semaphore is reached using this name */
    sem_unlink ("pSemCcspWifi");
    /* unlink prevents the semaphore existing forever */
    /* if a crash occurs during the execution         */
    wifi_util_dbg_print(WIFI_MGR,"Semaphore initialization Done!!\n");

    switch (fork()) {
        case 0:
            break;
        case -1:
            // Error
            wifi_util_dbg_print(WIFI_MGR,"Error daemonizing (fork)! %d - %s\n", errno, strerror(errno));
            exit(0);
            break;
        default:
            sem_wait (sem);
            sem_close (sem);
            _exit(0);
    }

    if (setsid() < 0) {
        wifi_util_dbg_print(WIFI_MGR,"Error demonizing (setsid)! %d - %s\n", errno, strerror(errno));
        exit(0);
    }

    fd = open("/dev/null", O_RDONLY);
    if (fd != 0) {
        dup2(fd, 0);
        close(fd);
    }
    fd = open("/dev/null", O_WRONLY);
    if (fd != 1) {
        dup2(fd, 1);
        close(fd);
    }
    fd = open("/dev/null", O_WRONLY);
    if (fd != 2) {
        dup2(fd, 2);
        close(fd);
    }
}

wifi_db_t *get_wifidb_obj(void)
{
    return &g_wifi_mgr.wifidb;
}

wifi_ctrl_t *get_wifictrl_obj(void)
{
    return &g_wifi_mgr.ctrl;
}

wifi_mgr_t *get_wifimgr_obj(void)
{
    return &g_wifi_mgr;
}

int init_wifi_hal()
{
    int ret = RETURN_OK;

    wifi_util_dbg_print(WIFI_CTRL,"%s: start wifi hal init\n",__FUNCTION__);

    ret = wifi_hal_init();
    if (ret != RETURN_OK) {
        wifi_util_dbg_print(WIFI_CTRL,"%s wifi_init failed:ret :%d\n",__FUNCTION__, ret);
        return RETURN_ERR;
    }

    /* Get the wifi capabilities from from hal*/
    ret = wifi_hal_getHalCapability(&g_wifi_mgr.hal_cap);
    if (ret != RETURN_OK) {
        wifi_util_dbg_print(WIFI_CTRL,"RDK_LOG_ERROR, %s wifi_getHalCapability returned with error %d\n", __FUNCTION__, ret);
        return RETURN_ERR;
    }

    return RETURN_OK;
}

int init_global_radio_config(rdk_wifi_radio_t *radios_cfg, UINT radio_index)
{
    UINT vap_array_index = 0;
    UINT i;
    wifi_hal_capability_t *wifi_hal_cap_obj = rdk_wifi_get_hal_capability_map();

    if (radios_cfg == NULL) {
        wifi_util_dbg_print(WIFI_CTRL,"%s:%d NULL Pointer\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    snprintf(radios_cfg->name, sizeof(radios_cfg->name),"radio%d", radio_index+1);
    for (i = 0; i < (sizeof(wifi_hal_cap_obj->wifi_prop.interface_map)/sizeof(wifi_interface_name_idex_map_t)); i++)
    {
        if (wifi_hal_cap_obj->wifi_prop.interface_map[i].rdk_radio_index == radio_index) {
            radios_cfg->vaps.rdk_vap_array[vap_array_index].vap_index = wifi_hal_cap_obj->wifi_prop.interface_map[i].index;
            radios_cfg->vaps.vap_map.vap_array[vap_array_index].vap_index = wifi_hal_cap_obj->wifi_prop.interface_map[i].index;
            radios_cfg->vaps.vap_map.vap_array[vap_array_index].radio_index = radio_index;
            strcpy((char *)radios_cfg->vaps.rdk_vap_array[vap_array_index].vap_name, (char *)wifi_hal_cap_obj->wifi_prop.interface_map[i].vap_name);
            strcpy((char *)radios_cfg->vaps.vap_map.vap_array[vap_array_index].vap_name, (char *)wifi_hal_cap_obj->wifi_prop.interface_map[i].vap_name);

            radios_cfg->vaps.rdk_vap_array[vap_array_index].associated_devices_queue = queue_create();
            if (radios_cfg->vaps.rdk_vap_array[vap_array_index].associated_devices_queue == NULL) {
                wifi_util_dbg_print(WIFI_CTRL,"%s:%d queue_create(associated_devices_queue) failed\n",__FUNCTION__, __LINE__);
            }
            radios_cfg->vaps.rdk_vap_array[vap_array_index].acl_map = hash_map_create();
            if (radios_cfg->vaps.rdk_vap_array[vap_array_index].acl_map == NULL) {
                wifi_util_dbg_print(WIFI_CTRL,"%s:%d hash_map_create(acl_map) failed\n",__FUNCTION__, __LINE__);
            }
            vap_array_index++;
            if (vap_array_index >= MAX_NUM_VAP_PER_RADIO) {
                break;
            }
        }
    }
    radios_cfg->vaps.radio_index = radio_index;
    radios_cfg->vaps.num_vaps = vap_array_index;
    radios_cfg->vaps.vap_map.num_vaps = vap_array_index;
    return RETURN_OK;
}

int init_wifimgr()
{
    if (!drop_root()) {
        wifi_util_dbg_print(WIFI_MGR,"%s: drop_root function failed!\n", __func__);
        gain_root_privilege();
    }
    struct stat sb;
    char db_file[128];

    //Initialize HAL and get Capabilities
    init_wifi_hal();

    pthread_cond_init(&g_wifi_mgr.dml_init_status, NULL);
    pthread_mutex_init(&g_wifi_mgr.lock, NULL);

    sprintf(db_file, "%s/rdkb-wifi.db", WIFIDB_DIR);
    if (stat(db_file, &sb) != 0) {
        wifi_util_dbg_print(WIFI_MGR,"WiFiDB file not present FRcase\n");
        g_wifi_mgr.ctrl.factory_reset = true;
        wifi_util_dbg_print(WIFI_MGR,"WiFiDB  FRcase factory_reset is true\n");
    }
    else {
        g_wifi_mgr.ctrl.factory_reset = false;
        wifi_util_dbg_print(WIFI_MGR,"WiFiDB FRcase factory_reset is false\n");
    }

    if (init_wifi_ctrl(&g_wifi_mgr.ctrl) != 0) {
        wifi_util_dbg_print(WIFI_MGR,"%s: wifi ctrl init failed\n", __func__);
        return -1;
    } else {
        wifi_util_dbg_print(WIFI_MGR,"%s: wifi ctrl initalization success\n", __func__);
    }
     
    int itr=0;
    for (itr=0; itr < (int)getNumberRadios(); itr++) {
        init_global_radio_config(&g_wifi_mgr.radio_config[itr], itr);
    }

    //Init csi_data_queue
    if (g_wifi_mgr.csi_data_queue == NULL) {
        g_wifi_mgr.csi_data_queue = queue_create();
    }

    //Start Wifi DB server, and Initialize data Cache
    init_wifidb();

    //Set Wifi Global Parameters
    init_wifi_global_config();

    //Start Wifi Monitor Thread
    start_wifi_health_monitor_thread();

    return 0;
}

int start_wifimgr()
{
    start_dml_main(&g_wifi_mgr.ssp);
    wifi_util_dbg_print(WIFI_MGR,"%s: waiting for dml init\n", __func__);
    pthread_cond_wait(&g_wifi_mgr.dml_init_status,&g_wifi_mgr.lock);
    wifi_util_dbg_print(WIFI_MGR,"%s: dml init complete\n", __func__);

    pthread_cond_destroy(&g_wifi_mgr.dml_init_status);
    pthread_mutex_unlock(&g_wifi_mgr.lock);


    if (start_wifi_ctrl(&g_wifi_mgr.ctrl) != 0) {
        wifi_util_dbg_print(WIFI_MGR,"%s: wifi ctrl start failed\n", __func__);
        return -1;
    }

    return 0;
}

int main(int argc, char *argv[])
{
    bool run_daemon = true;
    int  idx = 0;

    for (idx = 1; idx < argc; idx++) {
        if (strcmp(argv[idx], "-c" ) == 0) {
            run_daemon = false;
        }
    }

    if (run_daemon) {
        daemonize();
    }

    if (init_wifimgr() != 0) {
        wifi_util_dbg_print(WIFI_MGR,"%s: wifimgr init failed\n", __func__);
        return -1;
    }

    if (start_wifimgr() != 0) {
        wifi_util_dbg_print(WIFI_MGR,"%s: wifimgr start failed\n", __func__);
        return -1;
    }

    wifi_util_dbg_print(WIFI_MGR,"%s: Exiting Wifi mgr\n", __func__);
    return 0;
}
