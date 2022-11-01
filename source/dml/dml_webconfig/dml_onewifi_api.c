#include <stdio.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>
#include <pthread.h>
#include <msgpack.h>
#include <errno.h>
#include <cJSON.h>
#include "dml_onewifi_api.h"
#include "wifi_util.h"

webconfig_dml_t webconfig_dml;

dml_vap_default vap_default[MAX_VAP];
dml_radio_default radio_cfg[MAX_NUM_RADIOS];
dml_global_default global_cfg;
dml_stats_default stats[MAX_NUM_RADIOS];

void update_dml_vap_defaults();
void update_dml_radio_default();
void update_dml_global_default();
void update_dml_stats_default();

webconfig_dml_t* get_webconfig_dml()
{
    return &webconfig_dml;
}

queue_t** get_csi_entry_queue()
{
    webconfig_dml_t* dml = get_webconfig_dml();
    if (dml == NULL) {
        wifi_util_error_print(WIFI_DMCLI,"%s %d NULL Pointer\n", __func__, __LINE__);
        return NULL;
    }

    return &(dml->csi_data_queue);
}

active_msmt_t* get_dml_blaster(void)
{
    wifi_global_param_t *pcfg = get_wifidb_wifi_global_param();
    if (pcfg == NULL) {
        wifi_util_error_print(WIFI_DMCLI,"%s:%d Unable to get Global Config\n", __FUNCTION__,__LINE__);
        return FALSE;
    }
   webconfig_dml.blaster.ActiveMsmtEnable = pcfg->wifi_active_msmt_enabled;
   if(webconfig_dml.blaster.ActiveMsmtPktSize == 0 ) {
        webconfig_dml.blaster.ActiveMsmtPktSize = pcfg->wifi_active_msmt_pktsize;
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Fetching Global\n", __FUNCTION__,__LINE__);
   }
   if(webconfig_dml.blaster.ActiveMsmtSampleDuration == 0 ) {
        webconfig_dml.blaster.ActiveMsmtSampleDuration = pcfg->wifi_active_msmt_sample_duration;
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Fetching Global\n", __FUNCTION__,__LINE__);
   }
   if(webconfig_dml.blaster.ActiveMsmtNumberOfSamples == 0 ) {
        webconfig_dml.blaster.ActiveMsmtNumberOfSamples = pcfg->wifi_active_msmt_num_samples;
        wifi_util_dbg_print(WIFI_DMCLI,"%s:%d Fetching Global\n", __FUNCTION__,__LINE__);
   }
    return &webconfig_dml.blaster;
}

active_msmt_t *get_dml_cache_blaster(void)
{
    return &webconfig_dml.blaster;
}

queue_t** get_dml_assoc_dev_queue(unsigned int radio_index, unsigned int vap_array_index)
{
    webconfig_dml_t* dml = get_webconfig_dml();
    if (dml == NULL) {
        return NULL;
    }

    return &(dml->assoc_dev_queue[radio_index][vap_array_index]);
}

hash_map_t** get_dml_acl_hash_map(unsigned int radio_index, unsigned int vap_index)
{
    webconfig_dml_t* dml = get_webconfig_dml();
    if (dml == NULL) {
        wifi_util_error_print(WIFI_DMCLI,"%s %d NULL Pointer\n", __func__, __LINE__);
        return NULL;
    }

    return &(dml->radios[radio_index].vaps.rdk_vap_array[vap_index].acl_map);
}

queue_t** get_dml_acl_new_entry_queue(unsigned int radio_index, unsigned int vap_index)
{
    webconfig_dml_t* dml = get_webconfig_dml();
    if (dml == NULL) {
        wifi_util_error_print(WIFI_DMCLI,"%s %d NULL Pointer\n", __func__, __LINE__);
        return NULL;
    }

    return &(dml->acl_data.new_entry_queue[radio_index][vap_index]);
}

void** get_acl_vap_context()
{
     webconfig_dml_t* dml = get_webconfig_dml();
     if (dml == NULL) {
         return NULL;
     }
     return &(dml->acl_data.acl_vap_context);
}

UINT get_num_radio_dml()
{
    webconfig_dml_t* pwebconfig = get_webconfig_dml();
    if (pwebconfig == NULL){
        wifi_util_error_print(WIFI_DMCLI,"%s Error: value is NULL\n",__FUNCTION__);
        return 0;
    }

    if (pwebconfig->hal_cap.wifi_prop.numRadios < MIN_NUM_RADIOS || pwebconfig->hal_cap.wifi_prop.numRadios > MAX_NUM_RADIOS) {
        wifi_util_error_print(WIFI_DMCLI,"%s Error: hal_cap.wifi_prop.numRadios is out of range \n",__FUNCTION__);
        return 0;
    } else {
        return pwebconfig->hal_cap.wifi_prop.numRadios;
    }
}

UINT get_total_num_vap_dml()
{
    webconfig_dml_t* pwebconfig = get_webconfig_dml();
    UINT numberOfVap = 0;
    UINT i = 0;
    if (pwebconfig == NULL){
        wifi_util_error_print(WIFI_DMCLI,"%s Error: value is NULL\n",__FUNCTION__);
        return 0;
    }

    for (i = 0; i < get_num_radio_dml(); ++i) {
        numberOfVap += pwebconfig->radios[i].vaps.vap_map.num_vaps;
    }

    return numberOfVap;
}

UINT get_max_num_vap_dml()
{
    webconfig_dml_t* pwebconfig = get_webconfig_dml();
    UINT maxNumberOfVaps;

    if (pwebconfig == NULL){
        wifi_util_error_print(WIFI_DMCLI,"%s Error: value is NULL\n",__FUNCTION__);
        maxNumberOfVaps = MAX_NUM_RADIOS * MAX_NUM_VAP_PER_RADIO;
    } else {
        maxNumberOfVaps = 0;
        for (UINT i = 0; i < pwebconfig->hal_cap.wifi_prop.numRadios; i++) {
            maxNumberOfVaps += pwebconfig->hal_cap.wifi_prop.radiocap[i].maxNumberVAPs;
        }
    }
    return maxNumberOfVaps;
}

void update_csi_data_queue(rbusHandle_t handle, rbusEvent_t const* event, rbusEventSubscription_t* subscription)
{
    int len = 0;
    const char * pTmp = NULL;
    webconfig_subdoc_data_t data;
    rbusValue_t value;

    const char* eventName = event->name;

    wifi_util_dbg_print(WIFI_DMCLI,"rbus event callback Event is %s \n",eventName);
    value = rbusObject_GetValue(event->data, NULL );
    if(!value)
    {
        wifi_util_error_print(WIFI_DMCLI,"%s FAIL: value is NULL\n",__FUNCTION__);
        return;
    }
    pTmp = rbusValue_GetString(value, &len);
    if (pTmp == NULL) {
        wifi_util_error_print(WIFI_DMCLI,"%s Null pointer,Rbus set string len=%d\n",__FUNCTION__,len);
        return;
    }

    // setup the raw data
    memset(&data, 0, sizeof(webconfig_subdoc_data_t));
    data.signature = WEBCONFIG_MAGIC_SIGNATUTRE;
    data.type = webconfig_subdoc_type_dml;
    data.descriptor = 0;
    data.descriptor = webconfig_data_descriptor_encoded;
    strncpy(data.u.encoded.raw, pTmp, sizeof(data.u.encoded.raw) - 1);

    // tell webconfig to decode
    if (webconfig_set(&webconfig_dml.webconfig, &data)== webconfig_error_none){
        wifi_util_info_print(WIFI_DMCLI,"%s %d webconfig_set success \n",__FUNCTION__,__LINE__ );
    } else {
        wifi_util_error_print(WIFI_DMCLI,"%s %d webconfig_set fail \n",__FUNCTION__,__LINE__ );
        return;
    }
    
    queue_t** csi_queue = (queue_t **)get_csi_entry_queue();
    if ((csi_queue != NULL) && (*csi_queue != NULL)) {
        queue_destroy(*csi_queue);
    }
    *csi_queue = data.u.decoded.csi_data_queue;
}

void mac_filter_dml_vap_cache_update(int radio_index, int vap_array_index)
{
    //webconfig decode allocate mem for the hash map which is getting cleared and destroyed here
    hash_map_t** acl_dev_map = get_dml_acl_hash_map(radio_index, vap_array_index);
    if(*acl_dev_map) {
        acl_entry_t *temp_acl_entry, *acl_entry;
        mac_addr_str_t mac_str;
        acl_entry = hash_map_get_first(*acl_dev_map);
        while (acl_entry != NULL) {
            to_mac_str(acl_entry->mac,mac_str);
            acl_entry = hash_map_get_next(*acl_dev_map,acl_entry);
            temp_acl_entry = hash_map_remove(*acl_dev_map, mac_str);
            if (temp_acl_entry != NULL) {
                free(temp_acl_entry);
            }
        }
        hash_map_destroy(*acl_dev_map);
    }
}

void update_dml_subdoc_vap_data(webconfig_subdoc_data_t *data)
{
    webconfig_subdoc_decoded_data_t *params;
    unsigned int i, j;
    wifi_vap_info_map_t *map;
    wifi_vap_info_t *vap;
    wifi_vap_info_map_t *dml_map;
    wifi_vap_info_t *dml_vap;

    params = &data->u.decoded;
    wifi_util_info_print(WIFI_DMCLI,"%s:%d subdoc parse and update dml global cache:%d\n",__func__, __LINE__, data->type);
    for (i = 0; i < params->num_radios; i++) {
        map = &params->radios[i].vaps.vap_map;
        dml_map = &webconfig_dml.radios[i].vaps.vap_map;
        for (j = 0; j < map->num_vaps; j++) {
            vap = &map->vap_array[j];
            dml_vap = &dml_map->vap_array[j];

            switch (data->type) {
                case webconfig_subdoc_type_private:
                    if (is_vap_private(&params->hal_cap.wifi_prop, vap->vap_index) && (strlen(vap->vap_name))) {
                        memcpy(dml_vap, vap, sizeof(wifi_vap_info_t));
                    }
                    break;
                case webconfig_subdoc_type_home:
                    if (is_vap_xhs(&params->hal_cap.wifi_prop, vap->vap_index)) {
                        memcpy(dml_vap, vap, sizeof(wifi_vap_info_t));
                    }
                    break;
                case webconfig_subdoc_type_xfinity:
                    if (is_vap_hotspot(&params->hal_cap.wifi_prop, vap->vap_index)) {
                        memcpy(dml_vap, vap, sizeof(wifi_vap_info_t));
                    }
                    break;
                case webconfig_subdoc_type_mesh:
                    if (is_vap_mesh(&params->hal_cap.wifi_prop, vap->vap_index)) {
                        mac_filter_dml_vap_cache_update(i, j);
                        memcpy(dml_vap, vap, sizeof(wifi_vap_info_t));
                        webconfig_dml.radios[i].vaps.rdk_vap_array[j].acl_map = params->radios[i].vaps.rdk_vap_array[j].acl_map;
                        webconfig_dml.radios[i].vaps.rdk_vap_array[j].vap_index = params->radios[i].vaps.rdk_vap_array[j].vap_index;
                    }
                    break;
                case webconfig_subdoc_type_mesh_backhaul:
                    if (is_vap_mesh_backhaul(&params->hal_cap.wifi_prop, vap->vap_index)) {
                        mac_filter_dml_vap_cache_update(i, j);
                        memcpy(dml_vap, vap, sizeof(wifi_vap_info_t));
                        webconfig_dml.radios[i].vaps.rdk_vap_array[j].acl_map = params->radios[i].vaps.rdk_vap_array[j].acl_map;
                        webconfig_dml.radios[i].vaps.rdk_vap_array[j].vap_index = params->radios[i].vaps.rdk_vap_array[j].vap_index;
                    }
                    break;
                case webconfig_subdoc_type_mesh_sta:
                    if (is_vap_mesh_sta(&params->hal_cap.wifi_prop, vap->vap_index)) {
                        memcpy(dml_vap, vap, sizeof(wifi_vap_info_t));
                    }
                    break;
                default:
                    wifi_util_error_print(WIFI_DMCLI,"%s %d Invalid subdoc parse:%d\n",__func__, __LINE__, data->type);
                    break;
            }
        }
    }
}

void mac_filter_dml_cache_update(webconfig_subdoc_data_t *data)
{
    int itr, itrj;

    //webconfig decode allocate mem for the hash map which is getting cleared and destroyed here
    for (itr=0; itr<(int)data->u.decoded.num_radios; itr++) {
        for(itrj = 0; itrj < MAX_NUM_VAP_PER_RADIO; itrj++) {
            hash_map_t** acl_dev_map = get_dml_acl_hash_map(itr,itrj);
            if(*acl_dev_map) {
                acl_entry_t *temp_acl_entry, *acl_entry;
                mac_addr_str_t mac_str;
                acl_entry = hash_map_get_first(*acl_dev_map);
                while (acl_entry != NULL) {
                    to_mac_str(acl_entry->mac,mac_str);
                    acl_entry = hash_map_get_next(*acl_dev_map,acl_entry);
                    temp_acl_entry = hash_map_remove(*acl_dev_map, mac_str);
                    if (temp_acl_entry != NULL) {
                        free(temp_acl_entry);
                    }
                }
                hash_map_destroy(*acl_dev_map);
            }
        }
    }
}

void dml_cache_update(webconfig_subdoc_data_t *data)
{
    webconfig_subdoc_decoded_data_t *params;
    unsigned int i;

    switch(data->type) {
        case webconfig_subdoc_type_radio:
            params = &data->u.decoded;
            for (i = 0; i < params->num_radios; i++) {
                wifi_util_info_print(WIFI_DMCLI,"%s %d dml radio[%d] cache update\r\n", __func__, __LINE__, i);
                memcpy(&webconfig_dml.radios[i].oper, &params->radios[i].oper, sizeof(params->radios[i].oper));
            }
            break;
        case webconfig_subdoc_type_dml:
            wifi_util_info_print(WIFI_DMCLI,"%s:%d subdoc parse and update dml global cache:%d\n",__func__, __LINE__, data->type);
            mac_filter_dml_cache_update(data);
            memcpy((unsigned char *)&webconfig_dml.radios, (unsigned char *)&data->u.decoded.radios, data->u.decoded.num_radios*sizeof(rdk_wifi_radio_t));
            memcpy((unsigned char *)&webconfig_dml.config, (unsigned char *)&data->u.decoded.config, sizeof(wifi_global_config_t));
            memcpy((unsigned char *)&webconfig_dml.hal_cap,(unsigned char *)&data->u.decoded.hal_cap, sizeof(wifi_hal_capability_t));
            webconfig_dml.hal_cap.wifi_prop.numRadios = data->u.decoded.num_radios;
            break;
        default:
            update_dml_subdoc_vap_data(data);
            break;
    }
}

void set_webconfig_dml_data(rbusHandle_t handle, rbusEvent_t const* event, rbusEventSubscription_t* subscription)
{
    int len = 0;
    const char * pTmp = NULL;
    webconfig_subdoc_data_t data;
    rbusValue_t value;

    const char* eventName = event->name;

    wifi_util_dbg_print(WIFI_DMCLI,"rbus event callback Event is %s \n",eventName);
    value = rbusObject_GetValue(event->data, NULL );
    if(!value)
    {
        wifi_util_error_print(WIFI_DMCLI,"%s FAIL: value is NULL\n",__FUNCTION__);
        return;
    }
    pTmp = rbusValue_GetString(value, &len);
    if (pTmp == NULL) {
        wifi_util_error_print(WIFI_DMCLI,"%s Null pointer,Rbus set string len=%d\n",__FUNCTION__,len);
        return;
    }

    // setup the raw data
    memset(&data, 0, sizeof(webconfig_subdoc_data_t));
    data.signature = WEBCONFIG_MAGIC_SIGNATUTRE;
    data.type = webconfig_subdoc_type_unknown;
    data.descriptor = 0;
    data.descriptor = webconfig_data_descriptor_encoded | webconfig_data_descriptor_translate_to_tr181;
    strcpy(data.u.encoded.raw, pTmp);

    //wifi_util_dbg_print(WIFI_DMCLI,"%s:%d: dml Json:\n%s\r\n", __func__, __LINE__, data.u.encoded.raw);
    wifi_util_info_print(WIFI_DMCLI,"%s:%d: hal capability update\r\n", __func__, __LINE__);
    memcpy((unsigned char *)&data.u.decoded.hal_cap, (unsigned char *)&webconfig_dml.hal_cap, sizeof(wifi_hal_capability_t));

    data.u.decoded.num_radios = webconfig_dml.hal_cap.wifi_prop.numRadios;

    // tell webconfig to decode
    if (webconfig_set(&webconfig_dml.webconfig, &data)== webconfig_error_none){
        wifi_util_info_print(WIFI_DMCLI,"%s %d webconfig_set success \n",__FUNCTION__,__LINE__ );
    } else {
        wifi_util_error_print(WIFI_DMCLI,"%s %d webconfig_set fail \n",__FUNCTION__,__LINE__ );
        return;
    }
    dml_cache_update(&data);

    return ;
}


void rbus_dmlwebconfig_register(webconfig_dml_t *consumer)
{
    int rc = RBUS_ERROR_SUCCESS;
    char *component_name = "WebconfigDML";

    rbusEventSubscription_t rbusEvents[] = {
        { WIFI_WEBCONFIG_DOC_DATA_NORTH, NULL, 0, 0, set_webconfig_dml_data, NULL, NULL, NULL}, // DML Subdoc
        { WIFI_WEBCONFIG_GET_CSI, NULL, 0, 0, update_csi_data_queue, NULL, NULL, NULL}, // CSI subdoc
    };

    wifi_util_dbg_print(WIFI_DMCLI,"%s rbus open \n",__FUNCTION__);
    rc = rbus_open(&consumer->rbus_handle, component_name);

    if (rc != RBUS_ERROR_SUCCESS) {
        wifi_util_error_print(WIFI_DMCLI,"%s Rbus open failed\n",__FUNCTION__);
        return;
    }

    wifi_util_info_print(WIFI_DMCLI,"%s  rbus open success\n",__FUNCTION__);
    rc = rbusEvent_SubscribeEx(consumer->rbus_handle, rbusEvents, ARRAY_SZ(rbusEvents), 0);
    if(rc != RBUS_ERROR_SUCCESS) {
            wifi_util_error_print(WIFI_DMCLI,"Unable to subscribe to event  with rbus error code : %d\n", rc);
    }
    return;
}

webconfig_error_t webconfig_dml_apply(webconfig_dml_t *consumer, webconfig_subdoc_data_t *data)
{
    wifi_util_dbg_print(WIFI_DMCLI,"%s:%d webconfig dml apply\n", __func__, __LINE__);
    return webconfig_error_none;
}

void get_associated_devices_data(unsigned int radio_index)
{
    int itr=0, itrj=0;
    webconfig_subdoc_data_t data;
    char str[MAX_SUBDOC_SIZE];

#if 0
    //This part of code will be enabled once the rbus_get issue is resolved
    rc = rbus_get(webconfig_dml.rbus_handle, paramNames[0], &value);
    if (rc != RBUS_ERROR_SUCCESS) {
        wifi_util_dbg_print(WIFI_DMCLI,"rbus_get failed for [%s] with error [%d]\n", paramNames[0], rc);
        return;
    }
    str = rbusValue_GetString(value, (int*) &len);
    if (str == NULL) {
        wifi_util_dbg_print(WIFI_DMCLI,"%s Null pointer,Rbus set string len=%d\n",__FUNCTION__,len);
        return;
    }
#else
    get_assoc_devices_blob(str);
#endif
    memset(&data, 0, sizeof(webconfig_subdoc_data_t));
    memcpy((unsigned char *)&data.u.decoded.radios, (unsigned char *)&webconfig_dml.radios, get_num_radio_dml()*sizeof(rdk_wifi_radio_t));
    memcpy((unsigned char *)&data.u.decoded.config, (unsigned char *)&webconfig_dml.config,  sizeof(wifi_global_config_t));
    memcpy((unsigned char *)&data.u.decoded.hal_cap,(unsigned char *)&webconfig_dml.hal_cap, sizeof(wifi_hal_capability_t));
    data.u.decoded.num_radios = webconfig_dml.hal_cap.wifi_prop.numRadios;

    if (webconfig_decode(&webconfig_dml.webconfig, &data, str) != webconfig_error_none) {
        wifi_util_error_print(WIFI_DMCLI,"%s %d webconfig_decode returned error\n", __func__, __LINE__);
        return;
    }
    for (itr=0; itr < (int)get_num_radio_dml(); itr++) {
        for (itrj=0; itrj<MAX_NUM_VAP_PER_RADIO; itrj++) {
            queue_t** assoc_dev_queue = get_dml_assoc_dev_queue(itr, itrj);
            if ((assoc_dev_queue != NULL) && (*assoc_dev_queue != NULL)) {
                queue_destroy(*assoc_dev_queue);
            }
            *assoc_dev_queue = data.u.decoded.radios[itr].vaps.rdk_vap_array[itrj].associated_devices_queue;
        }
    }
}

unsigned long get_associated_devices_count(wifi_vap_info_t *vap_info)
{
    unsigned long count = 0;

    int radio_index = convert_vap_name_to_radio_array_index(&((webconfig_dml_t*) get_webconfig_dml())->hal_cap.wifi_prop, vap_info->vap_name);
    int vap_array_index = convert_vap_name_to_array_index(&((webconfig_dml_t*) get_webconfig_dml())->hal_cap.wifi_prop, vap_info->vap_name);
    queue_t **assoc_dev_queue = get_dml_assoc_dev_queue(radio_index, vap_array_index);

    if ((assoc_dev_queue == NULL) && (*assoc_dev_queue == NULL)) {
        wifi_util_dbg_print(WIFI_DMCLI,"%s %d No queue returning zero\n", __func__, __LINE__);
        return count;
    }

    count  = (unsigned long)queue_count(*assoc_dev_queue);
    wifi_util_dbg_print(WIFI_DMCLI,"%s %d returning queue count as %d\n", __func__, __LINE__, count);
    return count;
}

queue_t* get_associated_devices_queue(wifi_vap_info_t *vap_info)
{
    if (vap_info == NULL) {
        wifi_util_error_print(WIFI_DMCLI,"%s %d NULL Pointer\n", __func__, __LINE__);
        return NULL;
    }

    int radio_index = convert_vap_name_to_radio_array_index(&((webconfig_dml_t*) get_webconfig_dml())->hal_cap.wifi_prop, vap_info->vap_name);
    int vap_array_index = convert_vap_name_to_array_index(&((webconfig_dml_t*) get_webconfig_dml())->hal_cap.wifi_prop, vap_info->vap_name);

    if ((vap_array_index < 0) || (radio_index < 0)) {
        wifi_util_error_print(WIFI_DMCLI,"%s %d Invalid array/radio Indices\n", __func__, __LINE__);
        return NULL;
    }

    queue_t **assoc_dev_queue = get_dml_assoc_dev_queue(radio_index, vap_array_index);
    if (assoc_dev_queue == NULL) {
        wifi_util_error_print(WIFI_DMCLI,"%s %d NULL pointer \n", __func__, __LINE__);
        return NULL;
    }

    return *assoc_dev_queue;
}

queue_t** get_acl_new_entry_queue(wifi_vap_info_t *vap_info)
{
    if (vap_info == NULL) {
        wifi_util_error_print(WIFI_DMCLI,"%s %d NULL Pointer\n", __func__, __LINE__);
        return NULL;
    }

    int radio_index = convert_vap_name_to_radio_array_index(&((webconfig_dml_t*) get_webconfig_dml())->hal_cap.wifi_prop, vap_info->vap_name);
    int vap_array_index = convert_vap_name_to_array_index(&((webconfig_dml_t*) get_webconfig_dml())->hal_cap.wifi_prop, vap_info->vap_name);

    if ((vap_array_index < 0) || (radio_index < 0)) {
        wifi_util_error_print(WIFI_DMCLI,"%s %d Invalid array/radio Indices\n", __func__, __LINE__);
        return NULL;
    }

    webconfig_dml_t* dml = get_webconfig_dml();
    if (dml == NULL) {
        wifi_util_error_print(WIFI_DMCLI,"%s %d NULL Pointer\n", __func__, __LINE__);
        return NULL;
    }

    return &(dml->acl_data.new_entry_queue[radio_index][vap_array_index]);
}


hash_map_t** get_acl_hash_map(wifi_vap_info_t *vap_info)
{
    if (vap_info == NULL) {
        wifi_util_error_print(WIFI_DMCLI,"%s %d NULL Pointer\n", __func__, __LINE__);
        return NULL;
    }

    int radio_index = convert_vap_name_to_radio_array_index(&((webconfig_dml_t*) get_webconfig_dml())->hal_cap.wifi_prop, vap_info->vap_name);
    int vap_array_index = convert_vap_name_to_array_index(&((webconfig_dml_t*) get_webconfig_dml())->hal_cap.wifi_prop, vap_info->vap_name);

    if ((vap_array_index < 0) || (radio_index < 0)) {
        wifi_util_error_print(WIFI_DMCLI,"%s %d Invalid array/radio Indices\n", __func__, __LINE__);
        return NULL;
    }

    hash_map_t **acl_dev_map = get_dml_acl_hash_map(radio_index, vap_array_index);
    if (acl_dev_map == NULL) {
        wifi_util_error_print(WIFI_DMCLI,"%s %d NULL pointer \n", __func__, __LINE__);
        return NULL;
    }

    return acl_dev_map;
}

int init(webconfig_dml_t *consumer)
{
    //const char *paramNames[] = {WIFI_WEBCONFIG_INIT_DATA}, *str;
    const char *paramNames[] = {WIFI_WEBCONFIG_INIT_DML_DATA}, *str;
    rbusValue_t value;
    int rc = RBUS_ERROR_SUCCESS;
    unsigned int len, itr=0, itrj=0;
    webconfig_subdoc_data_t data;

    rbus_dmlwebconfig_register(consumer);
    rc = rbus_get(consumer->rbus_handle, paramNames[0], &value);
    if (rc != RBUS_ERROR_SUCCESS) {
        wifi_util_error_print(WIFI_DMCLI,"rbus_get failed for [%s] with error [%d]\n", paramNames[0], rc);
        return -1;
    }

    //Initialize Webconfig Framework
    consumer->webconfig.initializer = webconfig_initializer_dml;
    consumer->webconfig.apply_data = (webconfig_apply_data_t)webconfig_dml_apply;

    if (webconfig_init(&consumer->webconfig) != webconfig_error_none) {
        wifi_util_error_print(WIFI_DMCLI,"[%s]:%d Init WiFi Web Config  fail\n",__FUNCTION__,__LINE__);
        // unregister and deinit everything
        return RETURN_ERR;
    }

    memset(consumer->assoc_dev_queue, 0, sizeof(consumer->assoc_dev_queue));

    for (itr = 0; itr<MAX_NUM_RADIOS; itr++) {
        for (itrj = 0; itrj<MAX_NUM_VAP_PER_RADIO; itrj++) {
            queue_t **new_dev_queue = (queue_t **)get_dml_acl_new_entry_queue(itr, itrj);
            *new_dev_queue = queue_create();
        }
    }

    for (itr = 0; itr<MAX_NUM_RADIOS; itr++) {
        for (itrj = 0; itrj<MAX_NUM_VAP_PER_RADIO; itrj++) {
            consumer->radios[itr].vaps.rdk_vap_array[itrj].acl_map = NULL;
        }
    }

    queue_t **csi_queue = (queue_t**)get_csi_entry_queue();
    if (*csi_queue == NULL) {
        *csi_queue = queue_create();
    }

    wifi_util_info_print(WIFI_DMCLI,"%s %d rbus_get WIFI_WEBCONFIG_INIT_DML_DATA successfull \n",__FUNCTION__,__LINE__ );
    str = rbusValue_GetString(value, (int*) &len);
    if (str == NULL) {
        wifi_util_error_print(WIFI_DMCLI,"%s Null pointer,Rbus set string len=%d\n",__FUNCTION__,len);
        return RETURN_ERR;
    }

    wifi_util_dbg_print(WIFI_DMCLI,"%s %d rbus_get value=%s \n",__FUNCTION__,__LINE__,str );
    // setup the raw data
    memset(&data, 0, sizeof(webconfig_subdoc_data_t));
    data.signature = WEBCONFIG_MAGIC_SIGNATUTRE;
    data.type = webconfig_subdoc_type_dml;
    data.descriptor = 0;
    data.descriptor |= webconfig_data_descriptor_encoded;
    strcpy(data.u.encoded.raw, str);

    // tell webconfig to decode
    if (webconfig_set(&consumer->webconfig, &data)== webconfig_error_none){
        wifi_util_info_print(WIFI_DMCLI,"%s %d webconfig_set success \n",__FUNCTION__,__LINE__ );
    } else {
        wifi_util_error_print(WIFI_DMCLI,"%s %d webconfig_set fail \n",__FUNCTION__,__LINE__ );
    return 0;
    }

    memcpy((unsigned char *)&consumer->radios, (unsigned char *)&data.u.decoded.radios, data.u.decoded.num_radios*sizeof(rdk_wifi_radio_t));
    memcpy((unsigned char *)&consumer->config, (unsigned char *)&data.u.decoded.config, sizeof(wifi_global_config_t));
    memcpy((unsigned char *)&consumer->hal_cap, (unsigned char *)&data.u.decoded.hal_cap, sizeof(wifi_hal_capability_t));
    consumer->hal_cap.wifi_prop.numRadios = data.u.decoded.num_radios;
    consumer->harvester.b_inst_client_enabled=consumer->config.global_parameters.inst_wifi_client_enabled;
    consumer->harvester.u_inst_client_reporting_period=consumer->config.global_parameters.inst_wifi_client_reporting_period;
    consumer->harvester.u_inst_client_def_reporting_period=consumer->config.global_parameters.inst_wifi_client_def_reporting_period;
    strncpy(consumer->harvester.mac_address,(char *)consumer->config.global_parameters.inst_wifi_client_mac,sizeof(consumer->harvester.mac_address));
    update_dml_radio_default();
    update_dml_vap_defaults();
    update_dml_global_default();
    update_dml_stats_default();
    return 0;
}

wifi_global_config_t *get_dml_cache_global_wifi_config()
{
    return &webconfig_dml.config;

}

wifi_vap_info_map_t* get_dml_cache_vap_map(uint8_t radio_index)
{
    if(radio_index < get_num_radio_dml())
    {
        return &webconfig_dml.radios[radio_index].vaps.vap_map;
    }
    wifi_util_error_print(WIFI_DMCLI, "%s: wrong radio_index %d\n", __FUNCTION__, radio_index);
    return NULL;
}

wifi_radio_operationParam_t* get_dml_cache_radio_map(uint8_t radio_index)
{
    if(radio_index < get_num_radio_dml())
    {
        return &webconfig_dml.radios[radio_index].oper;
    }
    else
    {
        wifi_util_error_print(WIFI_DMCLI, "%s: wrong radio_index %d\n", __FUNCTION__, radio_index);
        return NULL;
    }
}

bool is_radio_config_changed;
bool g_update_wifi_region;

int convert_freq_band_to_dml_radio_index(int band, int *radio_index)
{
    if(band>0)
    {
        *radio_index = band;
        return RETURN_OK;
    }
    return RETURN_ERR;
}

bool is_dfs_channel_allowed(unsigned int channel)
{
    wifi_rfc_dml_parameters_t *rfc_pcfg = (wifi_rfc_dml_parameters_t *)get_wifi_db_rfc_parameters();
    if (channel >= 50 && channel <= 144) {
        if (rfc_pcfg->dfs_rfc == true) {
            return true;
        } else {
            wifi_util_error_print(WIFI_DMCLI,"%s:%d: invalid channel=%d  dfc_rfc= %d\r\n",__func__, __LINE__, channel, rfc_pcfg->dfs_rfc);
        }
    } else {
        return true;
    }

    return false;
}

wifi_vap_info_t *get_dml_cache_vap_info(uint8_t vap_index)
{
    unsigned int radio_index = 0;
    unsigned int vap_array_index = 0;
    unsigned int num_radios = get_num_radio_dml();

    if (vap_index > (num_radios * MAX_NUM_VAP_PER_RADIO)) {
        wifi_util_error_print(WIFI_DMCLI,"%s:%d:Invalid vap_index %d \n",__func__, __LINE__, vap_index);
        return NULL;
    }

    get_radioIndex_from_vapIndex(vap_index,&radio_index);

    for (vap_array_index = 0; vap_array_index < MAX_NUM_VAP_PER_RADIO; vap_array_index++) {
        if (vap_index == webconfig_dml.radios[radio_index].vaps.vap_map.vap_array[vap_array_index].vap_index) {
            wifi_util_dbg_print(WIFI_DMCLI,"%s:%d: vap_index : %d  is stored at  radio_index : %d vap_arr_index : %d\n",__func__, __LINE__, vap_index,  radio_index, vap_array_index);
            return &webconfig_dml.radios[radio_index].vaps.vap_map.vap_array[vap_array_index];
        } else {
            continue;
        }
    }
    wifi_util_error_print(WIFI_DMCLI,"%s:%d: vap_index not found %d\n",__func__, __LINE__, vap_index);
    return NULL;
}

wifi_vap_security_t * get_dml_cache_sta_security_parameter(uint8_t vapIndex)
{
    uint8_t radio_index = 0, vap_index = 0;
    get_vap_and_radio_index_from_vap_instance(&((webconfig_dml_t*) get_webconfig_dml())->hal_cap.wifi_prop, vapIndex, &radio_index, &vap_index);
    if (vap_index >= MAX_NUM_VAP_PER_RADIO) {
        wifi_util_error_print(WIFI_DMCLI, "%s: wrong radio_index %d vapIndex:%d \n", __FUNCTION__, radio_index, vapIndex);
        return NULL;
    }
    return &webconfig_dml.radios[radio_index].vaps.vap_map.vap_array[vap_index].u.sta_info.security;
}

wifi_vap_security_t * get_dml_cache_bss_security_parameter(uint8_t vapIndex)
{
    uint8_t radio_index = 0, vap_index = 0;
    get_vap_and_radio_index_from_vap_instance(&((webconfig_dml_t*) get_webconfig_dml())->hal_cap.wifi_prop, vapIndex, &radio_index, &vap_index);
    if(vap_index >= MAX_NUM_VAP_PER_RADIO) {
        wifi_util_error_print(WIFI_DMCLI, "%s: wrong radio_index %d vapIndex:%d \n", __FUNCTION__, radio_index, vapIndex);
        return NULL;
    }
    return &webconfig_dml.radios[radio_index].vaps.vap_map.vap_array[vap_index].u.bss_info.security;
}

int get_radioIndex_from_vapIndex(unsigned int vap_index, unsigned int *radio_index)
{
    unsigned int radioIndex = 0;
    unsigned int vapIndex = 0;

    if (radio_index == NULL) {
        wifi_util_error_print(WIFI_DMCLI,"%s:%d: Input arguements are NULL %d \n",__func__, __LINE__, vap_index);
        return RETURN_ERR;
    }

    webconfig_dml_t* webConfigDml = get_webconfig_dml();
    if (webConfigDml == NULL){
        wifi_util_error_print(WIFI_DMCLI,"%s:%d: get_webconfig_dml is NULL  \n",__func__, __LINE__);
        return RETURN_ERR;
    }

    for (radioIndex = 0; radioIndex < get_num_radio_dml(); radioIndex++){
        for (vapIndex = 0; vapIndex < MAX_NUM_VAP_PER_RADIO; vapIndex++){
            if (webConfigDml->radios[radioIndex].vaps.rdk_vap_array[vapIndex].vap_index == vap_index){
                *radio_index = radioIndex;
                return RETURN_OK;
            }
        }
    }

    wifi_util_error_print(WIFI_DMCLI,"%s:%d: vap index not found it  %d \n",__func__, __LINE__, vap_index);
    return RETURN_ERR;
}

int push_global_config_dml_cache_to_one_wifidb()
{
    wifi_util_dbg_print(WIFI_DMCLI, "%s:  Need to implement \n", __FUNCTION__);
    webconfig_subdoc_data_t data;
    char *str = NULL;
    memset(&data, 0, sizeof(webconfig_subdoc_data_t));
    memcpy((unsigned char *)&data.u.decoded.config, (unsigned char *)&webconfig_dml.config, sizeof(wifi_global_config_t));
    memcpy((unsigned char *)&data.u.decoded.hal_cap, (unsigned char *)&webconfig_dml.hal_cap, sizeof(wifi_hal_capability_t));

    if (webconfig_encode(&webconfig_dml.webconfig, &data, webconfig_subdoc_type_wifi_config) == webconfig_error_none) {
        str = data.u.encoded.raw;
        wifi_util_dbg_print(WIFI_DMCLI, "%s:  GlobalConfig DML cache encoded successfully  \n", __FUNCTION__);
        push_data_to_ctrl_queue(str, strlen(str), ctrl_event_type_webconfig, ctrl_event_webconfig_set_data_dml);
    } else {
        wifi_util_dbg_print(WIFI_DMCLI, "%s:%d: Webconfig set failed\n", __func__, __LINE__);
    }

    wifi_util_dbg_print(WIFI_DMCLI, "%s:  Global DML cache pushed to queue \n", __FUNCTION__);
    g_update_wifi_region = FALSE;
    return RETURN_OK;
}

int push_wifi_host_sync_to_ctrl_queue()
{
    wifi_util_dbg_print(WIFI_DMCLI, "%s:%d Pushing wifi host sync to ctrl queue\n", __func__, __LINE__);
    push_data_to_ctrl_queue(NULL, 0, ctrl_event_type_command, ctrl_event_type_command_wifi_host_sync);

    return RETURN_OK;
}

int push_kick_assoc_to_ctrl_queue(int vap_index) 
{
    char tmp_str[120];
    memset(tmp_str, 0, sizeof(tmp_str));
    wifi_util_info_print(WIFI_DMCLI, "%s:%d Pushing kick assoc to ctrl queue for vap_index %d\n", __func__, __LINE__, vap_index);
    snprintf(tmp_str, sizeof(tmp_str), "%d-ff:ff:ff:ff:ff:ff-0", vap_index);
    push_data_to_ctrl_queue(tmp_str, (strlen(tmp_str) + 1), ctrl_event_type_command, ctrl_event_type_command_kick_assoc_devices);

    return RETURN_OK;
}

int push_radio_dml_cache_to_one_wifidb()
{
    webconfig_subdoc_data_t data;
    char *str = NULL;

    if(is_radio_config_changed == FALSE)
    {
        wifi_util_info_print(WIFI_DMCLI, "%s: No Radio DML Modified Return success  \n", __FUNCTION__);
    return RETURN_OK;
    }
    memset(&data, 0, sizeof(webconfig_subdoc_data_t));
    memcpy((unsigned char *)&data.u.decoded.radios, (unsigned char *)&webconfig_dml.radios, get_num_radio_dml()*sizeof(rdk_wifi_radio_t));
    memcpy((unsigned char *)&data.u.decoded.hal_cap, (unsigned char *)&webconfig_dml.hal_cap, sizeof(wifi_hal_capability_t));

    data.u.decoded.num_radios = get_num_radio_dml();

    if (webconfig_encode(&webconfig_dml.webconfig, &data, webconfig_subdoc_type_radio) == webconfig_error_none) {
        str = data.u.encoded.raw;
        wifi_util_info_print(WIFI_DMCLI, "%s:  Radio DML cache encoded successfully  \n", __FUNCTION__);
        push_data_to_ctrl_queue(str, strlen(str), ctrl_event_type_webconfig, ctrl_event_webconfig_set_data_dml);
    } else {
        wifi_util_error_print(WIFI_DMCLI, "%s:%d: Webconfig set failed\n", __func__, __LINE__);
    }

    wifi_util_error_print(WIFI_DMCLI, "%s:  Radio DML cache pushed to queue \n", __FUNCTION__);
    is_radio_config_changed = FALSE;
    return RETURN_OK;
}

int push_csi_data_dml_cache_to_one_wifidb() {
    webconfig_subdoc_data_t data;
    char *str = NULL;

    memset(&data, 0, sizeof(webconfig_subdoc_data_t));
    wifi_util_dbg_print(WIFI_DMCLI, "%s: queue count is %lu\n", __func__, queue_count(webconfig_dml.csi_data_queue));
    memcpy((unsigned char *)&data.u.decoded.csi_data_queue, (unsigned char *)&webconfig_dml.csi_data_queue, sizeof(queue_t *));
    memcpy((unsigned char *)&data.u.decoded.hal_cap, (unsigned char *)&webconfig_dml.hal_cap, sizeof(wifi_hal_capability_t));

    if (webconfig_encode(&webconfig_dml.webconfig, &data, webconfig_subdoc_type_csi) == webconfig_error_none) {
        str = data.u.encoded.raw;
        wifi_util_info_print(WIFI_DMCLI, "%s: CSI cache encoded successfully  \n", __FUNCTION__);
        push_data_to_ctrl_queue(str, strlen(str), ctrl_event_type_webconfig, ctrl_event_webconfig_set_data_dml);
    } else {
        wifi_util_error_print(WIFI_DMCLI, "%s:%d: Webconfig set failed\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    wifi_util_info_print(WIFI_DMCLI, "%s:  CSI cache pushed to queue encoded data is %s\n", __FUNCTION__, str);
    return RETURN_OK;
}

int push_acl_list_dml_cache_to_one_wifidb(wifi_vap_info_t *vap_info)
{
    webconfig_subdoc_data_t data;
    char *str = NULL;

    memset(&data, 0, sizeof(webconfig_subdoc_data_t));
    memcpy((unsigned char *)&data.u.decoded.radios, (unsigned char *)&webconfig_dml.radios, get_num_radio_dml()*sizeof(rdk_wifi_radio_t));
    memcpy((unsigned char *)&data.u.decoded.hal_cap, (unsigned char *)&webconfig_dml.hal_cap, sizeof(wifi_hal_capability_t));


    data.u.decoded.num_radios = get_num_radio_dml();

    if (webconfig_encode(&webconfig_dml.webconfig, &data, webconfig_subdoc_type_mac_filter) == webconfig_error_none) {
        str = data.u.encoded.raw;
        wifi_util_info_print(WIFI_DMCLI, "%s: ACL DML cache encoded successfully  \n", __FUNCTION__);
        push_data_to_ctrl_queue(str, strlen(str), ctrl_event_type_webconfig, ctrl_event_webconfig_set_data_dml);
    } else {
        wifi_util_error_print(WIFI_DMCLI, "%s:%d: Webconfig set failed\n", __func__, __LINE__);
    }

    wifi_util_info_print(WIFI_DMCLI, "%s:  ACL DML cache pushed to queue \n", __FUNCTION__);
    return RETURN_OK;
}

wifi_radio_operationParam_t* get_dml_radio_operation_param(uint8_t radio_index)
{
    if (radio_index < get_num_radio_dml()) {
        return get_wifidb_radio_map(radio_index);
    } else {
        wifi_util_error_print(WIFI_CTRL, "%s: wrong radio_index %d\n", __FUNCTION__, radio_index);
        return NULL;
    }
}

wifi_vap_info_t* get_dml_vap_parameters(uint8_t vapIndex)
{
    uint8_t radio_index = 0, vap_array_index = 0;

    if (get_vap_and_radio_index_from_vap_instance(&((webconfig_dml_t*) get_webconfig_dml())->hal_cap.wifi_prop, vapIndex, &radio_index, &vap_array_index) == RETURN_ERR) {
        return NULL;
    }

    wifi_vap_info_map_t *l_vap_maps = get_wifidb_vap_map(radio_index);
    if (l_vap_maps == NULL || vap_array_index >= MAX_NUM_VAP_PER_RADIO) {
        wifi_util_error_print(WIFI_CTRL, "%s: wrong radio_index %d vapIndex:%d \n", __FUNCTION__, radio_index, vapIndex);
        return NULL;
    }

    return &l_vap_maps->vap_array[vap_array_index];
}

wifi_vap_info_map_t* get_dml_vap_map(uint8_t radio_index)
{
    return get_wifidb_vap_map(radio_index);
}

wifi_global_param_t* get_dml_wifi_global_param(void)
{
     return get_wifidb_wifi_global_param();
}

wifi_GASConfiguration_t* get_dml_wifi_gas_config(void)
{
     return get_wifidb_gas_config();
}

#define PRIVATE 0b0001
#define HOTSPOT 0b0010
#define HOME 0b0100
#define MESH 0b1000
#define MESH_STA 0b10000
#define MESH_BACKHAUL 0b100000
#define LNF 0b1000000

int is_vap_config_changed;
void get_subdoc_type_bit_mask_from_vap_index(uint8_t vap_index, int* subdoc)
{
    if (isVapPrivate(vap_index)) {
        *subdoc = PRIVATE;
        return;
    } else if (isVapHotspot(vap_index) || isVapHotspotSecure(vap_index)) {
        *subdoc = HOTSPOT;
        return;
    } else if (isVapXhs(vap_index)) {
        *subdoc = HOME;
        return;
    } else if (isVapSTAMesh(vap_index)) {
        *subdoc = MESH_STA;
        return;
    } else if (isVapMeshBackhaul(vap_index)) {
        *subdoc = MESH_BACKHAUL;
        return;
    } else if (isVapMesh(vap_index)) {
        *subdoc = MESH;
        return;
    } else if (isVapLnf(vap_index)) {
        *subdoc = LNF;
        return;
    } else {
        *subdoc = MESH_STA;
        return;
    }
}

void set_dml_cache_vap_config_changed(uint8_t vap_index)
{
    int subdoc = 0;
    unsigned int num_radios = get_num_radio_dml();

    if (vap_index <  (num_radios * MAX_NUM_VAP_PER_RADIO)) {
        get_subdoc_type_bit_mask_from_vap_index(vap_index,&subdoc);
        is_vap_config_changed = is_vap_config_changed|subdoc;
        return;
    } else {
        wifi_util_error_print(WIFI_DMCLI, "%s: wrong vap_index %d\n", __FUNCTION__, vap_index);
        return;
    }
}

int push_subdoc_to_one_wifidb(uint8_t subdoc)
{
    webconfig_subdoc_data_t data;
    char *str = NULL;

    memset(&data, 0, sizeof(webconfig_subdoc_data_t));
    memcpy((unsigned char *)&data.u.decoded.radios, (unsigned char *)&webconfig_dml.radios, get_num_radio_dml()*sizeof(rdk_wifi_radio_t));
    memcpy((unsigned char *)&data.u.decoded.hal_cap, (unsigned char *)&webconfig_dml.hal_cap, sizeof(wifi_hal_capability_t));
    data.u.decoded.num_radios = get_num_radio_dml();

    if (webconfig_encode(&webconfig_dml.webconfig, &data, subdoc) == webconfig_error_none) {
        str = data.u.encoded.raw;
        wifi_util_info_print(WIFI_DMCLI, "%s:  VAP DML cache encoded successfully  \n", __FUNCTION__);
        push_data_to_ctrl_queue(str, strlen(str), ctrl_event_type_webconfig, ctrl_event_webconfig_set_data_dml);
    } else {
        wifi_util_error_print(WIFI_DMCLI, "%s:%d: Webconfig set failed\n", __func__, __LINE__);
    }

    wifi_util_info_print(WIFI_DMCLI, "%s:  VAP DML cache pushed to queue \n", __FUNCTION__);
    return RETURN_OK;
}
int push_factory_reset_to_ctrl_queue()
{
    wifi_util_info_print(WIFI_DMCLI, "Inside :%s  \n", __FUNCTION__);
    bool factory_reset_flag =  true;
    push_data_to_ctrl_queue(&factory_reset_flag, sizeof(factory_reset_flag), ctrl_event_type_command, ctrl_event_type_command_factory_reset);
    return RETURN_OK;
}
int push_prefer_private_ctrl_queue(bool flag)
{
    wifi_util_dbg_print(WIFI_DMCLI, "Inside :%s flag=%d \n", __FUNCTION__,flag);
    push_data_to_ctrl_queue(&flag, sizeof(flag), ctrl_event_type_command, ctrl_event_type_prefer_private_rfc);
    return RETURN_OK;
}

int push_rfc_dml_cache_to_one_wifidb(bool rfc_value,ctrl_event_subtype_t rfc)
{
    wifi_util_info_print(WIFI_DMCLI, "Enter:%s  \n", __FUNCTION__);
    push_data_to_ctrl_queue(&rfc_value, sizeof(rfc_value), ctrl_event_type_command, rfc);
    return RETURN_OK;
}

int push_vap_dml_cache_to_one_wifidb()
{

    if(is_vap_config_changed == FALSE)
    {
        wifi_util_info_print(WIFI_DMCLI, "%s: No vap DML Modified Return success  \n", __FUNCTION__);
        return RETURN_OK;
    }

    if (is_vap_config_changed & PRIVATE) {
        wifi_util_info_print(WIFI_DMCLI, "%s: Subdoc webconfig_subdoc_type_private DML Modified  \n", __FUNCTION__);
        push_subdoc_to_one_wifidb(webconfig_subdoc_type_private);
    }
    if (is_vap_config_changed & HOTSPOT) {
        wifi_util_info_print(WIFI_DMCLI, "%s: Subdoc webconfig_subdoc_type_xfinity DML Modified  \n", __FUNCTION__);
        push_subdoc_to_one_wifidb(webconfig_subdoc_type_xfinity);
    }
    if (is_vap_config_changed & HOME) {
        wifi_util_info_print(WIFI_DMCLI, "%s: Subdoc webconfig_subdoc_type_home DML Modified  \n", __FUNCTION__);
        push_subdoc_to_one_wifidb(webconfig_subdoc_type_home);
    }
    if (is_vap_config_changed & MESH_STA) {
        wifi_util_info_print(WIFI_DMCLI, "%s: Subdoc webconfig_subdoc_type_mesh_sta DML Modified  \n", __FUNCTION__);
        push_subdoc_to_one_wifidb(webconfig_subdoc_type_mesh_sta);
    }
    if (is_vap_config_changed & MESH_BACKHAUL) {
        wifi_util_info_print(WIFI_DMCLI, "%s: Subdoc webconfig_subdoc_type_mesh_backhaul DML Modified  \n", __FUNCTION__);
        push_subdoc_to_one_wifidb(webconfig_subdoc_type_mesh_backhaul);
    }
    if (is_vap_config_changed & MESH) {
        wifi_util_info_print(WIFI_DMCLI, "%s: Subdoc webconfig_subdoc_type_mesh DML Modified  \n", __FUNCTION__);
        push_subdoc_to_one_wifidb(webconfig_subdoc_type_mesh);
    }
    if (is_vap_config_changed & LNF) {
        wifi_util_info_print(WIFI_DMCLI, "%s: Subdoc webconfig_subdoc_type_lnf DML Modified  \n", __FUNCTION__);
        push_subdoc_to_one_wifidb(webconfig_subdoc_type_lnf);
    }

    wifi_util_info_print(WIFI_DMCLI, "%s:  VAP DML cache pushed to queue \n", __FUNCTION__);
    is_vap_config_changed = FALSE;
    return RETURN_OK;
}


int push_blaster_config_dml_to_ctrl_queue()
{
    webconfig_subdoc_data_t data;
    char *str = NULL;
    memset(&data, 0, sizeof(webconfig_subdoc_data_t));
    memcpy((unsigned char *)&data.u.decoded.blaster, (unsigned char *)&webconfig_dml.blaster, sizeof(active_msmt_t));
    memcpy((unsigned char *)&data.u.decoded.hal_cap, (unsigned char *)&webconfig_dml.hal_cap, sizeof(wifi_hal_capability_t));
    data.u.decoded.num_radios = get_num_radio_dml();

    if (webconfig_encode(&webconfig_dml.webconfig, &data, webconfig_subdoc_type_blaster) == webconfig_error_none) {
        str = data.u.encoded.raw;
        wifi_util_info_print(WIFI_DMCLI, "%s:  Blaster subdoc encoded successfully  \n", __FUNCTION__);
        push_data_to_ctrl_queue(str, strlen(str), ctrl_event_type_webconfig, ctrl_event_webconfig_set_data_dml);
    } else {
        wifi_util_error_print(WIFI_DMCLI, "%s:%d: Webconfig set failed\n", __func__, __LINE__);
    }
    return RETURN_OK;
}

int process_neighbor_scan_dml()
{
    push_data_to_ctrl_queue(NULL, 0, ctrl_event_type_command, ctrl_event_type_command_wifi_neighborscan);
    wifi_util_info_print(WIFI_DMCLI, "%s: Neighbor scan command pushed to ctrl. queue \n", __FUNCTION__);
    return RETURN_OK;
}

instant_measurement_config_t *get_dml_cache_harvester()
{
    return &webconfig_dml.harvester;
}

instant_measurement_config_t* get_dml_harvester(void)
{
    //Need to modify to fetch from wifidb cache
    return &webconfig_dml.harvester;
}

int push_harvester_dml_cache_to_one_wifidb()
{
    webconfig_subdoc_data_t data;
    char *str = NULL;
    memset(&data, 0, sizeof(webconfig_subdoc_data_t));
    memcpy((unsigned char *)&data.u.decoded.harvester, (unsigned char *)&webconfig_dml.harvester, sizeof(instant_measurement_config_t));
    memcpy((unsigned char *)&data.u.decoded.hal_cap, (unsigned char *)&webconfig_dml.hal_cap, sizeof(wifi_hal_capability_t));

    if (webconfig_encode(&webconfig_dml.webconfig, &data, webconfig_subdoc_type_harvester) == webconfig_error_none) {
        str = data.u.encoded.raw;
        wifi_util_info_print(WIFI_DMCLI, "%s:  Harvester DML cache encoded successfully  \n", __FUNCTION__);
        push_data_to_ctrl_queue(str, strlen(str), ctrl_event_type_webconfig, ctrl_event_webconfig_set_data_dml);
    } else {
        wifi_util_error_print(WIFI_DMCLI, "%s:%d: Webconfig set failed\n", __func__, __LINE__);
    }
    wifi_util_info_print(WIFI_DMCLI, "%s:  Harvester DML cache pushed to queue \n", __FUNCTION__);

    //Rest to default value since instant measurement enable is triggered successfully
    if(webconfig_dml.harvester.b_inst_client_enabled == true){
        webconfig_dml.harvester.b_inst_client_enabled = webconfig_dml.config.global_parameters.inst_wifi_client_enabled;
        webconfig_dml.harvester.u_inst_client_reporting_period = webconfig_dml.config.global_parameters.inst_wifi_client_reporting_period;
        webconfig_dml.harvester.u_inst_client_def_reporting_period = webconfig_dml.config.global_parameters.inst_wifi_client_def_reporting_period;
        webconfig_dml.harvester.u_inst_client_def_override_ttl = 0;
        strncpy(webconfig_dml.harvester.mac_address,(char *)webconfig_dml.config.global_parameters.inst_wifi_client_mac,sizeof(webconfig_dml.harvester.mac_address));
    }
    return RETURN_OK;
}

void update_dml_vap_defaults() {
    int i = 0;
    char wps_pin[128];
    for(i = 0; i<MAX_VAP; i++) {
        vap_default[i].kick_assoc_devices = FALSE;
        vap_default[i].multicast_rate = 123;
        vap_default[i].associated_devices_highwatermark_threshold = 75;
        vap_default[i].long_retry_limit = 16;
        vap_default[i].bss_count_sta_as_cpe = TRUE;
        vap_default[i].retry_limit = 7;
        vap_default[i].wps_methods = (WIFI_ONBOARDINGMETHODS_PUSHBUTTON | WIFI_ONBOARDINGMETHODS_PIN);
        if (i<2) {
            memset(wps_pin, 0, sizeof(wps_pin));
            if (wifi_hal_get_default_wps_pin(wps_pin) == RETURN_OK) {
                strcpy(vap_default[i].wps_pin, wps_pin);
            } else {
                strcpy(vap_default[i].wps_pin, "12345678");
            }
        }
        vap_default[i].txoverflow = 0;
        vap_default[i].router_enabled = TRUE;
    }
}

dml_vap_default *get_vap_default(int vap_index) {
    if (vap_index < 0 || vap_index >= MAX_VAP) {
            wifi_util_error_print(WIFI_DMCLI,"Invalid vap index %d \n", vap_index);
            return NULL;
    }
   return &vap_default[vap_index];
}

dml_radio_default *get_radio_default_obj(int r_index) {
    if (r_index < 0 || r_index >= MAX_NUM_RADIOS) {
            wifi_util_error_print(WIFI_DMCLI,"Invalid radio index %d \n", r_index);
            return NULL;
    }
   return &radio_cfg[r_index];
}

dml_global_default *get_global_default_obj() {
    return &global_cfg;
}

void update_dml_radio_default() {
    int i = 0;

    for(i =0; i<MAX_NUM_RADIOS; i++) {
        radio_cfg[i].AutoChannelSupported = TRUE;
        strncpy(radio_cfg[i].TransmitPowerSupported,"0,12,25,50,75,100",sizeof(radio_cfg[i].TransmitPowerSupported)-1);
        radio_cfg[i].DCSSupported = TRUE;
        radio_cfg[i].ExtensionChannel = 3;
        radio_cfg[i].BasicRate = WIFI_BITRATE_DEFAULT;
        radio_cfg[i].ThresholdRange = 100;
        radio_cfg[i].ThresholdInUse = -99;
        radio_cfg[i].ReverseDirectionGrant = 0;
        radio_cfg[i].AutoChannelRefreshPeriod = 0;
        radio_cfg[i].IEEE80211hEnabled = FALSE;
        radio_cfg[i].DFSEnabled = FALSE;
        radio_cfg[i].IGMPSnoopingEnabled = FALSE;
        radio_cfg[i].FrameBurst = FALSE;
        radio_cfg[i].APIsolation = FALSE;
        radio_cfg[i].OnOffPushButtonTime = 0;
        radio_cfg[i].MulticastRate = 0;
        radio_cfg[i].MCS = 0;
        if (i == 0) {
            strncpy(radio_cfg[i].Alias,"Radio0",sizeof(radio_cfg[i].Alias)-1);
            radio_cfg[i].SupportedFrequencyBands = WIFI_FREQUENCY_2_4_BAND;
            radio_cfg[i].MaxBitRate = 1147;
            strncpy(radio_cfg[i].PossibleChannels,"1,2,3,4,5,6,7,8,9,10,11",sizeof(radio_cfg[i].PossibleChannels)-1);
            strncpy(radio_cfg[i].ChannelsInUse,"1",sizeof(radio_cfg[i].ChannelsInUse)-1);
            strncpy(radio_cfg[i].SupportedStandards,"g,n,ax",sizeof(radio_cfg[i].SupportedStandards)-1);
        }
        else if (i == 1) {
            strncpy(radio_cfg[i].Alias,"Radio1",sizeof(radio_cfg[i].Alias)-1);
            radio_cfg[i].SupportedFrequencyBands = WIFI_FREQUENCY_5_BAND;
            radio_cfg[i].MaxBitRate = 4804;
            strncpy(radio_cfg[i].PossibleChannels,"36,40,44,48,52,56,60,64,100,104,108,112,116,120,124,128,132,136,140,144,149,153,157,161,165",sizeof(radio_cfg[i].PossibleChannels)-1);
            strncpy(radio_cfg[i].ChannelsInUse,"44",sizeof(radio_cfg[i].ChannelsInUse)-1);
            strncpy(radio_cfg[i].SupportedStandards,"a,n,ac,ax",sizeof(radio_cfg[i].SupportedStandards)-1);
        }
    }
}

void update_dml_global_default() {
        strncpy(global_cfg.RadioPower,"PowerUp",sizeof(global_cfg.RadioPower)-1);
}

dml_stats_default *get_stats_default_obj(int r_index)
{
    if (r_index < 0 || r_index >= MAX_NUM_RADIOS) {
        wifi_util_error_print(WIFI_DMCLI,"Invalid radio index %d \n", r_index);
        return NULL;
    }
    return &stats[r_index];
}

void update_dml_stats_default()
{
    int i = 0;
    for(i =0; i<MAX_NUM_RADIOS; i++) {
        stats[i].PacketsOtherReceived = 0;
        stats[i].ActivityFactor_RX = 0;
        stats[i].ActivityFactor_TX = 2;
        stats[i].RetransmissionMetric = 0;
        stats[i].MaximumNoiseFloorOnChannel = 4369;
        stats[i].MinimumNoiseFloorOnChannel =4369;
        stats[i].StatisticsStartTime = 0;
        stats[i].ReceivedSignalLevelNumberOfEntries = 60;
        stats[i].RadioStatisticsMeasuringInterval = 1800;
        stats[i].RadioStatisticsMeasuringRate = 30;
        if (i == 0) {
            stats[i].PLCPErrorCount = 253;
            stats[i].FCSErrorCount = 17;
            stats[i].MedianNoiseFloorOnChannel = -77;
        }else if (i == 1) {
            stats[i].PLCPErrorCount = 23714;
            stats[i].FCSErrorCount = 1565;
            stats[i].MedianNoiseFloorOnChannel = -87;
        }
    }
}

