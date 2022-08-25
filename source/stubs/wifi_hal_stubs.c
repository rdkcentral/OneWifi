#include <pthread.h>
#include <sys/time.h>
#include <wifi_hal_rdk_framework.h>
#include <wifi_hal_ap.h>
#include <wifi_hal_generic.h>


#define RETURN_OK 0

INT wifi_anqpSendResponse(UINT apIndex, mac_address_t sta, unsigned char token, wifi_anqp_node_t *head)
{
    // TODO: Free previously allocated memory
    return RETURN_OK;
}

INT wifi_hal_purgeScanResult(INT apIndex, bssid_t bssid)
{
    return RETURN_OK;
}

INT wifi_hal_disconnect(INT apIndex)
{
    return RETURN_OK;
}

INT wifi_chan_event_register(wifi_chan_event_CB_t event_cb)
{
    return RETURN_OK;
}

INT wifi_getApInterworkingElement(INT apIndex, wifi_InterworkingElement_t *output_struct)
{
    return RETURN_OK;
}

INT wifi_hal_connect(INT ap_index, wifi_bss_info_t *bss)
{
    return RETURN_OK;
}

INT wifi_hal_createVAP(wifi_radio_index_t index, wifi_vap_info_map_t *map)
{
    return RETURN_OK;
}

INT wifi_hal_findNetworks(INT ap_index, wifi_channel_t *channel, wifi_bss_info_t **bss_array, UINT *num_bss)
{
    return RETURN_OK;
}

INT wifi_hal_get_default_keypassphrase(char *password, int vap_index)
{
    return RETURN_OK;
}

INT wifi_hal_get_default_ssid(char *ssid, int vap_index)
{
    return RETURN_OK;
}

INT wifi_hal_get_default_wps_pin(char *pin)
{
    return RETURN_OK;
}

INT wifi_hal_getHalCapability(wifi_hal_capability_t *hal)
{
    return RETURN_OK;
}

INT wifi_hal_getScanResults(wifi_radio_index_t index, wifi_channel_t *channel, wifi_bss_info_t **bss, UINT *num_bss)
{
    return RETURN_OK;
}

INT wifi_hal_init()
{
    return RETURN_OK;
}

INT wifi_hal_kickAssociatedDevice(INT ap_index, mac_address_t mac)
{
    return RETURN_OK;
}

INT wifi_hal_mgmt_frame_callbacks_register(wifi_receivedMgmtFrame_callback func)
{
    return RETURN_OK;
}

INT wifi_hal_post_init()
{
    return RETURN_OK;
}

INT wifi_hal_pre_init()
{
    return RETURN_OK;
}

void wifi_hal_scanResults_callback_register(wifi_scanResults_callback func)
{
}

INT wifi_hal_setApWpsButtonPush(INT ap_index)
{
    return RETURN_OK;
}

INT wifi_hal_setRadioOperatingParameters(wifi_radio_index_t index, wifi_radio_operationParam_t *operationParam)
{
    return RETURN_OK;
}

void wifi_hal_staConnectionStatus_callback_register(wifi_staConnectionStatus_callback func)
{
}

INT wifi_hal_startScan(wifi_radio_index_t index, wifi_neighborScanMode_t scan_mode, INT dwell_time, UINT num, UINT *chan_list)
{
    return RETURN_OK;
}

INT wifi_hal_get_default_country_code(char *code)
{
    return RETURN_OK;
}

INT wifi_hal_get_default_radius_key(char *radius_key)
{
    return RETURN_OK;
}
