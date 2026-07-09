/*
 * Automatic Channel Selection (ACS) delegation - OneWifi side.
 *
 * The EasyMesh agent delegates channel selection to OneWifi by writing a per-radio
 * channel exclusion list (JSON) to the rbus parameter
 * Device.WiFi.X_RDKCENTRAL-COM_StartACS. This file contains:
 *
 *   1. Generic plumbing (same for every platform): set_StartACS() (rbus -> queue),
 *      decode_acs_exclusion_json() (JSON -> acs_exclude_entry_t[]), and
 *      process_start_acs_command() (decode, then call the backend).
 *   2. The vendor override point platform_acs_apply_exclusion(): weak default. A
 *      platform with its own engine overrides it with a strong symbol (no build flag).
 *   3. The default deterministic fallback selection, used when no vendor engine is
 *      present.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <pthread.h>
#include <cjson/cJSON.h>
#include "wifi_hal.h"
#include "wifi_ctrl.h"
#include "wifi_mgr.h"
#include "wifi_util.h"
#include "wifi_hal_rdk_framework.h"
#include "wifi_stubs.h"
#include "wifi_ctrl_acs.h"

#define ACS_SUBDOC_VERSION      "1.0"
#define ACS_SUBDOC_NAME         "Acs"
#define ACS_MAX_EXCLUDE_ENTRIES 256
#define ACS_MAX_CHANNELS        64

/* Internal OneWifi helpers that have no public header prototype (mirrors the way
   wifi_ctrl_queue_handlers.c uses them). */
extern void start_wifi_sched_timer(unsigned int index, wifi_ctrl_t *ctrl,
    wifi_scheduler_type_t type);
extern int update_wifi_radio_config(int radio_index, wifi_radio_operationParam_t *config,
    wifi_radio_feature_param_t *feat_config);

/**
 * @brief Decoded result of an ACS exclusion JSON sub-document.
 */
typedef struct {
    int radio_index;                /**< 0-based radio index */
    acs_exclude_entry_t *excl_list; /**< Allocated array of exclusion entries (caller frees) */
    int excl_count;                 /**< Number of entries in excl_list */
} acs_exclusion_decoded_t;

/* ----------------------------------------------------------------------------
 *  Section 1 : GENERIC JSON decode + plumbing (vendor reusable)
 * ------------------------------------------------------------------------- */

static int validate_acs_subdoc_header(const cJSON *root)
{
    cJSON *version_obj = cJSON_GetObjectItemCaseSensitive(root, "Version");
    cJSON *subdoc_obj = cJSON_GetObjectItemCaseSensitive(root, "SubDocName");

    if (!cJSON_IsString(version_obj) || version_obj->valuestring == NULL) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d 'Version' is missing or not a string\n", __func__, __LINE__);
        return RETURN_ERR;
    }
    if (0 != strcmp(version_obj->valuestring, ACS_SUBDOC_VERSION)) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d Unsupported Version '%s', expected '%s'\n",
            __func__, __LINE__, version_obj->valuestring, ACS_SUBDOC_VERSION);
        return RETURN_ERR;
    }
    if (!cJSON_IsString(subdoc_obj) || subdoc_obj->valuestring == NULL) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d 'SubDocName' is missing or not a string\n", __func__, __LINE__);
        return RETURN_ERR;
    }
    if (0 != strcmp(subdoc_obj->valuestring, ACS_SUBDOC_NAME)) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d Unexpected SubDocName '%s', expected '%s'\n",
            __func__, __LINE__, subdoc_obj->valuestring, ACS_SUBDOC_NAME);
        return RETURN_ERR;
    }
    return RETURN_OK;
}

static int validate_acs_radio_name(const cJSON *root)
{
    cJSON *radio_name_obj = cJSON_GetObjectItemCaseSensitive(root, "RadioName");
    int radioIndex;

    if (!cJSON_IsString(radio_name_obj) || radio_name_obj->valuestring == NULL) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d 'RadioName' is missing or not a string\n", __func__, __LINE__);
        return RETURN_ERR;
    }
    radioIndex = convert_radio_name_to_radio_index(radio_name_obj->valuestring);
    if (radioIndex < 0 || radioIndex >= (int)getNumberRadios()) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d Invalid RadioName '%s' (resolved index=%d)\n",
            __func__, __LINE__, radio_name_obj->valuestring, radioIndex);
        return RETURN_ERR;
    }
    return radioIndex;
}

static int validate_acs_list_entry(const cJSON *entry)
{
    cJSON *opclass_obj = cJSON_GetObjectItemCaseSensitive(entry, "opclass");
    cJSON *ch_len_obj = cJSON_GetObjectItemCaseSensitive(entry, "exclude_channels_length");
    cJSON *channels_obj = cJSON_GetObjectItemCaseSensitive(entry, "exclude_channels");
    cJSON *ch = NULL;
    int actual_count;

    if (!cJSON_IsNumber(opclass_obj)) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d 'opclass' is missing or not a number\n", __func__, __LINE__);
        return RETURN_ERR;
    }
    if (opclass_obj->valueint <= 0 || opclass_obj->valueint > 255) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d 'opclass' value %d out of range [1..255]\n",
            __func__, __LINE__, opclass_obj->valueint);
        return RETURN_ERR;
    }
    if (!cJSON_IsNumber(ch_len_obj)) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d 'exclude_channels_length' is missing or not a number\n",
            __func__, __LINE__);
        return RETURN_ERR;
    }
    if (ch_len_obj->valueint <= 0) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d 'exclude_channels_length' must be > 0, got %d\n",
            __func__, __LINE__, ch_len_obj->valueint);
        return RETURN_ERR;
    }
    if (!cJSON_IsArray(channels_obj)) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d 'exclude_channels' is missing or not an array\n",
            __func__, __LINE__);
        return RETURN_ERR;
    }
    actual_count = cJSON_GetArraySize(channels_obj);
    if (actual_count != ch_len_obj->valueint) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d 'exclude_channels' size %d != length %d for opclass %d\n",
            __func__, __LINE__, actual_count, ch_len_obj->valueint, opclass_obj->valueint);
        return RETURN_ERR;
    }
    cJSON_ArrayForEach(ch, channels_obj) {
        if (!cJSON_IsNumber(ch)) {
            wifi_util_error_print(WIFI_CTRL, "%s:%d Non-numeric channel in opclass %d\n",
                __func__, __LINE__, opclass_obj->valueint);
            return RETURN_ERR;
        }
        if (ch->valueint <= 0 || ch->valueint > 255) {
            wifi_util_error_print(WIFI_CTRL, "%s:%d Channel %d out of range [1..255] in opclass %d\n",
                __func__, __LINE__, ch->valueint, opclass_obj->valueint);
            return RETURN_ERR;
        }
    }
    return RETURN_OK;
}

/**
 * @brief Decode an ACS exclusion JSON sub-document into a vendor-neutral array.
 *
 * Expected JSON:
 *   { "Version":"1.0", "SubDocName":"Acs", "RadioName":"radio2",
 *     "AcsList":[ {"opclass":115,"exclude_channels_length":2,"exclude_channels":[36,40]} ] }
 *
 * An empty AcsList [] yields excl_list=NULL, excl_count=0 (clear exclusions).
 */
static int decode_acs_exclusion_json(const char *json_str, acs_exclusion_decoded_t *decoded)
{
    cJSON *root = NULL;
    cJSON *acs_list = NULL;
    cJSON *entry = NULL;
    cJSON *channel_obj = NULL;
    int total_channels = 0;
    int excl_count = 0;

    if (json_str == NULL || decoded == NULL) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d NULL input parameter\n", __func__, __LINE__);
        return RETURN_ERR;
    }

    memset(decoded, 0, sizeof(acs_exclusion_decoded_t));
    decoded->radio_index = -1;

    root = cJSON_Parse(json_str);
    if (root == NULL) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d Failed to parse JSON: %s\n", __func__, __LINE__,
            cJSON_GetErrorPtr() ? cJSON_GetErrorPtr() : "unknown error");
        return RETURN_ERR;
    }

    if (RETURN_OK != validate_acs_subdoc_header(root)) {
        goto err;
    }

    decoded->radio_index = validate_acs_radio_name(root);
    if (decoded->radio_index < 0) {
        goto err;
    }

    acs_list = cJSON_GetObjectItemCaseSensitive(root, "AcsList");
    if (!cJSON_IsArray(acs_list)) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d 'AcsList' is missing or not an array\n", __func__, __LINE__);
        goto err;
    }

    if (0 == cJSON_GetArraySize(acs_list)) {
        wifi_util_info_print(WIFI_CTRL, "%s:%d Empty AcsList, clearing exclusions for radio %d\n",
            __func__, __LINE__, decoded->radio_index);
        cJSON_Delete(root);
        return RETURN_OK;
    }

    cJSON_ArrayForEach(entry, acs_list) {
        cJSON *ch_len_obj;
        if (RETURN_OK != validate_acs_list_entry(entry)) {
            goto err;
        }
        ch_len_obj = cJSON_GetObjectItemCaseSensitive(entry, "exclude_channels_length");
        total_channels += ch_len_obj->valueint;
    }

    if (total_channels > ACS_MAX_EXCLUDE_ENTRIES) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d Total exclusion channels %d exceeds maximum %d\n",
            __func__, __LINE__, total_channels, ACS_MAX_EXCLUDE_ENTRIES);
        goto err;
    }

    decoded->excl_list = malloc(sizeof(acs_exclude_entry_t) * total_channels);
    if (decoded->excl_list == NULL) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d Failed to allocate %d entries\n",
            __func__, __LINE__, total_channels);
        goto err;
    }

    cJSON_ArrayForEach(entry, acs_list) {
        cJSON *opclass_obj = cJSON_GetObjectItemCaseSensitive(entry, "opclass");
        cJSON *channels_arr = cJSON_GetObjectItemCaseSensitive(entry, "exclude_channels");
        int op_class = opclass_obj->valueint;

        cJSON_ArrayForEach(channel_obj, channels_arr) {
            decoded->excl_list[excl_count].op_class = (uint8_t)op_class;
            decoded->excl_list[excl_count].channel = (uint8_t)channel_obj->valueint;
            excl_count++;
        }
    }
    decoded->excl_count = excl_count;

    wifi_util_info_print(WIFI_CTRL, "%s:%d Decoded %d exclusion entries for radio %d\n",
        __func__, __LINE__, excl_count, decoded->radio_index);

    cJSON_Delete(root);
    return RETURN_OK;

err:
    cJSON_Delete(root);
    free(decoded->excl_list);
    decoded->excl_list = NULL;
    decoded->excl_count = 0;
    decoded->radio_index = -1;
    return RETURN_ERR;
}

/* ----------------------------------------------------------------------------
 *  Section 2 : DEFAULT FALLBACK channel selection (weak / overridable)
 * ------------------------------------------------------------------------- */

static int acs_opclass_to_bw_slot(uint8_t opclass, wifi_channelBandwidth_t *bw);

/*
 * Returns true if the 20MHz channel `ch` is excluded. The exclusion list is grouped
 * by IEEE operating class; only classes describing 20MHz channels gate a 20MHz
 * primary channel: 81/82 (2.4G), 115/118/121/124/125 (5G), 131/136 (6G). Wider
 * classes (e.g. 83, 128) describe 40/80/160MHz channels and are skipped.
 */
static bool acs_chan_excluded(const acs_exclude_entry_t *excl, int n, int ch)
{
    int i;
    for (i = 0; i < n; i++) {
        wifi_channelBandwidth_t ebw;
        if (acs_opclass_to_bw_slot(excl[i].op_class, &ebw) != 0) {
            continue; /* not a 20MHz operating class: does not gate a 20MHz primary */
        }
        if (excl[i].channel == (uint8_t)ch) {
            return true;
        }
    }
    return false;
}

static bool acs_chan_in_list(const int *list, int len, int ch)
{
    int i;
    for (i = 0; i < len; i++) {
        if (list[i] == ch) {
            return true;
        }
    }
    return false;
}

/* True if every 20MHz sub-channel of (primary, width) is present in allowed[]. */
static bool acs_block_allowed(wifi_freq_bands_t band, wifi_channelBandwidth_t width,
    int primary, const int *allowed, int allowed_len)
{
    int sub[MAX_CHANNELS];
    int sub_n = 0;
    int i;

    if (get_on_channel_scan_list(band, width, primary, sub, &sub_n) != 0 || sub_n == 0) {
        return false;
    }
    for (i = 0; i < sub_n; i++) {
        if (!acs_chan_in_list(allowed, allowed_len, sub[i])) {
            return false;
        }
    }
    return true;
}

static wifi_channelBandwidth_t acs_width_step_down(wifi_channelBandwidth_t w)
{
    switch (w) {
        case WIFI_CHANNELBANDWIDTH_160MHZ: return WIFI_CHANNELBANDWIDTH_80MHZ;
        case WIFI_CHANNELBANDWIDTH_80MHZ:  return WIFI_CHANNELBANDWIDTH_40MHZ;
        case WIFI_CHANNELBANDWIDTH_40MHZ:  return WIFI_CHANNELBANDWIDTH_20MHZ;
        default:                           return WIFI_CHANNELBANDWIDTH_20MHZ;
    }
}

/* Map an IEEE Annex E operating class to a channels_per_bandwidth[] slot + width. */
static int acs_opclass_to_bw_slot(uint8_t opclass, wifi_channelBandwidth_t *bw)
{
    switch (opclass) {
        case 81: case 82: case 115: case 118: case 121: case 124: case 125:
        case 131: case 136:
            *bw = WIFI_CHANNELBANDWIDTH_20MHZ;  return 0;
        case 83: case 84: case 116: case 119: case 122: case 126: case 127:
        case 132:
            *bw = WIFI_CHANNELBANDWIDTH_40MHZ;  return 1;
        case 128: case 130: case 133:
            *bw = WIFI_CHANNELBANDWIDTH_80MHZ;  return 2;
        case 129: case 134:
            *bw = WIFI_CHANNELBANDWIDTH_160MHZ; return 3;
        default:
            return -1;
    }
}

/*
 * Push the exclusion list to the HAL keep out list so a platform ACS engine (if one
 * runs later, e.g. after a DFS hit or reboot) keeps avoiding the excluded channels.
 * Each excluded primary is expanded to its 20MHz sub-channels via
 * get_on_channel_scan_list() and stored per-bandwidth (as process_bandwidth() does).
 */
static void acs_apply_keep_out(int radio_index, wifi_radio_operationParam_t *oper,
    const acs_exclude_entry_t *excl, int n)
{
    int i;

    memset(oper->channels_per_bandwidth, 0, sizeof(oper->channels_per_bandwidth));

    if (n == 0) {
        oper->acs_keep_out_reset = false;
        wifi_hal_set_acs_keep_out_chans(NULL, radio_index);
        return;
    }

    for (i = 0; i < n; i++) {
        wifi_channelBandwidth_t bw = WIFI_CHANNELBANDWIDTH_20MHZ;
        wifi_channels_list_per_bandwidth_t *cl;
        int sub[MAX_CHANNELS];
        int sub_n = 0;
        int max_lists;
        int slot = acs_opclass_to_bw_slot(excl[i].op_class, &bw);

        if (slot < 0 || slot >= MAX_NUM_CHANNELBANDWIDTH_SUPPORTED) {
            wifi_util_dbg_print(WIFI_CTRL, "%s:%d skipping unmapped opclass %d for keep-out\n",
                __func__, __LINE__, excl[i].op_class);
            continue;
        }

        cl = &oper->channels_per_bandwidth[slot];
        max_lists = (int)(sizeof(cl->channels_list) / sizeof(cl->channels_list[0]));
        if (cl->num_channels_list >= max_lists) {
            continue;
        }
        if (get_on_channel_scan_list(oper->band, bw, excl[i].channel, sub, &sub_n) != 0) {
            continue;
        }
        memcpy(cl->channels_list[cl->num_channels_list].channels_list, sub, sizeof(sub));
        cl->channels_list[cl->num_channels_list].num_channels = sub_n;
        cl->num_channels_list++;
        cl->chanwidth = bw;
    }
    wifi_hal_set_acs_keep_out_chans(oper, radio_index);
}

/*
 * Deterministic fallback channel selection (CORE_AIR_0013 / CORE_AIR_0014):
 *   - Operate on the radio's hardware operable 20MHz channels (get_allowed_channels)
 *     minus the channels excluded under a 20MHz operating class.
 *   - Enable ACS only when 2 or more channels remain allowed, else fix the channel.
 *   - If the current channel is still deployable at its width, do not switch (just
 *     refresh keep out and republish). Otherwise pick the lowest allowed channel
 *     whose width block is allowed, stepping the width down (160->80->40->20) when
 *     the current width is not deployable.
 *   - The operating class is left unchanged here; it is refreshed by the driver's
 *     channel change event.
 */
static int acs_select_channel(wifi_ctrl_t *ctrl, int radio_index,
    const acs_exclude_entry_t *excl, int excl_count)
{
    wifi_mgr_t *mgr = get_wifimgr_obj();
    wifi_radio_operationParam_t *oper;
    wifi_radio_feature_param_t *feat;
    wifi_radio_capabilities_t *radio_cap;
    int operable[ACS_MAX_CHANNELS];
    int operable_len = 0;
    int allowed[ACS_MAX_CHANNELS];
    int allowed_len = 0;
    int i;

    if (mgr == NULL) {
        return RETURN_ERR;
    }

    oper = (wifi_radio_operationParam_t *)get_wifidb_radio_map((uint8_t)radio_index);
    feat = (wifi_radio_feature_param_t *)get_wifidb_radio_feat_map((uint8_t)radio_index);
    if (oper == NULL || feat == NULL) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d no radio map for index %d\n",
            __func__, __LINE__, radio_index);
        return RETURN_ERR;
    }

    radio_cap = &mgr->hal_cap.wifi_prop.radiocap[radio_index];

    if (get_allowed_channels(oper->band, radio_cap, operable, &operable_len, oper->DfsEnabled)
            != RETURN_OK || operable_len == 0) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d no operable channels for radio %d band %d\n",
            __func__, __LINE__, radio_index, oper->band);
        return RETURN_ERR;
    }

    for (i = 0; i < operable_len && allowed_len < ACS_MAX_CHANNELS; i++) {
        if (!acs_chan_excluded(excl, excl_count, operable[i])) {
            allowed[allowed_len++] = operable[i];
        }
    }

    wifi_util_info_print(WIFI_CTRL,
        "%s:%d radio %d band %d cur_ch %d width %d : %d operable, %d allowed\n",
        __func__, __LINE__, radio_index, oper->band, oper->channel,
        oper->channelWidth, operable_len, allowed_len);

    /* CORE_AIR_0014: automatic channel selection is enabled only when 2 or more
       20MHz channels are allowed; with fewer than two it is a fixed channel. */
    pthread_mutex_lock(&mgr->data_cache_lock);
    oper->autoChannelEnabled = (allowed_len >= 2);
    pthread_mutex_unlock(&mgr->data_cache_lock);

    /* Refresh the HAL keep out list whether or not we switch channel. */
    acs_apply_keep_out(radio_index, oper, excl, excl_count);

    /* If the current operating channel is still deployable, do not switch. */
    if (acs_chan_in_list(allowed, allowed_len, oper->channel) &&
        acs_block_allowed(oper->band, oper->channelWidth, oper->channel, allowed, allowed_len)) {
        wifi_util_info_print(WIFI_CTRL,
            "%s:%d radio %d current channel %d still allowed, no switch\n",
            __func__, __LINE__, radio_index, oper->channel);
        goto publish;
    }

    if (allowed_len == 0) {
        wifi_util_error_print(WIFI_CTRL,
            "%s:%d radio %d has no allowed channel after exclusion; channel unchanged\n",
            __func__, __LINE__, radio_index);
        return RETURN_ERR;
    }

    {
        wifi_channelBandwidth_t width = oper->channelWidth;
        int new_chan = -1;
        wifi_channelBandwidth_t new_width = width;
        bool done = false;

        while (!done) {
            for (i = 0; i < allowed_len; i++) {
                wifi_radio_operationParam_t trial;
                if (!acs_block_allowed(oper->band, width, allowed[i], allowed, allowed_len)) {
                    continue;
                }
                trial = *oper;
                trial.channel = allowed[i];
                trial.channelWidth = width;
                if (wifi_radio_operationParam_validation(&mgr->hal_cap, &trial) == RETURN_OK) {
                    new_chan = allowed[i];
                    new_width = width;
                    done = true;
                    break;
                }
            }
            if (done || width == WIFI_CHANNELBANDWIDTH_20MHZ) {
                break;
            }
            width = acs_width_step_down(width);
        }

        if (new_chan < 0) {
            wifi_util_error_print(WIFI_CTRL,
                "%s:%d radio %d could not find a deployable channel\n",
                __func__, __LINE__, radio_index);
            return RETURN_ERR;
        }

        pthread_mutex_lock(&mgr->data_cache_lock);
        oper->channel = new_chan;
        oper->channelWidth = new_width;
        pthread_mutex_unlock(&mgr->data_cache_lock);

        if (wifi_hal_setRadioOperatingParameters(radio_index, oper) != RETURN_OK) {
            wifi_util_error_print(WIFI_CTRL,
                "%s:%d wifi_hal_setRadioOperatingParameters failed radio %d ch %d width %d\n",
                __func__, __LINE__, radio_index, new_chan, new_width);
            return RETURN_ERR;
        }
        wifi_util_info_print(WIFI_CTRL,
            "%s:%d ACS selected channel %d width %d on radio %d\n",
            __func__, __LINE__, new_chan, new_width, radio_index);
    }

publish:
    /* Persist + trigger northbound radio sub-document publish so the EasyMesh agent
       emits an Operating Channel Report (mirrors process_channel_change_event). */
    mgr->ctrl.webconfig_state |= ctrl_webconfig_state_radio_cfg_rsp_pending;
    start_wifi_sched_timer((unsigned int)radio_index, ctrl, wifi_radio_sched);
    update_wifi_radio_config(radio_index, oper, feat);
    return RETURN_OK;
}

/*
 * Vendor override point. Weak default = generic fallback above. A platform with its own
 * channel selection engine links a STRONG definition of this same symbol to take
 * over (the generic decode/plumbing above stays shared).
 */
__attribute__((weak))
int platform_acs_apply_exclusion(wifi_ctrl_t *ctrl, int radio_index,
    const acs_exclude_entry_t *excl, int excl_count)
{
    return acs_select_channel(ctrl, radio_index, excl, excl_count);
}

/* ----------------------------------------------------------------------------
 *  Section 1 (cont.) : command-queue handler + rbus set handler
 * ------------------------------------------------------------------------- */

void process_start_acs_command(wifi_ctrl_t *ctrl, void *data, unsigned int len)
{
    acs_exclusion_decoded_t decoded = { 0 };

    if (data == NULL || len == 0) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d NULL or empty input\n", __func__, __LINE__);
        return;
    }

    wifi_util_info_print(WIFI_CTRL, "%s:%d StartACS JSON received: '%s'\n",
        __func__, __LINE__, (char *)data);

    if (RETURN_OK != decode_acs_exclusion_json((const char *)data, &decoded)) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d Failed to decode ACS exclusion JSON\n",
            __func__, __LINE__);
        return;
    }

    /* Hand the decoded, vendor-neutral list to the channel selection backend. */
    platform_acs_apply_exclusion(ctrl, decoded.radio_index, decoded.excl_list, decoded.excl_count);

    free(decoded.excl_list);
}

bus_error_t set_StartACS(char *name, raw_data_t *p_data, bus_user_data_t *user_data)
{
    char *pTmp = NULL;
    unsigned int payload_len = 0;
    (void)user_data;

    if (!name) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d element name is not found\r\n", __func__, __LINE__);
        return bus_error_element_name_missing;
    }
    if (p_data->data_type != bus_data_type_string) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d wrong bus data_type:%x\n",
            __func__, __LINE__, p_data->data_type);
        return bus_error_invalid_input;
    }

    pTmp = (char *)p_data->raw_data.bytes;
    payload_len = p_data->raw_data_len;

    if (pTmp == NULL || pTmp[0] == '\0' || payload_len == 0) {
        wifi_util_error_print(WIFI_CTRL, "%s:%d payload is NULL or empty\n", __func__, __LINE__);
        return bus_error_invalid_input;
    }

    pTmp[payload_len] = '\0';

    wifi_util_info_print(WIFI_CTRL, "%s:%d StartACS request received: '%s'\n",
        __func__, __LINE__, pTmp);

    push_event_to_ctrl_queue(pTmp, (payload_len + 1), wifi_event_type_command,
        wifi_event_type_command_start_acs, NULL);

    return bus_error_success;
}
