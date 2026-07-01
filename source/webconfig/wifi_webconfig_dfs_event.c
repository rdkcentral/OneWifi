#include "wifi_webconfig.h"
#include "wifi_util.h"

webconfig_subdoc_object_t dfs_event_objects[3] = {
    { webconfig_subdoc_object_type_version, "Version" },
    { webconfig_subdoc_object_type_subdoc, "SubDocName" },
    { webconfig_subdoc_object_type_dfs_event, "DFSEvent" }
};

webconfig_error_t init_dfs_event_subdoc(webconfig_subdoc_t *doc)
{
    doc->num_objects = sizeof(dfs_event_objects)/sizeof(webconfig_subdoc_object_t);
    memcpy((unsigned char *)doc->objects, (unsigned char *)&dfs_event_objects, sizeof(dfs_event_objects));

    return webconfig_error_none;
}
webconfig_error_t access_check_dfs_event_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    wifi_util_info_print(WIFI_WEBCONFIG, "%s:%d: \n", __func__, __LINE__);
    return webconfig_error_none;
}
webconfig_error_t encode_dfs_event_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    wifi_util_info_print(WIFI_WEBCONFIG, "%s:%d: \n", __func__, __LINE__);
    cJSON *json, *obj;
    char *str;
    em_bus_event_type_dfs_evnt_params_t *params;

    if (data == NULL) {
        return webconfig_error_encode;
    }

    params = &data->u.decoded.dfs_event;

    json = cJSON_CreateObject();
    if (json == NULL) {
        return webconfig_error_encode;
    }

    data->u.encoded.json = json;
    cJSON_AddStringToObject(json, "Version", "1.0");
    cJSON_AddStringToObject(json, "SubDocName", "DFSEvent");

    obj = cJSON_CreateObject();
    cJSON_AddItemToObject(json, "DFSEvent", obj);
    cJSON_AddNumberToObject(obj, "event_type", params->event_type);
    cJSON_AddNumberToObject(obj, "radio_index", params->radio_index);
    cJSON_AddNumberToObject(obj, "op_class", params->op_class);
    cJSON_AddNumberToObject(obj, "channel", params->channel);
    cJSON_AddNumberToObject(obj, "sec_remain_non_occ_dur", params->sec_remain_non_occ_dur);
    cJSON_AddNumberToObject(obj, "status", params->status);
    str = cJSON_Print(json);

    data->u.encoded.raw = (webconfig_subdoc_encoded_raw_t)calloc(strlen(str) + 1, sizeof(char));
    if (data->u.encoded.raw == NULL) {
        cJSON_free(str);
        cJSON_Delete(json);
        return webconfig_error_encode;
    }

    memcpy(data->u.encoded.raw, str, strlen(str) + 1);
    data->descriptor = webconfig_data_descriptor_encoded;
    cJSON_free(str);
    cJSON_Delete(json);

    return webconfig_error_none;
}

webconfig_error_t decode_dfs_event_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    return webconfig_error_none;
}

webconfig_error_t translate_to_dfs_event_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    return webconfig_error_none;
}

webconfig_error_t translate_from_dfs_event_subdoc(webconfig_t *config, webconfig_subdoc_data_t *data)
{
    return webconfig_error_none;
}
