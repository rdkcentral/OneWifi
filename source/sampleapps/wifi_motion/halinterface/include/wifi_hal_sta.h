/*
 * If not stated otherwise in this file or this component's LICENSE file the
 * following copyright and licenses apply:
 *
 * Copyright 2016 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/
#ifndef __WIFI_HAL_STA_H__
#define __WIFI_HAL_STA_H__

#ifdef __cplusplus
extern "C"{
#endif

/**
 * @addtogroup WIFI_HAL_TYPES
 * @{
 */
/**
 * @brief Station capabilities.
 */
typedef struct
{

} wifi_sta_capability_t;

/**
 * @brief Station statistics.
 */
typedef struct
{
    UINT vap_index; /**< VAP index. */
    wifi_connection_status_t connect_status; /**< Connection status. */
    UINT channel; /**< Channel. */
    UINT channelWidth; /**< Channel width. */
    UINT op_class; /**< Operating class. */
} wifi_station_stats_t;

/**
 * @brief Connects a client VAP to a specified BSS.
 *
 * @param[in] ap_index Index of the client VAP.
 * @param[in] bss      Pointer to a `wifi_bss_info_t` structure containing
 *                     information about the BSS to connect to.
 *
 * @returns The status of the operation.
 * @retval RETURN_OK If successful.
 * @retval RETURN_ERR If any error is detected.
 */
INT wifi_connect(INT ap_index, wifi_bss_info_t *bss);

/**
 * @brief Disconnects a client VAP.
 *
 * @param[in] ap_index Index of the client VAP.
 *
 * @returns The status of the operation.
 * @retval RETURN_OK If successful.
 * @retval RETURN_ERR If any error is detected.
 */
INT wifi_disconnect(INT ap_index);

/**
 * @brief Gets the capabilities of a station.
 *
 * @param[in] ap_index  Index of the client VAP.
 * @param[out] capability Pointer to a `wifi_sta_capability_t` structure to store
 *                        the station capabilities.
 *
 * @returns The status of the operation.
 * @retval RETURN_OK If successful.
 * @retval RETURN_ERR If any error is detected.
 */
INT wifi_getStationCapability(INT ap_index, wifi_sta_capability_t *cap);

/**
 * @brief Finds available networks.
 *
 * @param[in] ap_index  Index of the client VAP.
 * @param[in] channel   Pointer to a `wifi_channel_t` structure containing the channel
 *                      number and band information.
 * @param[out] bss      Pointer to a pointer to an array of `wifi_bss_info_t`
 *                      structures. The array is allocated by the HAL layer and
 *                      should be freed by the caller.
 * @param[out] num_bss  Pointer to a variable to store the number of BSSs found.
 *
 * @returns The status of the operation.
 * @retval RETURN_OK If successful.
 * @retval RETURN_ERR If any error is detected.
 */
INT wifi_findNetworks(INT ap_index, wifi_channel_t *channel, wifi_bss_info_t **bss, UINT *num_bss);

/**
 * @brief Gets station statistics.
 *
 * @param[in] ap_index Index of the client VAP.
 * @param[out] sta      Pointer to a `wifi_station_stats_t` structure to store the
 *                      station statistics.
 *
 * @returns The status of the operation.
 * @retval RETURN_OK If successful.
 * @retval RETURN_ERR If any error is detected.
 */
INT wifi_getStationStats(INT ap_index, wifi_station_stats_t *sta);

/**
 * @brief Callback function invoked when the station connection status changes.
 *
 * @param[in] apIndex  Index of the client VAP.
 * @param[in] bss_dev  Pointer to a `wifi_bss_info_t` structure containing information
 *                     about the BSS.
 * @param[in] sta      Pointer to a `wifi_station_stats_t` structure containing the
 *                     station statistics.
 *
 * @returns The status of the operation.
 */
typedef INT ( * wifi_staConnectionStatus_callback)(INT apIndex, wifi_bss_info_t *bss_dev, wifi_station_stats_t *sta);

/**
 * @brief Registers a callback function for station connection status changes.
 *
 * @param[in] callback_proc Pointer to the callback function to register.
 */
void wifi_staConnectionStatus_callback_register(wifi_staConnectionStatus_callback callback_proc);

#ifdef __cplusplus
}
#endif

#endif
