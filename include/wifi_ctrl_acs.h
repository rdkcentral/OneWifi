/*
 * Automatic Channel Selection (ACS) delegation - OneWifi side.
 *
 * The EasyMesh agent delegates channel selection to OneWifi by writing a channel
 * exclusion list (JSON) to the rbus parameter Device.WiFi.X_RDKCENTRAL-COM_StartACS.
 * This module provides the generic handling (rbus plumbing + JSON decode) and a
 * default fallback channel selection used when no vendor engine is present.
 *
 * Vendor override: the work after decoding goes through platform_acs_apply_exclusion(),
 * whose default definition is weak. A platform with its own channel selection engine
 * links a strong definition of the same symbol to take over (no build flag needed).
 */

#ifndef WIFI_CTRL_ACS_H
#define WIFI_CTRL_ACS_H

#include <stdint.h>
#include "wifi_hal.h"
#include "wifi_ctrl.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Vendor-neutral decoded ACS exclusion entry.
 *
 * Deliberately independent of any vendor HAL type so the override point below stays
 * portable across platforms.
 */
typedef struct {
    uint8_t op_class; /**< IEEE 802.11 Annex E operating class */
    uint8_t channel;  /**< Channel number to exclude within that operating class */
} acs_exclude_entry_t;

/**
 * @brief rbus set handler for Device.WiFi.X_RDKCENTRAL-COM_StartACS.
 *
 * Validates the incoming JSON payload and pushes it to the control queue for
 * processing by process_start_acs_command(). Registered in bus_register_handlers().
 */
bus_error_t set_StartACS(char *name, raw_data_t *p_data, bus_user_data_t *user_data);

/**
 * @brief Control queue handler for the StartACS command.
 *
 * Decodes the JSON exclusion list and forwards the decoded, vendor-neutral list
 * to the channel selection backend (platform_acs_apply_exclusion()). Invoked from
 * handle_command_event() for wifi_event_type_command_start_acs.
 *
 * @param[in] ctrl  wifi control context
 * @param[in] data  NULL-terminated JSON string payload
 * @param[in] len   payload length including the NULL terminator
 */
void process_start_acs_command(wifi_ctrl_t *ctrl, void *data, unsigned int len);

/**
 * @brief Channel selection backend (overridable).
 *
 * Applies a decoded exclusion list to a radio and selects/commits an operating
 * channel. The default implementation (weak symbol in wifi_ctrl_acs.c) performs a
 * generic, deterministic fallback selection. A vendor with its own engine provides
 * a STRONG definition of this symbol to take over.
 *
 * @param[in] ctrl        wifi control context
 * @param[in] radio_index 0-based radio index
 * @param[in] excl        array of exclusion entries (may be NULL when excl_count==0)
 * @param[in] excl_count  number of entries in @p excl (0 = clear/no exclusions)
 * @return RETURN_OK on success, RETURN_ERR on failure
 */
int platform_acs_apply_exclusion(wifi_ctrl_t *ctrl, int radio_index,
                                 const acs_exclude_entry_t *excl, int excl_count);

#ifdef __cplusplus
}
#endif

#endif /* WIFI_CTRL_ACS_H */
