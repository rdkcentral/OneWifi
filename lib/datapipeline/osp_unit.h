#ifndef OSP_UNIT_H_INCLUDED
#define OSP_UNIT_H_INCLUDED

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>


/// @file
/// @brief OSP Unit API
///
/// @addtogroup OSP
/// @{


// ===========================================================================
//  Unit API
// ===========================================================================

/// @defgroup OSP_UNIT Unit API
/// OpenSync Unit API
/// @{


/**
 * @brief Return device identification
 *
 * This function provides a null terminated byte string containing the device
 * identification. The device identification is part of the AWLAN_Node table.
 * In the simplest implementation, this function may be the same as
 * osp_unit_serial_get().
 *
 * @param buff   pointer to a string buffer
 * @param buffsz size of string buffer
 * @return true on success
 */
bool osp_unit_id_get(char *buff, size_t buffsz);

/**
 * @brief Return device serial number
 *
 * This function provides a null terminated byte string containing the serial
 * number. The serial number is part of the AWLAN_Node table.
 * For example, the serial number may be derived from the MAC address.
 * Please see implementation inside osp_unit.c file for the reference.
 *
 * @param buff   pointer to a string buffer
 * @param buffsz size of string buffer
 * @return true on success
 */
bool osp_unit_serial_get(char *buff, size_t buffsz);

/**
 * @brief Return device model
 *
 * This function provides a null terminated byte string containing the device
 * model. The device model is a part of the AWLAN_Node table.
 *
 * In the simplest implementation, this function may return the value of
 * CONFIG_TARGET_MODEL.
 *
 * It is safe to return false here. The TARGET_NAME will be used
 * as a model name in that case.
 *
 * @param buff   pointer to a string buffer
 * @param buffsz size of string buffer
 * @return true on success
 */
bool osp_unit_model_get(char *buff, size_t buffsz);

/**
 * @brief Return device stock keeping unit number
 *
 * This function provides a null terminated byte string containing the stock
 * keeping unit number. It is usually used by stores to track inventory.
 * The SKU is part of the AWLAN_Node table.
 *
 * If cloud doesn't support SKU for this target, this function should return
 * false.
 *
 * @param buff   pointer to a string buffer
 * @param buffsz size of string buffer
 * @return true on success
 */
bool osp_unit_sku_get(char *buff, size_t buffsz);

/**
 * @brief Return hardware version number
 *
 * This function provides a null terminated byte string containing the hardware
 * version number. The hardware version is part of the AWLAN_Node table.
 * If not needed this function should return false.
 *
 * @param buff   pointer to a string buffer
 * @param buffsz size of string buffer
 * @return true on success
 */
bool osp_unit_hw_revision_get(char *buff, size_t buffsz);

/**
 * @brief Return platform version number
 *
 * This function provides a null terminated byte string containing the platform
 * version number. The platform version number is part of the AWLAN_Node table.
 * If not needed this function should return false.
 *
 * @param buff   pointer to a string buffer
 * @param buffsz size of string buffer
 * @return true on success
 */
bool osp_unit_platform_version_get(char *buff, size_t buffsz);

/**
 * @brief Return software version number
 *
 * This function provides a null terminated byte string containing the software
 * version number.
 * Expected format: VERSION-BUILD_NUMBER-gGITSHA-PROFILE
 * Sample: 1.0.0.0-200-g1a2b3c-devel
 *
 * @param buff   pointer to a string buffer
 * @param buffsz size of string buffer
 * @return true on success
 */
bool osp_unit_sw_version_get(char *buff, size_t buffsz);

/**
 * @brief Return vendor name
 *
 * This function provides a null terminated byte string containing the device's
 * vendor name. The vendor name is part of the AWLAN_Node table.
 * It is safe to return false here if not needed.
 *
 * @param  buff   pointer to a string buffer
 * @param  buffsz size of string buffer
 * @return true on success
 */
bool osp_unit_vendor_name_get(char *buff, size_t buffsz);

/**
 * @brief Return vendor part number
 *
 * This function provides a null terminated byte string containing the device's
 * vendor part number. The vendor part number is part of the AWLAN_Node table.
 * It is safe to return false here if not needed.
 *
 * @param  buff   pointer to a string buffer
 * @param  buffsz size of string buffer
 * @return true on success
 */
bool osp_unit_vendor_part_get(char *buff, size_t buffsz);

/**
 * @brief Return manufacturer name
 *
 * This function provides a null terminated byte string containing the
 * manufacturer name who built the device. The manufacturer name is part of
 * the AWLAN_Node table.
 * It is safe to return false here if not needed or unknown.
 *
 * @param  buff   pointer to a string buffer
 * @param  buffsz size of string buffer
 * @return true on success
 */
bool osp_unit_manufacturer_get(char *buff, size_t buffsz);

/**
 * @brief Return factory name
 *
 * This function provides a null terminated byte string containing the factory
 * name where the device was built. The factory name is part of the AWLAN_Node
 * table.
 * It is safe to return false here if not needed or unknown.
 *
 * @param  buff   pointer to a string buffer
 * @param  buffsz size of string buffer
 * @return true on success
 */
bool osp_unit_factory_get(char *buff, size_t buffsz);

/**
 * @brief Return manufacturing date
 *
 * This function provides a null terminated byte string containing the date
 * when the device was built. The date should be in a format "YYYY/WW", where
 * YYYY stands for year, and WW stands for work week of the year.
 * The manufacturing date is part of the AWLAN_Node table.
 * It is safe to return false here if not needed or unknown.
 *
 * @param  buff   pointer to a string buffer
 * @param  buffsz size of string buffer
 * @return true on success
 */
bool osp_unit_mfg_date_get(char *buff, size_t buffsz);

/**
 * @brief Return serial_model hostname
 *
 * This function provides a null terminated byte string to be used as a 
 * hostname for DHCP client. The default implementation returns
 * string in <SERIAL>_<MODEL> format
 *
 * @param  buff   pointer to a string buffer
 * @param  buffsz size of string buffer
 * @return true on success
 */
bool osp_unit_dhcpc_hostname_get(void *buff, size_t buffsz);

/* Note WPA3 configuration is not supported by the lagacy security schema ("security" parameter
   in Wifi_VIF_Config table). Therefore need to switch to the new schema in case correspoding
   RFC is being set for WPA3 capable devices. But Cloud-Controller can work with the new schema
   only in case the third digit in FW version is >= 3, for example:
   3.4.3; 4.0.3; 4.1.4 - these versions support new security schema.
   3.4.2; 4.0.1; 4.1.0 - these versions do not support new security schema.
*/

bool osp_unit_sec_schema_is_legacy(void);

/// @} OSP_UNIT
/// @} OSP

#endif /* OSP_UNIT_H_INCLUDED */
