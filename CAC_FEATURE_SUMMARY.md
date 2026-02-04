# Connection Admission Control (CAC) Feature Summary

## Overview
YES, the OneWifi repository contains Connection Admission Control (CAC) related features and functions.

## CAC Files Found

### 1. **wifi_cac.c** - Main CAC Implementation
- **Location**: `/source/apps/cac/wifi_cac.c`
- **Size**: 1,235 lines
- **Description**: Core implementation of WiFi Connection Admission Control functionality

### 2. **wifi_cac.h** - CAC Header File
- **Location**: `/source/apps/cac/wifi_cac.h`
- **Description**: Header file defining CAC data structures, constants, and function prototypes

### 3. **wifi_webconfig_cac.c** - CAC WebConfig Integration
- **Location**: `/source/webconfig/wifi_webconfig_cac.c`
- **Description**: WebConfig integration for CAC configuration management

## Key CAC Features and Functions

### Data Structures
```c
typedef enum {
    status_ok,
    status_wait,
    status_deny
} cac_status_t;

typedef struct {
    unsigned int    ap_index;
    mac_addr_str_t  mac_addr;
    int             num_frames;
    int             rssi_avg;
    int             snr_avg;
    int             uplink_rate_avg;
    int             seconds_alive;
} cac_sta_info_t;

typedef struct {
    unsigned int    ap_index;
    mac_address_t   sta_mac;
    int             rssi_avg;
    int             snr_avg;
    int             uplink_rate_avg;
    int             sampling_count;
    int             sampling_interval;
} cac_associated_devices_t;
```

### Core Functions

1. **cac_event_exec_start()** - Initialize CAC event execution
2. **cac_event_exec_stop()** - Stop CAC event execution
3. **cac_event_exec_timeout()** - Handle CAC timeout events
4. **cac_mgmt_frame_event()** - Process management frame events for CAC
5. **cac_print()** - CAC-specific logging to `/rdklogs/logs/wifiConnAdmissionCtrl.txt`
6. **telemetry_event_cac()** - Send CAC telemetry events

### Admission Control Criteria

The CAC implementation evaluates multiple parameters before admitting clients:

1. **RSSI (Received Signal Strength Indicator)**
   - Pre-association and post-association checks
   - Threshold-based admission control

2. **SNR (Signal-to-Noise Ratio)**
   - Pre-association and post-association checks
   - Ensures minimum signal quality

3. **Channel Utilization (CU)**
   - Monitors channel congestion
   - Prevents overloading of access points

4. **MCS (Modulation and Coding Scheme)**
   - Evaluates client capability
   - Ensures minimum data rate support

5. **Minimum Bit Rate (MBR)**
   - Enforces minimum throughput requirements
   - Uses MCS index to rate mapping table

### Status Codes
- `CAC_STATUS_OK (0)` - Client admission approved
- `CAC_STATUS_DENY (1)` - Client admission denied

### WLAN Status Codes
- `WLAN_STATUS_SUCCESS (0)` - Association successful
- `WLAN_STATUS_AP_UNABLE_TO_HANDLE_NEW_STA (17)` - AP capacity reached
- `WLAN_STATUS_DENIED_POOR_CHANNEL_CONDITIONS (34)` - Poor channel conditions

## WebConfig Integration

The CAC feature integrates with the WebConfig subsystem:

### Configuration Objects
```c
webconfig_subdoc_object_t cac_config_objects[3] = {
    { webconfig_subdoc_object_type_version, "Version" },
    { webconfig_subdoc_object_type_subdoc, "SubDocName" },
    { webconfig_subdoc_object_type_cac, "VapConnectionControl" },
};
```

### Key WebConfig Functions
- `init_cac_config_subdoc()` - Initialize CAC subdocument
- `encode_cac_config_subdoc()` - Encode CAC configuration to JSON
- `decode_cac_config_subdoc()` - Decode CAC configuration from JSON
- `access_check_cac_config_subdoc()` - Access control checks
- `translate_from_cac_config_subdoc()` - Translation from subdoc format
- `translate_to_cac_config_subdoc()` - Translation to subdoc format

## Logging

CAC maintains dedicated logging:
- **Log File**: `/rdklogs/logs/wifiConnAdmissionCtrl.txt`
- **Format**: Timestamped entries with decision details
- **Content**: Pre-association and post-association admission decisions

### Example Log Entries
- `PRE DENY: <index>,RSSI,<mac>,<threshold>,<value>`
- `PRE DENY: <index>,SNR,<mac>,<threshold>,<value>`
- `PRE DENY: <index>,CU,<mac>,<threshold>,<value>`
- `PRE DENY: <index>,MBR,<mac>,<threshold>,<value>`
- `POSTASSOC DENY: <index>,<parameter>,<mac>,<threshold>,<value>`
- `ASSOC ACCEPT` - Client accepted

## Telemetry

CAC provides telemetry events for different VAP types:
- **XHS (5GHz Hotspot Secure)**: `XWIFIS_<type>_accum`
- **XH (5GHz Hotspot Open)**: `XWIFI_<type>_accum`
- **6GHz Hotspot Secure**: `XWIFIS_6G<type>_accum`
- **6GHz Hotspot Open**: `XWIFI_6G<type>_accum`

## MCS to Rate Mapping

The implementation includes comprehensive MCS index to data rate mapping tables for:
- **802.11n** (20MHz, 40MHz channels)
- **802.11ac** (20MHz, 40MHz, 80MHz, 160MHz channels)
- **802.11ax** (20MHz, 40MHz, 80MHz, 160MHz channels)

Support for different guard intervals (400ns/800ns).

## Summary

The OneWifi repository has a **comprehensive Connection Admission Control (CAC) implementation** that:
- Controls client association based on multiple quality metrics
- Supports both pre-association and post-association checks
- Integrates with WebConfig for dynamic configuration
- Provides detailed logging and telemetry
- Supports multiple WiFi standards (802.11n/ac/ax)
- Handles various channel bandwidths (20/40/80/160 MHz)

**Note**: While there is no file named exactly `wificac.c`, the actual CAC implementation is in `wifi_cac.c` (note the underscore).
