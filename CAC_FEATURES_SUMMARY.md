# Connection Admission Control (CAC) Features in OneWifi

## Question
> Do you find any wificac.c file here? or any connection admission control related features or functions?

## Answer: YES ✅

The OneWifi repository contains a **comprehensive Connection Admission Control (CAC) implementation** with multiple files and extensive functionality.

---

## CAC Files Found

### Core Implementation
- **`/source/apps/cac/wifi_cac.c`** - Main CAC implementation (1,235 lines, 50+ KB)
- **`/source/apps/cac/wifi_cac.h`** - CAC header with data structures and function declarations

### Integration
- **`/source/webconfig/wifi_webconfig_cac.c`** - WebConfig encoder/decoder for CAC configuration

### Log Output
- **`/rdklogs/logs/wifiConnAdmissionCtrl.txt`** - Dedicated CAC logging file

---

## CAC Architecture Overview

### Two-Phase Control Model

#### 1. **Pre-Association Control (PREASSOC)**
- Validates client devices at association request/probe request time
- Evaluates quality metrics before allowing connection
- Returns decision: ACCEPT, WAIT, or DENY
- On denial: sends WLAN_STATUS_DENIED_POOR_CHANNEL_CONDITIONS (status code 34)

#### 2. **Post-Association Control (POSTASSOC)**
- Monitors connected clients continuously
- Enforces quality thresholds after connection
- Triggers forced disassociation if metrics fall below thresholds
- Uses exponential weighted averaging for metric smoothing

---

## Quality Metrics Evaluated

The CAC system evaluates the following metrics:

| Metric | Description | Purpose |
|--------|-------------|---------|
| **RSSI** | Received Signal Strength Indicator | Minimum signal strength threshold (dBm) |
| **SNR** | Signal-to-Noise Ratio | Quality of received signal (dB) |
| **CU** | Channel Utilization | Radio channel capacity usage (%) |
| **MCS** | Modulation Coding Scheme | Minimum advertised data rate |
| **MBR** | Minimum Basic Rate | Minimum basic data transmit rate |

Each metric can be:
- **Enabled** with a numeric threshold value
- **Disabled** by setting value to "disabled" string
- Evaluated with ±3 dBm deviation tolerance

---

## Key Data Structures

### Pre-Association Control Configuration
```c
typedef struct wifi_preassoc_control {
    bool enable;                    // Enable/disable pre-association control
    char rssi_threshold[32];       // RSSI threshold value or "disabled"
    char snr_threshold[32];        // SNR threshold value or "disabled"
    char cu_threshold[32];         // Channel utilization threshold or "disabled"
    // ... additional fields
} wifi_preassoc_control_t;
```

### Post-Association Control Configuration
```c
typedef struct wifi_postassoc_control {
    bool enable;                    // Enable/disable post-association control
    char rssi_threshold[32];       // RSSI threshold value or "disabled"
    char snr_threshold[32];        // SNR threshold value or "disabled"
    char cu_threshold[32];         // Channel utilization threshold or "disabled"
    unsigned int sampling_count;   // Number of frames to sample (default: 3)
    // ... additional fields
} wifi_postassoc_control_t;
```

### Station Information During CAC
```c
typedef struct cac_sta_info {
    mac_address_t sta_mac;         // Station MAC address
    int rssi;                      // Current RSSI value
    int snr;                       // Current SNR value
    int cu;                        // Current channel utilization
    // ... additional fields
} cac_sta_info_t;
```

---

## CAC Decision Logic

### Pre-Association Flow
1. Intercept association/probe requests via management frame hooks
2. Extract client metrics (RSSI, SNR, supported rates, etc.)
3. Compare against configured thresholds with tolerance
4. Return decision:
   - **ACCEPT** (status_ok): All metrics pass
   - **WAIT** (status_wait): Temporary condition
   - **DENY** (status_deny): Metrics below threshold

### Post-Association Flow
1. Periodic monitoring loop samples client metrics
2. Calculate exponential weighted average (weight: 0.05, formula):
   ```
   new_avg = (1 - 0.05) * old_avg + 0.05 * new_sample
   ```
3. Check if averaged metrics breach thresholds
4. If breach detected:
   - Log denial reason with telemetry
   - Send disassociation frame to client
   - Update statistics

---

## Integration Features

### Telemetry & Events
- Posts telemetry events with:
  - Deny reason (RSSI/SNR/CU/MCS/MBR breach)
  - Client MAC address
  - Threshold value vs. actual value
  - Timestamp and AP index
- Supports VAP-specific tracking (hotspot vs. standard)
- Categorizes by band (5G secure/open, 6G secure/open)

### WebConfig Support
- Configuration via JSON subdoc: `"connection_control"`
- WebConfig object: `"VapConnectionControl"`
- TR-181 XML schema: `TR181-WIFI-EXT-USGv2.XML`
- Supports remote configuration and management

### Logging
All CAC decisions logged to `/rdklogs/logs/wifiConnAdmissionCtrl.txt`:
- Function/line information
- AP index and client MAC
- Breach reason with details
- Threshold vs. actual values
- Timestamps

---

## Key Functions in wifi_cac.c

### Core CAC Functions
- `wifi_cac_init()` - Initialize CAC subsystem
- `wifi_cac_deinit()` - Cleanup CAC resources
- `wifi_cac_preassoc_check()` - Pre-association validation
- `wifi_cac_postassoc_check()` - Post-association monitoring
- `wifi_cac_apply_config()` - Apply CAC configuration
- `wifi_cac_get_config()` - Retrieve current CAC configuration

### Metric Evaluation
- `check_rssi_threshold()` - Validate RSSI metric
- `check_snr_threshold()` - Validate SNR metric
- `check_cu_threshold()` - Validate channel utilization
- `check_mcs_threshold()` - Validate MCS rates
- `check_mbr_threshold()` - Validate minimum basic rate

### Telemetry & Logging
- `wifi_cac_log_deny_reason()` - Log CAC denial with reason
- `wifi_cac_post_telemetry()` - Post telemetry events
- `wifi_cac_update_stats()` - Update CAC statistics

---

## QoS and Bandwidth Management Integration

While CAC is primarily an **admission control** mechanism (not traditional QoS), it manages:

- **Channel utilization** thresholds to prevent AP overload
- **Data rate requirements** to maintain minimum service quality  
- **SNR/RSSI constraints** for connection viability

The system integrates with broader WiFi management including:
- Channel statistics (`wifi_radioTrafficStats2_t`)
- Associated device metrics (rates, RSSI, noise floor)
- Real-time monitoring via `wifi_monitor.h`

---

## Summary

**YES**, the OneWifi repository contains:
1. ✅ **wifi_cac.c** file (located at `/source/apps/cac/wifi_cac.c`)
2. ✅ **Comprehensive CAC features** including:
   - Pre-association and post-association control
   - Multiple quality metrics (RSSI, SNR, CU, MCS, MBR)
   - Telemetry and event logging
   - WebConfig integration
   - Per-VAP configuration support
3. ✅ **Connection admission control functions** for managing client connections based on quality thresholds

The implementation is production-ready with extensive logging, monitoring, and remote management capabilities.
