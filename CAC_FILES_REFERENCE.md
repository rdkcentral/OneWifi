# CAC Files Quick Reference

## Answer to Your Question

**YES**, the OneWifi repository contains Connection Admission Control (CAC) files and features!

## File Locations

### Primary CAC Implementation Files

1. **wifi_cac.c** (Main Implementation)
   ```
   /source/apps/cac/wifi_cac.c
   Lines: 1,235
   ```

2. **wifi_cac.h** (Header File)
   ```
   /source/apps/cac/wifi_cac.h
   Lines: 89
   ```

3. **wifi_webconfig_cac.c** (WebConfig Integration)
   ```
   /source/webconfig/wifi_webconfig_cac.c
   Lines: 206
   ```

## Other Files Referencing CAC

Based on grep search, 80+ files reference CAC functionality including:

### Build Files
- `/build/openwrt/makefile`
- `/build/openwrt/MT7966.config`
- `/build/linux/rpi/makefile`
- `/build/linux/bpi/makefile`

### Core Components
- `/source/dml/dml_webconfig/dml_onewifi_api.h`
- `/source/dml/dml_webconfig/dml_onewifi_api.c`
- `/source/core/wifi_ctrl.c`
- `/source/core/wifi_ctrl.h`
- `/source/core/wifi_mgr.c`
- `/source/core/wifi_mgr.h`
- `/source/core/services/vap_svc.c`

### Applications and Services
- `/source/apps/wifi_apps.c`
- `/source/apps/wifi_apps_mgr.c`
- `/source/apps/wifi_apps_mgr.h`

### Stats and Monitoring
- `/source/stats/wifi_stats.c`
- `/source/stats/wifi_monitor.c`
- `/source/stats/wifi_monitor.h`

### Database
- `/source/db/wifi_db.c`
- `/source/db/wifi_db.h`
- `/source/db/wifi_db_apis.c`

### Configuration
- `/config/rdkb-wifi.ovsschema`
- `/config/TR181-WiFi-USGv2.XML`
- `/config/TR181-WIFI-EXT-USGv2.XML`
- `/config/bus_dml_config.json`

### Platform
- `/source/platform/common/data_model/wifi_dml_cb.c`
- `/source/platform/common/data_model/wifi_dml_api.c`

### Sample Applications
- `/source/sampleapps/webconfig_consumer_apis.c`
- `/source/sampleapps/wifi_webconfig_consumer.c`
- `/source/sampleapps/wifi_webconfig_consumer.h`

### Utilities
- `/source/utils/wifi_util.c`
- `/source/utils/wifi_validator.c`

## Quick Search Commands

To explore CAC in the repository, use:

```bash
# Find all CAC-related files
find /home/runner/work/OneWifi/OneWifi -name "*cac*" -type f

# Search for CAC references in code
grep -ri "cac\|connection admission control" /home/runner/work/OneWifi/OneWifi --include="*.c" --include="*.h"

# View CAC implementation
cat /home/runner/work/OneWifi/OneWifi/source/apps/cac/wifi_cac.c
cat /home/runner/work/OneWifi/OneWifi/source/apps/cac/wifi_cac.h
```

## Note on File Naming

The file is named **`wifi_cac.c`** (with underscore), not `wificac.c` (without underscore).

## For More Details

See [CAC_FEATURE_SUMMARY.md](./CAC_FEATURE_SUMMARY.md) for comprehensive documentation of all CAC features and functions.
