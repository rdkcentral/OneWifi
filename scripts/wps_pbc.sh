#!/bin/bash

modprobe gpio_keys
EVENT_DEVICE="/dev/input/event0"  # Confirmed from evtest
VAP_INDEX_2G=0  # Virtual AP index for OneWifi
VAP_INDEX_5G=1  # Virtual AP index for OneWifi
VAP_INDEX_6G=2  # Virtual AP index for OneWifi
LOGFILE="/tmp/wps_trigger.log"

echo "Listening for WPS button press on $EVENT_DEVICE..." | tee -a $LOGFILE

# Read event stream and trigger WPS when KEY_WPS_BUTTON (529) is detected
evtest "$EVENT_DEVICE" | while read line; do
    if echo "$line" | grep -q "code 529 (KEY_WPS_BUTTON), value 1"; then
        echo "✅ WPS Button Pressed! Triggering OneWifi WPS for 2G, 5G and 6G..." | tee -a $LOGFILE

        # Kill any existing interactive session before triggering WPS
        pkill -f onewifi_component_test_app

        # Run WPS command and log output
        echo "Executing: echo 'wps $VAP_INDEX' | /usr/bin/onewifi_component_test_app" | tee -a $LOGFILE
        echo "wps $VAP_INDEX_2G" | /usr/bin/onewifi_component_test_app >> $LOGFILE 2>&1

        echo "wps $VAP_INDEX_5G" | /usr/bin/onewifi_component_test_app >> $LOGFILE 2>&1

        echo "wps $VAP_INDEX_6G" | /usr/bin/onewifi_component_test_app >> $LOGFILE 2>&1

        sleep 5  # Prevent multiple triggers within 5 seconds
    fi
done

