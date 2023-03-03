#!/bin/sh
source /etc/log_timestamp.sh
source /lib/rdk/t2Shared_api.sh
check_count=0
vap_2g_down=0
vap_5g_down=0
vap_6g_down=0
pre_timestamp=0
cur_timestamp=0
private_2g_instance=1
private_5g_instance=2
private_6g_instance=17
hal_indication="/tmp/hal_initialize_failed"
prev_reboot_timestamp=0
cur_reboot_timestamp=0
hal_error_reboot="/nvram/hal_error_reboot"

MODEL_NUM=`grep MODEL_NUM /etc/device.properties | cut -d "=" -f2`
LOG_FILE="/rdklogs/logs/wifi_selfheal.txt"

onewifi_restart_wifi()
{
        echo_t "private_vap is down self heal is executing" >> $LOG_FILE
        systemctl restart onewifi.service
        echo_t "private_vap self heal executed onewifi restarted" >> $LOG_FILE
}

vap_restart()
{
    echo_t "$1 is down. Self heal is executing" >> $LOG_FILE
    max_sta=`dmcli eRT getv Device.WiFi.AccessPoint.$2.X_CISCO_COM_BssMaxNumSta | grep "value:" | cut -f2- -d:| cut -f2- -d:`
    if [ $max_sta == 75 ]; then
        dmcli eRT setv Device.WiFi.AccessPoint.$2.X_CISCO_COM_BssMaxNumSta int 74 > /dev/null
    else
        dmcli eRT setv Device.WiFi.AccessPoint.$2.X_CISCO_COM_BssMaxNumSta int 75 > /dev/null
    fi
    dmcli eRT setv Device.WiFi.ApplyAccessPointSettings bool true > /dev/null
    echo_t "$1  self heal executed" >> $LOG_FILE
}

while true
 do
 if [ $check_count == 3 ]; then
        check_count=0
        cur_timestamp="`date +"%s"` $1"
        #echo_t "cur_timestamp = $cur_timestamp" >> $LOG_FILE
        status_2g=`dmcli eRT getv Device.WiFi.AccessPoint.1.Enable | grep "value:" | cut -f2- -d:| cut -f2- -d:`
         if [ $status_2g == "true" ]; then
                ssid_2g=`wl -i wl0.1 status | grep  -m 1 "BSSID:" | cut -d ":" -f2-7 | awk '{print $1}'`
                if [ $ssid_2g ==  "00:00:00:00:00:00" ];then
                        if [ $vap_2g_down == 1 ]; then
                                time_diff=`expr $cur_timestamp - $pre_timestamp`
                                echo_t "time_diff = $time_diff" >> $LOG_FILE
                                if [ $time_diff -ge 43200 ]; then
                                        onewifi_restart_wifi
                                        pre_timestamp="`date +"%s"` $1"
                                        vap_2g_down=0
                                        continue
                                else
                                        vap_restart "private_2g" $private_2g_instance
                                fi
                        else
                                vap_restart "private_2g" $private_2g_instance
                                vap_2g_down=1
                        fi
                else
                        vap_2g_down=0
                fi
        fi
        status_5g=`dmcli eRT getv Device.WiFi.AccessPoint.2.Enable | grep "value:" | cut -f2- -d:| cut -f2- -d:`
         if [ $status_5g == "true" ]; then
                ssid_5g=`wl -i wl1.1 status | grep  -m 1 "BSSID:" | cut -d ":" -f2-7 | awk '{print $1}'`
                if [ $ssid_5g ==  "00:00:00:00:00:00" ];then
                        if [ $vap_5g_down == 1 ]; then
                                time_diff=`expr $cur_timestamp - $pre_timestamp`
                                echo_t "time_diff = $time_diff" >> $LOG_FILE 
                                if [ $time_diff -ge 43200 ]; then
                                        onewifi_restart_wifi
                                        pre_timestamp="`date +"%s"` $1"
                                        vap_5g_down=0
                                        continue
                                else
                                        vap_restart "private_5g" $private_5g_instance
                                fi
                        else
                                vap_restart "private_5g" $private_5g_instance
                                vap_5g_down=1
                        fi
                else
                        vap_5g_down=0
                fi
        fi

        if [ "$MODEL_NUM" == "CGM4981COM" ]; then
            status_6g=`dmcli eRT getv Device.WiFi.AccessPoint.$private_6g_instance.Enable | grep "value:" | cut -f2- -d:| cut -f2- -d:`
            if [ $status_6g == "true" ]; then
                bss_status="`wl -i wl2.1 bss`"
                if [ $bss_status == "down" ]; then
                    if [ $vap_6g_down == 1 ]; then
                        time_diff=`expr $cur_timestamp - $pre_timestamp`
                        echo_t "time_diff = $time_diff" >> $LOG_FILE
                        if [ $time_diff -ge 43200 ]; then
                            onewifi_restart_wifi
                            pre_timestamp="`date +"%s"` $1"
                            vap_6g_down=0
                            continue
                        else
                            vap_restart "private_6g" $private_6g_instance
                        fi
                    else
                        vap_restart "private_6g" $private_6g_instance
                        vap_6g_down=1
                    fi
                else
                    vap_6g_down=0
                fi
            fi
        fi
 fi
 if [ -f  $hal_indication ]; then
        cur_reboot_timestamp="`date +"%s"` $1"
        if [ -f $hal_error_reboot ]; then
            prev_reboot_timestamp=`cat $hal_error_reboot`
        fi
        time_diff=`expr $cur_reboot_timestamp - $prev_reboot_timestamp`
        if [ $time_diff -ge 86400 ]; then
            echo $cur_reboot_timestamp > $hal_error_reboot
            echo_t "wifi-interface-problem self heal executed" >>  /rdklogs/logs/wifi_selfheal.txt
            echo_t "Rebooting the device" >>  /rdklogs/logs/wifi_selfheal.txt
            dmcli eRT setv Device.DeviceInfo.X_RDKCENTRAL-COM_LastRebootReason string "wifi-interface-problem"
            dmcli eRT setv Device.X_CISCO_COM_DeviceControl.RebootDevice string "Device"
        fi
 fi
 sleep 5m
 ((check_count++))
done
