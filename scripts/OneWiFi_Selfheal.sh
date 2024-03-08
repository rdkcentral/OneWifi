#!/bin/sh
source /etc/log_timestamp.sh
source /lib/rdk/t2Shared_api.sh
source /usr/ccsp/tad/corrective_action.sh
check_count=0
vap_2g_down=0
vap_5g_down=0
vap_6g_down=0
pre_timestamp=0
cur_timestamp=0
radio_2g_instance=1
radio_5g_instance=2
radio_6g_instance=3
private_2g_instance=1
private_5g_instance=2
private_6g_instance=17
hal_indication="/tmp/hal_initialize_failed"
prev_reboot_timestamp=0
cur_reboot_timestamp=0
hal_error_reboot="/nvram/hal_error_reboot"
dml_status=0
dml_restart=0
wifi_stuck_detect="/nvram/wifi_stuck_detect"
pre_rxprobe_req_2g_cnt=0
cur_rxprobe_req_2g_cnt=0
pre_txprobe_resp_2g_cnt=0
cur_txprobe_resp_2g_cnt=0
pre_rxprobe_req_5g_cnt=0
cur_rxprobe_req_5g_cnt=0
pre_txprobe_resp_5g_cnt=0
cur_txprobe_resp_5g_cnt=0
force_reset_subdoc=0
webcfg_rfc_enabled=""

SW_UPGRADE_DEFAULT_FILE="/tmp/sw_upgrade_private_defaults"
wave_driver_restart_cnt=0
bss_queue_full=0
bss_queue_full_cnt=0

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
    # This is to set supported stations in order to restore station cfg but re-visit the Self-Heal reason */
    echo_t "$1 is down. Self heal is executing" >> $LOG_FILE
    dmcli eRT setv Device.WiFi.AccessPoint.$2.ForceApply bool true > /dev/null
    echo_t "$1  self heal executed" >> $LOG_FILE
}

print_wifi_2g_txprobe_cnt()
{
    echo_t "pre_rxprobe_req_2g_cnt = $pre_rxprobe_req_2g_cnt" >> $LOG_FILE
    echo_t "cur_rxprobe_req_2g_cnt = $cur_rxprobe_req_2g_cnt" >> $LOG_FILE
    echo_t "pre_txprobe_resp_2g_cnt = $pre_txprobe_resp_2g_cnt" >> $LOG_FILE
    echo_t "cur_txprobe_resp_2g_cnt = $cur_txprobe_resp_2g_cnt" >> $LOG_FILE
}

sync_all_wifi_2g_txprobe_cnt()
{
    pre_rxprobe_req_2g_cnt=`wl -i wl0.1 counters | grep  -m 1 "rxprobereq " | cut -d ":" -f2-7 | awk '{print $6}'`
    cur_rxprobe_req_2g_cnt=$pre_rxprobe_req_2g_cnt

    pre_txprobe_resp_2g_cnt=`wl -i wl0.1 counters | grep  -m 1 "txprobersp " | cut -d ":" -f2-7 | awk '{print $8}'`
    cur_txprobe_resp_2g_cnt=$pre_txprobe_resp_2g_cnt
}

check_wifi_2g_stuck_status()
{
    if [ $pre_rxprobe_req_2g_cnt == 0 ]; then
        sync_all_wifi_2g_txprobe_cnt
        print_wifi_2g_txprobe_cnt
    else
        cur_rxprobe_req_2g_cnt=`wl -i wl0.1 counters | grep  -m 1 "rxprobereq " | cut -d ":" -f2-7 | awk '{print $6}'`
        if [ $cur_rxprobe_req_2g_cnt -gt $pre_rxprobe_req_2g_cnt ]; then
            cur_txprobe_resp_2g_cnt=`wl -i wl0.1 counters | grep  -m 1 "txprobersp " | cut -d ":" -f2-7 | awk '{print $8}'`
            if [ $cur_txprobe_resp_2g_cnt -eq $pre_txprobe_resp_2g_cnt ]; then
                print_wifi_2g_txprobe_cnt
                if [ -f $wifi_stuck_detect ]; then
                    echo_t "wifi 2g radio re-init" >>  $LOG_FILE
                    `wl -i wl0 reinit`
                else
                    echo_t "2G wifi radio in bad state, Enable WiFiStuckDetect RFC to resolve the issue" >>  $LOG_FILE
                fi
            fi
        fi
        sync_all_wifi_2g_txprobe_cnt
    fi
}

print_wifi_5g_txprobe_cnt()
{
    echo_t "pre_rxprobe_req_5g_cnt = $pre_rxprobe_req_5g_cnt" >> $LOG_FILE
    echo_t "cur_rxprobe_req_5g_cnt = $cur_rxprobe_req_5g_cnt" >> $LOG_FILE
    echo_t "pre_txprobe_resp_5g_cnt = $pre_txprobe_resp_5g_cnt" >> $LOG_FILE
    echo_t "cur_txprobe_resp_5g_cnt = $cur_txprobe_resp_5g_cnt" >> $LOG_FILE
}

sync_all_wifi_5g_txprobe_cnt()
{
    pre_rxprobe_req_5g_cnt=`wl -i wl1.1 counters | grep  -m 1 "rxprobereq " | cut -d ":" -f2-7 | awk '{print $6}'`
    cur_rxprobe_req_5g_cnt=$pre_rxprobe_req_5g_cnt

    pre_txprobe_resp_5g_cnt=`wl -i wl1.1 counters | grep  -m 1 "txprobersp " | cut -d ":" -f2-7 | awk '{print $8}'`
    cur_txprobe_resp_5g_cnt=$pre_txprobe_resp_5g_cnt
}

check_wifi_5g_stuck_status()
{
    if [ $pre_rxprobe_req_5g_cnt == 0 ]; then
        sync_all_wifi_5g_txprobe_cnt
        print_wifi_5g_txprobe_cnt
    else
        cur_rxprobe_req_5g_cnt=`wl -i wl1.1 counters | grep  -m 1 "rxprobereq " | cut -d ":" -f2-7 | awk '{print $6}'`
        if [ $cur_rxprobe_req_5g_cnt -gt $pre_rxprobe_req_5g_cnt ]; then
            cur_txprobe_resp_5g_cnt=`wl -i wl1.1 counters | grep  -m 1 "txprobersp " | cut -d ":" -f2-7 | awk '{print $8}'`
            if [ $cur_txprobe_resp_5g_cnt -eq $pre_txprobe_resp_5g_cnt ]; then
                print_wifi_5g_txprobe_cnt
                if [ -f $wifi_stuck_detect ]; then
                    echo_t "wifi 5g radio re-init" >>  $LOG_FILE
                    `wl -i wl1 reinit`
                else
                    echo_t "5G wifi radio in bad state, Enable WiFiStuckDetect RFC to resolve the issue" >>  $LOG_FILE
                fi
            fi
        fi
        sync_all_wifi_5g_txprobe_cnt
    fi
}

#Check for bss queue full
check_bss_queue_full()
{
    if [ -f /proc/net/mtlk/wlan2.0/General ]; then
        bss_mgmt_free_entries_1="$(cat  /proc/net/mtlk/wlan2.0/General | grep  -w  "mgmt bds queue free entries"  | grep -o -E [0-9]+ | head -1)"
        bss_mgmt_free_entries_2="$(cat  /proc/net/mtlk/wlan2.0/General | grep -w  "mgmt bds queue free entries (reserved queue)" | grep -o -E [0-9]+)"
        if [ "$bss_mgmt_free_entries_1" == "0"  -a  "$bss_mgmt_free_entries_2" == "0" ]; then
            echo_t "bss Queue full" >> $LOG_FILE
            bss_queue_full=1
        else
            bss_queue_full=0
        fi
    fi
}

#wave driver restart for CMXB7
wave_driver_restart()
{
    echo_t "5G private SSID is down self heal is executing" >> $LOG_FILE
    systemctl stop onewifi.service
    systemctl stop systemd-wave_init.service
    sleep 3
    systemctl start systemd-wave_init.service
    systemctl start onewifi.service
    echo_t "5G private SSID  self heal executed onewifi and wave driver restarted" >> $LOG_FILE

}

#Check bss queue for one min in 10 sec interval
check_bss_queue_one_min()
{
    while true
    do
        check_bss_queue_full
        if [ "$bss_queue_full" == "1"  -a  "$bss_queue_full_cnt" -le "6" ]; then
            sleep 10
            ((bss_queue_full_cnt++))
        else
            break
        fi
    done
}

while true
do
    if [ "$MODEL_NUM" == "TG4482A" ]; then
        #CMXB7 onewifi selfheal for Both BSS TX queues full, dropping the frame
        echo_t "Executing Onewifi selfheal for CMXB7" >> $LOG_FILE
        mw=0
        checkMaintenanceWindow
        if [ "$reb_window" == "1" ]; then
            mw=1
            wave_driver_restart_cnt=0
        fi
        check_bss_queue_full
        if [ "$bss_queue_full" == "1" ]; then
            if [ "$mw" == "1" ]; then
                echo_t "In maintenance window " >>  $LOG_FILE
                check_bss_queue_one_min
                if [ "$bss_queue_full" == "1" ]; then
                    wave_driver_restart
                    wave_driver_restart_cnt=0
                fi
            else
                echo_t "Not in maintenance window " >>  $LOG_FILE
                if [ $wave_driver_restart_cnt -eq 0 ]; then
                    check_bss_queue_one_min
                    if [ "$bss_queue_full" == "1" ]; then
                        wave_driver_restart
                        wave_driver_restart_cnt=1
                    fi
                fi
            fi
        fi
    else
        if [ $check_count == 3 ]; then
            check_count=0
            cur_timestamp="`date +"%s"` $1"
            #echo_t "cur_timestamp = $cur_timestamp" >> $LOG_FILE
            if [ "$MODEL_NUM" == "SR213" ]; then
                eco_mode_2g=`dmcli eRT getv Device.WiFi.Radio.$radio_2g_instance.X_RDK_EcoPowerDown | grep "value:" | cut -f2- -d:| cut -f2- -d:` 
                eco_mode_5g=`dmcli eRT getv Device.WiFi.Radio.$radio_5g_instance.X_RDK_EcoPowerDown | grep "value:" | cut -f2- -d:| cut -f2- -d:` 
            else
                eco_mode_2g="false"
                eco_mode_5g="false"
            fi
            if [ $eco_mode_2g == "false" ]; then
                radio_status_2g=`dmcli eRT getv Device.WiFi.Radio.$radio_2g_instance.Enable | grep "value:" | cut -f2- -d:| cut -f2- -d:` 
                if [ $radio_status_2g == "true" ]; then
                    status_2g=`dmcli eRT getv Device.WiFi.AccessPoint.$private_2g_instance.Enable | grep "value:" | cut -f2- -d:| cut -f2- -d:`
                    if [ $status_2g == "true" ]; then
                        if [ "$MODEL_NUM" == "VTER11QEL" ]; then
                            ssid_2g=`iw dev ath0 info |grep -w "addr" |awk '{print $2}'`
                        else
                            ssid_2g=`wl -i wl0.1 status | grep  -m 1 "BSSID:" | cut -d ":" -f2-7 | awk '{print $1}'`
                        fi
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
                fi
            fi
            if [ $eco_mode_5g == "false" ]; then
                radio_status_5g=`dmcli eRT getv Device.WiFi.Radio.$radio_5g_instance.Enable | grep "value:" | cut -f2- -d:| cut -f2- -d:` 
                if [ $radio_status_5g == "true" ]; then
                    status_5g=`dmcli eRT getv Device.WiFi.AccessPoint.$private_5g_instance.Enable | grep "value:" | cut -f2- -d:| cut -f2- -d:`
                    if [ $status_5g == "true" ]; then
                        if [ "$MODEL_NUM" == "VTER11QEL" ]; then
                            ssid_5g=`iw dev ath1 info |grep -w "addr" |awk '{print $2}'`
                        else
                            ssid_5g=`wl -i wl1.1 status | grep  -m 1 "BSSID:" | cut -d ":" -f2-7 | awk '{print $1}'`
                        fi
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
                fi
            fi

            if [ "$MODEL_NUM" == "CGM4981COM" ] || [ "${MODEL_NUM}" = "CGM601TCOM" ] || [ "${MODEL_NUM}" = "SG417DBCT" ]; then
                radio_status_6g=`dmcli eRT getv Device.WiFi.Radio.$radio_6g_instance.Enable | grep "value:" | cut -f2- -d:| cut -f2- -d:` 
                if [ $radio_status_6g == "true" ]; then
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

        #we need to use this changes for only TechXB7 device.
        if [ "$MODEL_NUM" == "CGM4331COM" -o "$MODEL_NUM" == "CGA4332COM" ]; then
            check_wifi_2g_stuck_status
            check_wifi_5g_stuck_status
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
                echo_t "wifi-interface-problem self heal executed" >>  $LOG_FILE
                echo_t "Rebooting the device" >>  $LOG_FILE
                dmcli eRT setv Device.DeviceInfo.X_RDKCENTRAL-COM_LastRebootReason string "wifi-interface-problem"
                dmcli eRT setv Device.X_CISCO_COM_DeviceControl.RebootDevice string "Device"
            fi
        fi
    fi

    dml_status=`dmcli eRT getv Device.WiFi.SSID.1.Enable | grep -c "error code:"`
    if [ $dml_status != 0 ]; then
        ((dml_restart++))
        echo_t "DMCLI unresponsive" >>  $LOG_FILE
    else
        dml_restart=0
    fi
    if [ $dml_restart -ge 3 ]; then
        dml_restart=0
        echo_t "DMCLI crashed self heal executed restarting OneWifi" >>  $LOG_FILE
        onewifi_restart_wifi
    fi

    if [ $force_reset_subdoc -le  2 ]; then
        if [ -f  $SW_UPGRADE_DEFAULT_FILE ]; then
            webcfg_rfc_enabled=`dmcli eRT getv Device.X_RDK_WebConfig.RfcEnable | grep "value" | cut -d ':' -f3-5`
            echo_t "webcfg_rfc status is $webcfg_rfc_enabled" >>  /rdklogs/logs/wifi_selfheal.txt
            dmcli eRT setv Device.X_RDK_WebConfig.webcfgSubdocForceReset string privatessid
            echo_t "Selfheal execution to force_reset on private vaps passed from WebConfig" >> /rdklogs/logs/wifi_selfheal.txt
            rm -f $SW_UPGRADE_DEFAULT_FILE
        fi
        ((force_reset_subdoc++))
    fi

    sleep 5m
    ((check_count++))
done
