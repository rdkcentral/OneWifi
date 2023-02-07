#!/bin/sh
source /etc/log_timestamp.sh
source /lib/rdk/t2Shared_api.sh
check_count=0
vap_2g_down=0
vap_5g_down=0
pre_timestamp=0
cur_timestamp=0

onewifi_restart_wifi()
{
        echo_t "private_vap is down self heal is executing" >>  /rdklogs/logs/wifi_selfheal.txt
        systemctl restart onewifi.service
        echo_t "private_vap self heal executed onewifi restarted" >>  /rdklogs/logs/wifi_selfheal.txt
}

private_vap_2g_restart()
{
        echo_t "private_2g is down self heal is executing" >>  /rdklogs/logs/wifi_selfheal.txt
        max_sta_2g=`dmcli eRT getv Device.WiFi.AccessPoint.1.X_CISCO_COM_BssMaxNumSta | grep "value:" | cut -f2- -d:| cut -f2- -d:`
        if [ $max_sta_2g == 75 ]; then
                dmcli eRT setv Device.WiFi.AccessPoint.1.X_CISCO_COM_BssMaxNumSta int 74
        else
                dmcli eRT setv Device.WiFi.AccessPoint.1.X_CISCO_COM_BssMaxNumSta int 75
        fi
        dmcli eRT setv Device.WiFi.ApplyAccessPointSettings bool true
        echo_t "private_2g self heal executed" >>  /rdklogs/logs/wifi_selfheal.txt
}

private_vap_5g_restart()
{
        echo_t "private_5g is down self heal is executing" >>  /rdklogs/logs/wifi_selfheal.txt
        max_sta_5g=`dmcli eRT getv Device.WiFi.AccessPoint.2.X_CISCO_COM_BssMaxNumSta | grep "value:" | cut -f2- -d:| cut -f2- -d:`
        if [ $max_sta_5g == 75 ]; then
                dmcli eRT setv Device.WiFi.AccessPoint.2.X_CISCO_COM_BssMaxNumSta int 74
        else
                dmcli eRT setv Device.WiFi.AccessPoint.2.X_CISCO_COM_BssMaxNumSta int 75
        fi
        dmcli eRT setv Device.WiFi.ApplyAccessPointSettings bool true
        echo_t "private_5g  self heal executed" >>  /rdklogs/logs/wifi_selfheal.txt
}

while true
 do
 if [ $check_count == 3 ]; then
        check_count=0
        cur_timestamp="`date +"%s"` $1"
        #echo_t "cur_timestamp = $cur_timestamp" >> /rdklogs/logs/wifi_selfheal.txt
        status_2g=`dmcli eRT getv Device.WiFi.AccessPoint.1.Enable | grep "value:" | cut -f2- -d:| cut -f2- -d:`
         if [ $status_2g == "true" ]; then
                ssid_2g=`wl -i wl0.1 status | grep  -m 1 "BSSID:" | cut -d ":" -f2-7 | awk '{print $1}'`
                if [ $ssid_2g ==  "00:00:00:00:00:00" ];then
                        if [ $vap_2g_down == 1 ]; then
                                time_diff=`expr $cur_timestamp - $pre_timestamp`
                                echo_t "time_diff = $time_diff" >> /rdklogs/logs/wifi_selfheal.txt
                                if [ $time_diff -ge 43200 ]; then
                                        onewifi_restart_wifi
                                        pre_timestamp="`date +"%s"` $1"
                                        vap_2g_down=0
                                        continue
                                else
                                        private_vap_2g_restart
                                fi
                        else
                                private_vap_2g_restart
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
                                echo_t "time_diff = $time_diff" >> /rdklogs/logs/wifi_selfheal.txt
                                if [ $time_diff -ge 43200 ]; then
                                        onewifi_restart_wifi
                                        pre_timestamp="`date +"%s"` $1"
                                        vap_5g_down=0
                                        continue
                                else
                                        private_vap_5g_restart
                                fi
                        else
                                private_vap_5g_restart
                                vap_5g_down=1
                        fi
                else
                        vap_5g_down=0
                fi
        fi
 fi
 sleep 5m
((check_count++))
done
