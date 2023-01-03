#!/bin/sh
source /etc/log_timestamp.sh
source /lib/rdk/t2Shared_api.sh
check_count=0
while true
 do
 if [ $check_count == 3 ]; then
        check_count=0
        status_2g=`dmcli eRT getv Device.WiFi.AccessPoint.1.Enable | grep "value:" | cut -f2- -d:| cut -f2- -d:`
         if [ $status_2g == "true" ]; then
                ssid_2g=`wl -i wl0.1 status | grep  -m 1 "BSSID:" | cut -d ":" -f2-7 | awk '{print $1}'`
                if [ $ssid_2g ==  "00:00:00:00:00:00" ];then
                        echo_t "private_2g is down self heal is executing" >>  /rdklogs/logs/wifi_selfheal.txt
                        max_sta_2g=`dmcli eRT getv Device.WiFi.AccessPoint.1.X_CISCO_COM_BssMaxNumSta | grep "value:" | cut -f2- -d:| cut -f2- -d:`
                        if [ $max_sta_2g == 75 ]; then
                                dmcli eRT setv Device.WiFi.AccessPoint.1.X_CISCO_COM_BssMaxNumSta int 74
                        else
                                dmcli eRT setv Device.WiFi.AccessPoint.1.X_CISCO_COM_BssMaxNumSta int 75
                        fi
                        dmcli eRT setv Device.WiFi.ApplyAccessPointSettings bool true
                        echo_t "private_2g self heal executed" >>  /rdklogs/logs/wifi_selfheal.txt
                fi
        fi
        status_5g=`dmcli eRT getv Device.WiFi.AccessPoint.2.Enable | grep "value:" | cut -f2- -d:| cut -f2- -d:`
         if [ $status_5g == "true" ]; then
                ssid_5g=`wl -i wl1.1 status | grep  -m 1 "BSSID:" | cut -d ":" -f2-7 | awk '{print $1}'`
                if [ $ssid_5g ==  "00:00:00:00:00:00" ];then
                        echo_t "private_5g is down self heal is executing" >>  /rdklogs/logs/wifi_selfheal.txt
                        max_sta_5g=`dmcli eRT getv Device.WiFi.AccessPoint.2.X_CISCO_COM_BssMaxNumSta | grep "value:" | cut -f2- -d:| cut -f2- -d:`
                        if [ $max_sta_5g == 75 ]; then
                                dmcli eRT setv Device.WiFi.AccessPoint.2.X_CISCO_COM_BssMaxNumSta int 74
                        else
                                dmcli eRT setv Device.WiFi.AccessPoint.2.X_CISCO_COM_BssMaxNumSta int 75
                        fi
                        dmcli eRT setv Device.WiFi.ApplyAccessPointSettings bool true
                        echo_t "private_5g  self heal executed" >>  /rdklogs/logs/wifi_selfheal.txt
                fi
        fi
 fi
 sleep 5m
((check_count++))
done

