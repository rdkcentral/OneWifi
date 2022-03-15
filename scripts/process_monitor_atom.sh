#! /bin/sh
######################################################################################
# If not stated otherwise in this file or this component's LICENSE file the
# following copyright and licenses apply:

#  Copyright 2018 RDK Management

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

# http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#######################################################################################

# wait for 7mins of uptime
uptime=$(cut -d. -f1 /proc/uptime)
if [ "$uptime" -lt 420 ]; then
    sleep $((420-uptime))
fi

echo "`date +'%Y-%m-%d:%H:%M:%S:%6N'` [RDKB_PLATFORM_INFO] Starting process_monitor_atom.sh on Atom CPU" >> /rdklogs/logs/AtomConsolelog.txt.0

. /etc/device.properties
touch /rdklogs/logs/authenticator_error_log.txt
touch /rdklogs/logs/ap_init.txt.0
BINPATH="/usr/bin"
TELNET_SCRIPT_PATH="/usr/ccsp"
RDKLOGGER_PATH="/rdklogger"
echo "Inside process monitor script"
loop=1
Subsys="eRT."	
check_dmesg=""
check_dmesg_wps_gpio_dump=""
check_dmesg_deauth=""
check_dmesg_NF_TIMEOUT=""
check_dmesg_TX_OVERFLOW=""
check_dmesg_CHSCAN_STUCK=""
check_dmesg_RATE=""
check_dmesg_duplicate_aid=""
check_dmesg_BEACONSTUCK=""
time=0
prev_apstats_iw2_tx_pkts=0
prev_apstats_iw2_rx_pkts=0
prev_apstats_iw5_tx_pkts=0
prev_apstats_iw5_rx_pkts=0
WIFI_RESTART=0
HOSTAPD_RESTART=0
AP_UP_COUNTER=0
FASTDOWN_COUNTER=0
LOOP_COUNTER=0
HOSTAPD_RESTART_COUNTER=0
rc=0
NTP_CONF="/tmp/ntp.conf"
newline="
"
MODEL_NUM=`grep MODEL_NUM /etc/device.properties | cut -d "=" -f2`
MESH_ENABLE=`syscfg get mesh_enable`
MESH_LOCK="/tmp/mesh.lock"
MESH_LOCKED_COUNT=0

incorrect_hostapd_config=0

prev_beacon_swba_intr=0
captiveportal_count=0

source /lib/rdk/t2Shared_api.sh

if [ -e /rdklogger/log_capture_path_atom.sh ]
then
	source /rdklogger/log_capture_path_atom.sh 
else
	echo_t()
	{
        	echo $1
	}
fi

restart_wifi()
{
	touch /tmp/process_monitor_restartwifi
	cd /usr/ccsp/wifi
	export LD_LIBRARY_PATH=$PWD:.:$PWD/../../lib:$PWD/../../.:/lib:/usr/lib:$LD_LIBRARY_PATH
	if [ -f /etc/ath/fast_down.sh ];then
		FASTDOWN_PID=`pidof fast_down.sh`
	else
		FASTDOWN_PID=`pidof apdown`
	fi
	APUP_PID=`pidof apup`
	if [ $FASTDOWN_COUNTER -eq 0 ] && [ "$APUP_PID" == "" ] && [ "$FASTDOWN_PID" == "" ]; then
		if [ -f /etc/ath/fast_down.sh ];then
			/etc/ath/fast_down.sh
			rc=$?
		else
			/etc/ath/apdown
		fi
		FASTDOWN_COUNTER=$(($FASTDOWN_COUNTER + 1))
	fi

	if [ "$rc" != "0" ]; then
		echo_t "fast_down did not succeed, will retry"
	else
		FASTDOWN_COUNTER=0
	fi
	if [ -f /etc/ath/fast_down.sh ];then
		FASTDOWN_PID=`pidof fast_down.sh`
	else
		FASTDOWN_PID=`pidof apdown`
	fi
	APUP_PID=`pidof apup`
	if [ "$APUP_PID" == "" ] && [ "$FASTDOWN_PID" == "" ] && [ $FASTDOWN_COUNTER -eq 0 ]; then
		$BINPATH/CcspWifiSsp -subsys $Subsys &
		sleep 60
	else
		echo_t "WiFiAgent_process restart was skipped, fastdown or apup in progress"
		FASTDOWN_COUNTER=0
	fi
	cd -
	rm /tmp/process_monitor_restartwifi
}

Zombie_check()
{
	zombie_count=0

	for file in /proc/*/stat
	do

	if [ -f $file ]; then
        	process_status=`cat $file | awk '{ print $3 }'`


        	if [ "$process_status" = "Z" ]; then
                	process_pid=`cat $file | awk '{ print $1 }'`
                	process_name=`cat $file | awk '{ print $2 }' | cut -d "(" -f2 | cut -d ")" -f1`
                	parent_id=`cat $file | awk '{ print $4 }'`
                	echo_t "zombie_pid:$process_pid, zombie_pname: $process_name, zombie_parent_pid:$parent_id"
        		zombie_count=$((zombie_count+1))
        	fi

	fi
	done
	echo_t "Total_Zombie_count:$zombie_count"
}

while [ $loop -eq 1 ]
do
	uptime=$(cut -d. -f1 /proc/uptime)
	sleep 300

captiveportel_OFF=`sysevent get CaptivePortalCheck`

if [ "$BOX_TYPE" = "XB3" ] && [ "$captiveportel_OFF" != "" ]; then
	echo_t " captive portal check is set to  $captiveportel_OFF" 

	if [ "$captiveportel_OFF" == "false" ] && [ $captiveportal_count -eq 0 ]; then
        	echo_t "captive portal settings are done from the UI , Making the moniter script to sleep to sleep 30 sec "
        	captiveportal_count=$((captiveportal_count+1))
        	sleep 30
	else
        	if [ $captiveportal_count -eq 0 ]; then
                	echo_t "captive portal settings are yet to be done"
                else
                	echo_t "captive portal settings are already done, skipping the sleep : captiveportal_count - $captiveportal_count "
			if [ "$captiveportel_OFF" == "true" ]; then
			echo_t "resetting the counter captiveportal_count to 0 due to wifi-reset "
                        	captiveportal_count=0
  			fi
                fi
	fi
fi 

interface=1
#Checking if ping to ARM is not failing
	while [ $interface -eq 1 ]
	do
	        if [ "$DEVICE_MODEL" = "TCHXB3" ]; then
        	        PING_RES=`ping -I eth0.500 -c 2 -w 10 $ARM_INTERFACE_IP`
                	CHECK_PING_RES=`echo $PING_RES | grep "packet loss" | cut -d"," -f3 | cut -d"%" -f1`
			if [ "$CHECK_PING_RES" = "" ]
			then
				check_if_eth0_500_up=`ifconfig eth0.500 | grep UP `
				check_if_eth0_500_ip=`ifconfig eth0.500 | grep inet `
				if [ "$check_if_eth0_500_up" = "" ] || [ "$check_if_eth0_500_ip" = "" ]
                        	then
                                	echo_t "[RDKB_PLATFORM_ERROR] : eth0.500 is not up, setting to recreate interface"
                                	rpc_ifconfig eth0.500 >/dev/null 2>&1
					sleep 3
                        	fi
                        	PING_RES=`ping -I eth0.500 -c 2 -w 10 $ARM_INTERFACE_IP`
                        	CHECK_PING_RES=`echo $PING_RES | grep "packet loss" | cut -d"," -f3 | cut -d"%" -f1`
                        	if [ "$CHECK_PING_RES" != "" ]
                        	then
                                	if [ "$CHECK_PING_RES" -ne 100 ]
                                	then
                                        	echo_t "[RDKB_PLATFORM_ERROR] : eth0.500 is up,Ping to Peer IP is success"
                                        	break
                                	fi
                               		echo_t "[RDKB_PLATFORM_ERROR] : ARM ping Interface is down"

				fi
			else
                        	if [ "$CHECK_PING_RES" -ne 100 ]
                        	then
                                	echo_t "RDKB_SELFHEAL : Ping to Peer IP from ATOM is success"
                                	break
                        	fi
                        	echo_t "[RDKB_PLATFORM_ERROR] : ARM ping Interface is down"

			fi
		fi
		interface=`expr $interface + 1`
	done
        
	Dropbear_Pid=`pidof dropbear`
	if [ "$Dropbear_Pid" = "" ]
	then
		if [ -f $TELNET_SCRIPT_PATH/dropbear-start ]
		then
		   echo_t "RDKB_PROCESS_CRASHED : dropbear is not running in ATOM, restarting dropbear"
		   $TELNET_SCRIPT_PATH/dropbear-start
		else
			echo_t "dropbear script not found"
		fi
	fi

 	if [ -f /lib/rdk/wifi_config_profile_check.sh ];then
		source /lib/rdk/wifi_config_profile_check.sh 
                rc=$?
                if [ "$rc" == "0" ]; then
			echo_t "[RDKB_SELFHEAL.WARNING] : WiFi config file is corrupted. Restoring from backup"
			source /etc/ath/apcfg wifi_config_check # add here to be safe even though apup will do the same later
			APUP_PID=`pidof apup`
 			if [ -f /etc/ath/fast_down.sh ];then
                		FASTDOWN_PID=`pidof fast_down.sh`
			else	
                		FASTDOWN_PID=`pidof apdown`
                	fi
			if [ "$APUP_PID" == "" ] && [ "$FASTDOWN_PID" == "" ]; then
                		echo_t "resetting radios"
				dmcli eRT setv Device.X_CISCO_COM_DeviceControl.RebootDevice string Wifi
                                continue
			fi
                fi
        fi
			
	isNativeHostapdDisabled=`psmcli get Device.DeviceInfo.X_RDKCENTRAL-COM_RFC.Control.DisableNativeHostapd` #RDKB-30035

	cd /usr/ccsp/wifi
	WiFi_PID=`pidof CcspWifiSsp`
	if [ "$WiFi_PID" == "" ]; then
		echo_t "WiFi process is not running, restarting it"
		echo_t "RDKB_PROCESS_CRASHED : WiFiAgent_process is not running, need restart"
		t2CountNotify "WIFI_SH_WIFIAGENT_Restart"
		restart_wifi
	else
	  radioenable=`dmcli eRT getv Device.WiFi.Radio.1.Enable`
	  radioenable_error=`echo $radioenable | grep "Execution fail"`
	  if [ "$radioenable_error" != "" ]; then
	    echo_t "wifi parameter timed out or failed"
		wifi_name_query=`dmcli eRT getv com.cisco.spvtg.ccsp.wifi.Name`
		wifi_name_error=`echo $wifi_name_query | grep "Execution fail"`
		if [ "$wifi_name_error" != "" ]; then
		  echo_t "WiFi process is not responding. Restarting it"
		  kill -9 $WiFi_PID
		  restart_wifi
		fi
	  else
        	WIFI_RESTART=0
                HOSTAPD_RESTART=0
		APUP_PID=`pidof apup`
 		if [ -f /etc/ath/fast_down.sh ];then
                	FASTDOWN_PID=`pidof fast_down.sh`
		else	
                	FASTDOWN_PID=`pidof apdown`
                fi

        if [ -f /tmp/cfg_list.txt ];then
           rm  /tmp/cfg_list.txt
        fi
        # quary the cfg list in text file
        cfg -s > /tmp/cfg_list.txt

        check_radio=`grep AP_RADIO_ENABLED /tmp/cfg_list.txt`
                if [ "$check_radio" != "" ]; then
			check_radio_enable5=`grep AP_RADIO_ENABLED:=1 /tmp/cfg_list.txt | cut -d"=" -f2`
            check_radio_enable2=`grep AP_RADIO_ENABLED_2:=1 /tmp/cfg_list.txt | cut -d"=" -f2`
		else
			check_radio_enable5=`grep RADIO_ENABLE_2:=1 /tmp/cfg_list.txt | cut -d"=" -f2`
            check_radio_enable2=`grep RADIO_ENABLE:=1 /tmp/cfg_list.txt | cut -d"=" -f2`
		fi
                check_radio_intf_up=`grep "PCI rescan's were met without successfull recovery, exiting apup" /rdklogs/logs/ap_init.txt.0`
		if [ "$check_radio" != "" ]; then
			radio5g=`lspci -mvk | grep 02:00.0`
			radio2g=`lspci -mvk | grep 03:00.0`
			if [ "$radio5g" == "" ] && [ "$radio2g" == "" ]; then
				echo_t "Both WiFi Radios missing"
			else
				if [ "$radio5g" == "" ] ;then
					echo_t "5G WiFi Radios missing"
				else
					if [ "$radio2g" == "" ];then
						echo_t "2G WiFi Radios missing"
					fi
                                fi

                                ath_pci_5=`echo $radio5g | grep ath_pci`
                                ath_pci_2=`echo $radio2g | grep ath_pci`
                                if [ "$ath_pci_5" == "" ] || [ "$ath_pci_2" == "" ]; then
                                      if [ "$ath_pci_5" == "" ]; then
                                            echo_t "ath_pci_5 missing"
                                      fi
                                      if [ "$ath_pci_2" == "" ]; then
                                            echo_t "ath_pci_2 missing"
                                      fi
				fi
			fi
		else
			radio2g=`lspci -mvk | grep 02:00.0`
			radio5g=`lspci -mvk | grep 03:00.0`
			if [ "$radio5g" == "" ] && [ "$radio2g" == "" ]; then
				echo_t "Both WiFi Radios missing"
			else 
				if [ "$radio5g" == "" ];then
				        echo_t "5G WiFi Radios missing"
				else
					if [ "$radio2g" == "" ];then
						echo_t "2G WiFi Radios missing"
					fi
                                fi

                                ath_pci_5=`echo $radio5g | grep ath_pci`
                                ath_pci_2=`echo $radio2g | grep ath_pci`
                                if [ "$ath_pci_5" == "" ] || [ "$ath_pci_2" == "" ]; then
                                      if [ "$ath_pci_5" == "" ]; then
                                            echo_t "ath_pci_5 missing"
                                      fi
                                      if [ "$ath_pci_2" == "" ]; then
                                            echo_t "ath_pci_2 missing"
                                      fi
                                fi
			fi
		fi

                if [ "$check_radio_enable5" == "1" ]
                then
                    getPciDetails5G=`lspci_pciutils -vvvs 02:00.0 | grep "Unknown header type"`
                    if [ "$getPciDetails5G" != "" ]
                    then
                       echo_t "5G_UNKNOWN_HEADER_TYPE_DETECTED"

                       if [ "$MODEL_NUM" == "TG1682G" ]; then
                           txSelfHeal=`dmcli eRT getv Device.WiFi.TxOverflowSelfheal | grep true`
                           if [ "$txSelfHeal" != "" ];then
                              echo_t "Starting Self Heal..."
                              echo_t "Turning WiFi Down"
                              dmcli eRT setv Device.WiFi.Status string Down
                              sleep 10
                              /usr/sbin/wps_gpio write 100 1
                              /usr/sbin/wps_gpio write 10 0
                              /usr/sbin/wps_gpio write 10 1
                              sleep 5
                              echo_t "Turning WiFi Up"
                              dmcli eRT setv Device.WiFi.Status string Up
                           fi
                       fi
                    else
			   check_interface_ath1=`dmcli eRT getv Device.WiFi.SSID.2.Enable | grep true`
                           if [ "$check_interface_ath1" != "" ]; then
	                      beacon_swba_intr=`apstats -v -i ath1 | grep "Total beacons sent to fw in SWBA intr" | awk '{print $10}'`
                              if [ "$beacon_swba_intr" == "$prev_beacon_swba_intr" ] && [ "$beacon_swba_intr" != "0" ]; then
                                 echo_t "5G_FW_UNRESPONSIVE"
                                 if [ "$MODEL_NUM" == "TG1682G" ] || [ "$MODEL_NUM" == "DPC3941" ] || [ "$MODEL_NUM" == "DPC3941B" ] || [ "$MODEL_NUM" == "DPC3939B" ]; then
                                    txSelfHeal=`dmcli eRT getv Device.WiFi.TxOverflowSelfheal | grep true`
                                    if [ "$txSelfHeal" != "" ];then
                                       echo_t "Starting Self Heal..."
                                       echo_t "Turning WiFi Down"
                                       dmcli eRT setv Device.WiFi.Status string Down
                                       sleep 10
                                       if [ "$MODEL_NUM" == "TG1682G" ]; then
                                                /usr/sbin/wps_gpio write 100 1
                                                /usr/sbin/wps_gpio write 10 0
                                                /usr/sbin/wps_gpio write 10 1
                                       fi
                                       if [ "$MODEL_NUM" == "DPC3941" ] || [ "$MODEL_NUM" == "DPC3941B" ] || [ "$MODEL_NUM" == "DPC3939B" ]; then
                                                wifi_pci_reset
                                       fi
                                       sleep 5
                                       echo_t "Turning WiFi Up"
                                       dmcli eRT setv Device.WiFi.Status string Up
                                    fi
                                 fi
                              fi
			      prev_beacon_swba_intr=$beacon_swba_intr
                           fi
                    fi
                fi

		if [ -e "/lib/rdk/platform_process_monitor.sh" ] && [ -e "/lib/rdk/platform_ap_monitor.sh" ] && [ "$DEVICE_MODEL" == "TCHXB3" ];then
			sh /lib/rdk/platform_process_monitor.sh 
			sh /lib/rdk/platform_ap_monitor.sh 
		fi
                
                if [ -f $MESH_LOCK ]; then
 		 MESH_LOCKED_COUNT=$(($MESH_LOCKED_COUNT + 1))
                 if [ $MESH_LOCKED_COUNT -gt 5 ]; then
                  MESH_LOCKED_COUNT=0
                 else
                  echo_t "Mesh is transitioning the Vaps, skipping wifi checks"
                 fi
                else
                 MESH_LOCKED_COUNT=0
                fi
#Check for bridge interface and ath interface for Xfinity Home and Lnf SSIDs
                for var in 3 4 11 12
                do
                    check_xh_enable=`grep AP_ENABLE_$var:= /tmp/cfg_list.txt | cut -d"=" -f2`
                    if [ "$check_xh_enable" == "1" ]; then
                        check_xh_vlan=`grep AP_VLAN_$var:= /tmp/cfg_list.txt | cut -d"=" -f2`
                        if [ "$check_xh_vlan" != "" ]; then
                            ath_if=`expr $var - 1`
                            check_device=`iwconfig ath$ath_if 2>&1 | grep ath$ath_if | cut -d " " -f6-`
                            if [ "$check_device" == "No such device" ]  || [ "$check_device" == " No such device" ]; then
                                echo_t "[RDKB-SELFHEAL] ath$ath_if interface is not created for SSID $var" >> /rdklogs/logs/SelfHeal.txt.0
                            else
                                check_essid=`iwconfig ath$ath_if 2>&1 | grep ESSID | cut -f2 -d\"`
                                if [ "$check_essid" != "" ]; then
                                    bridge_ifname=`grep AP_BRNAME_$var:= /tmp/cfg_list.txt | cut -d"=" -f2`
                                    check_br_interface=`brctl show $bridge_ifname 2>&1 | grep "eth0.$check_xh_vlan"`
                                    if [ "$check_br_interface" == "" ]; then
                                        echo_t "[RDKB-SELFHEAL] bridge interface $bridge_ifname with eth0.$check_xh_vlan not created for ath$ath_if interface" >> /rdklogs/logs/SelfHeal.txt.0
                                    fi
                                else
                                    echo_t "[RDKB-SELFHEAL] ESSID is not attached to ath$ath_if" >> /rdklogs/logs/SelfHeal.txt.0
                                fi
                            fi
                        fi
                    fi
                done

		if [ "$check_radio_enable5" == "1" ] || [ "$check_radio_enable2" == "1" ] && [ $MESH_LOCKED_COUNT -eq 0 ]; then
			if [ "$APUP_PID" == "" ] && [ "$FASTDOWN_PID" == "" ] && [ $FASTDOWN_COUNTER -eq 0 ]; then
                                AP_UP_COUNTER=0
				HOSTAPD_PID=`pidof hostapd`
				#RDKB-30035 MOD START
				if [ "$isNativeHostapdDisabled" != "1" ] && [ "$HOSTAPD_PID" == "" ] && [ $HOSTAPD_RESTART_COUNTER -lt 4 ]; then
				#RDKB-30035 MOD END
					WIFI_RESTART=1
                                        HOSTAPD_RESTART=1
                                        #CiscoXB3-4205- Check if hostapd config file exists and if it is empty, if empty recreate the hostapd config file
                                        conf=`cat /tmp/conf_filename`
                                        for file in $conf; do
                                         if [ -s $file ]; then
                                          echo "Config file $file is proper"
   					 else
                                          echo_t "Hostapd Config file $file is found empty, recreate it"
				          index=$(echo $file | sed 's/^.*ath//g' | sed 's/[^0-9]*//g')
 					  WPS=`wifi_api wifi_getApWpsEnable $index`
                                          wifi_api wifi_createHostApdConfig $index $WPS
   					  if [ ! -s $file ]; then
  					   echo_t "Hostapd config failed to recreate $file"
  					   wifi_api wifi_removeApSecVaribles $index
                                          fi
 					 fi
                                        done  
					echo_t "RDKB_PROCESS_NOT_RUNNING : Hostapd_process is not running, will Reset Radios, this will restart hostapd"
			       
				else
					HOSTAPD_RESTART_COUNTER=0
					check_ap_tkip_cfg=$(grep 'TKIP\\' /tmp/cfg_list.txt)
                			if [ "$check_ap_tkip_cfg" != "" ]; then                         
                        			echo_t "TKIP has backslash"
                                                continue      
                			fi  
					check_ap_enable5=`grep AP_ENABLE_2:=1 /tmp/cfg_list.txt | cut -d"=" -f2`
					check_interface_up5=`ifconfig | grep -v ath1[0-9] | grep ath1`
					check_ap_enable2=`grep AP_ENABLE:=1 /tmp/cfg_list.txt | cut -d"=" -f2`
					check_ap_enable_ath2=`grep AP_ENABLE_3:=1 /tmp/cfg_list.txt | cut -d"=" -f2`
					check_interface_up2=`ifconfig | grep ath0`
					check_interface_up_ath2=`ifconfig | grep ath2`
					check_interface_iw2=`iwconfig ath0 | grep Access | awk '{print $6}'`
					check_interface_iw5=`iwconfig ath1 | grep Access | awk '{print $6}'`
					check_interface_iw_ath2=`iwconfig ath2 | grep Access | awk '{print $6}'`
					check_hostapd_ath0=`grep ath0 /proc/$(pidof hostapd)/cmdline`
					check_hostapd_ath1=`grep -v ath1[0-9] /proc/$(pidof hostapd)/cmdline | grep ath1`
					check_wps_ath0=`grep WPS_ENABLE:=2 /tmp/cfg_list.txt`
					check_wps_ath1=`grep WPS_ENABLE_2:=2 /tmp/cfg_list.txt`
					check_ap_sec_mode_2=`grep AP_SECMODE:=WPA /tmp/cfg_list.txt`
					check_ap_sec_mode_5=`grep AP_SECMODE_2:=WPA /tmp/cfg_list.txt`
					if [ "$isNativeHostapdDisabled" != "1" ] && [ "$check_radio_enable2" == "1" ] && [ "$check_ap_enable2" == "1" ] && [ "$check_ap_sec_mode_2" != "" ] && [ "$check_hostapd_ath0" == "" ]; then
						echo_t "Hostapd incorrect config"
						incorrect_hostapd_config=1
					fi
					if [ "$isNativeHostapdDisabled" != "1" ] && [ "$check_radio_enable5" == "1" ] && [ "$check_ap_enable5" == "1" ] && [ "$check_ap_sec_mode_5" != "" ] && [ "$check_hostapd_ath1" == "" ]; then
						echo_t "Hostapd incorrect config"
						incorrect_hostapd_config=1
					fi
					

					if [ "$check_ap_enable2" == "1" ] && [ "$check_radio_enable2" == "1" ] && [ "$check_interface_iw2" == "Not-Associated" ]; then
						echo_t "ath0 is Not-Associated, flapping ath0 interface"
						ifconfig ath0 down
						ifconfig ath0 up
                                                check_interface_iw2=`iwconfig ath0 | grep Access | awk '{print $6}'`

						#RDKB-30035 MOD START
						if [ "$check_interface_iw2" == "Not-Associated" ] && [ "$(pidof apup)" == "" ] && [ "$(pidof fastdown)" == "" ] && [ "$(pidof apdown)" == "" ] && [[ "$isNativeHostapdDisabled" == "1" || "$(pidof hostapd)" != "" ]]; then
								echo_t "ath0 is Not-Associated, restarting radios"
								WIFI_RESTART=1
						fi
					fi

					if [ "$check_ap_enable5" == "1" ] && [ "$check_radio_enable5" == "1" ] && [ "$check_interface_iw5" == "Not-Associated" ]; then
						echo_t "ath1 is Not-Associated, flapping ath1 interface"
						ifconfig ath1 down
						ifconfig ath1 up
                                                check_interface_iw5=`iwconfig ath1 | grep Access | awk '{print $6}'`

						#RDKB-30035 START
						if [ "$check_interface_iw5" == "Not-Associated" ] && [ "$(pidof apup)" == "" ] && [ "$(pidof fastdown)" == "" ] && [ "$(pidof apdown)" == "" ] && [[ "$isNativeHostapdDisabled" == "1" || "$(pidof hostapd)" != "" ]]; then
						#RDKB-30035 END
								echo_t "ath1 is Not-Associated, restarting radios"
								WIFI_RESTART=1
						fi
					fi

					if [ "$check_ap_enable_ath2" == "1" ] && [ "$check_radio_enable2" == "1" ] && [ "$check_interface_iw_ath2" == "Not-Associated" ]; then
						echo_t "ath2 is Not-Associated, flapping ath2 interface"
						ifconfig ath2 down
						ifconfig ath2 up
                                                check_interface_iw_ath2=`iwconfig ath2 | grep Access | awk '{print $6}'`

						#RDKB-30035 START
						if [ "$check_interface_iw_ath2" == "Not-Associated" ] && [ "$(pidof apup)" == "" ] && [ "$(pidof fastdown)" == "" ] && [ "$(pidof apdown)" == "" ] && [[ "$isNativeHostapdDisabled" == "1" || "$(pidof hostapd)" != "" ]]; then
								echo_t "ath2 is Not-Associated, restarting radios"
								WIFI_RESTART=1
						fi
					fi


					if [ "$check_ap_enable5" == "1" ] && [ "$check_radio_enable5" == "1" ] && [ "$check_interface_up5" == "" ] && [ "$(pidof hostapd)" != "" ]; then
						check_interface_up5=`ifconfig | grep -v ath1[0-9] | grep ath1`

						#RDKB-30035 START
						if [ "$check_interface_up5" == "" ] && [ "$(pidof apup)" == "" ] && [ "$(pidof fastdown)" == "" ] && [ "$(pidof apdown)" == "" ] && [[ "$isNativeHostapdDisabled" == "1" || "$(pidof hostapd)" != "" ]]; then
							echo_t "ath1 is down, restarting radios"
							WIFI_RESTART=1
						fi
					fi
				
					if [ "$check_ap_enable2" == "1" ] && [ "$check_radio_enable2" == "1" ] && [ "$check_interface_up2" == "" ] && [ "$(pidof hostapd)" != "" ]; then
						check_interface_up2=`ifconfig | grep ath0`

						#RDKB-30035 START
						if [ "$check_interface_up2" == "" ] && [ "$(pidof apup)" == "" ] && [ "$(pidof fastdown)" == "" ] && [ "$(pidof apdown)" == "" ] && [[ "$isNativeHostapdDisabled" == "1" || "$(pidof hostapd)" != "" ]]; then
							echo_t "ath0 is down, restarting radios"
							WIFI_RESTART=1
						fi
					fi
					time=$(($time + 300))
                                        if [ $time -eq 600 ] || [  $time -eq 1200 ] || [  $time -eq 1800 ]; then
						if [ "$check_ap_enable2" == "1" ]; then

						check_apstats_iw2_p_req=`apstats -v -i ath0 | grep "Rx Probe request" | awk '{print $5}'`
						check_apstats_iw2_p_res=`apstats -v -i ath0 | grep "Tx Probe response" | awk '{print $5}'`
						check_apstats_iw2_au_req=`apstats -v -i ath0 | grep "Rx auth request" | awk '{print $5}'`
						check_apstats_iw2_au_resp=`apstats -v -i ath0 | grep "Tx auth response" | awk '{print $5}'`
						check_apstats_iw2_tx_pkts=`apstats -v -i ath0 | grep "Tx Data Packets" | awk '{print $5}'`
						check_apstats_iw2_tx_bytes=`apstats -v -i ath0 | grep "Tx Data Bytes" | awk '{print $5}'`
						check_apstats_iw2_rx_pkts=`apstats -v -i ath0 | grep "Rx Data Packets" | awk '{print $5}'`
						check_apstats_iw2_rx_bytes=`apstats -v -i ath0 | grep "Rx Data Bytes" | awk '{print $5}'`

						echo_t "2G_ProbeRequest:$check_apstats_iw2_p_req" >> /rdklogs/logs/wifihealth.txt
						echo_t "2G_ProbeResponse:$check_apstats_iw2_p_res" >> /rdklogs/logs/wifihealth.txt
						echo_t "2G_AuthRequest:$check_apstats_iw2_au_req" >> /rdklogs/logs/wifihealth.txt
						echo_t "2G_AuthResponse:$check_apstats_iw2_au_resp" >> /rdklogs/logs/wifihealth.txt
						echo_t "2G_TxPackets:$check_apstats_iw2_tx_pkts" >> /rdklogs/logs/wifihealth.txt
						t2ValNotify "2GTxPackets_split" "$check_apstats_iw2_tx_pkts"
                                                echo_t "2G_TxBytes:$check_apstats_iw2_tx_bytes" >> /rdklogs/logs/wifihealth.txt
						echo_t "2G_Tx_Packet_Delta:`expr $check_apstats_iw2_tx_pkts - $prev_apstats_iw2_tx_pkts`" >> /rdklogs/logs/wifihealth.txt
						prev_apstats_iw2_tx_pkts=$check_apstats_iw2_tx_pkts
						echo_t "2G_RxPackets:$check_apstats_iw2_rx_pkts" >> /rdklogs/logs/wifihealth.txt
                                                t2ValNotify "2GRxPackets_split" "$check_apstats_iw2_rx_pkts"
						echo_t "2G_RxBytes:$check_apstats_iw2_rx_bytes" >> /rdklogs/logs/wifihealth.txt
						echo_t "2G_Rx_Packet_Delta:`expr $check_apstats_iw2_rx_pkts - $prev_apstats_iw2_rx_pkts`" >> /rdklogs/logs/wifihealth.txt
						prev_apstats_iw2_rx_pkts=$check_apstats_iw2_rx_pkts

						iwpriv ath0 get_dl_fa_stats						 
						fi

						if [ "$check_ap_enable5" == "1" ]; then

						check_apstats_iw5_p_req=`apstats -v -i ath1 | grep "Rx Probe request" | awk '{print $5}'`
						check_apstats_iw5_p_res=`apstats -v -i ath1 | grep "Tx Probe response" | awk '{print $5}'`
						check_apstats_iw5_au_req=`apstats -v -i ath1 | grep "Rx auth request" | awk '{print $5}'`
						check_apstats_iw5_au_resp=`apstats -v -i ath1 | grep "Tx auth response" | awk '{print $5}'`
						check_apstats_iw5_tx_pkts=`apstats -v -i ath1 | grep "Tx Data Packets" | awk '{print $5}'`
						check_apstats_iw5_tx_bytes=`apstats -v -i ath1 | grep "Tx Data Bytes" | awk '{print $5}'`
						check_apstats_iw5_rx_pkts=`apstats -v -i ath1 | grep "Rx Data Packets" | awk '{print $5}'`
						check_apstats_iw5_rx_bytes=`apstats -v -i ath1 | grep "Rx Data Bytes" | awk '{print $5}'`

						echo_t "5G_ProbeRequest:$check_apstats_iw5_p_req" >> /rdklogs/logs/wifihealth.txt
						echo_t "5G_ProbeResponse:$check_apstats_iw5_p_res" >> /rdklogs/logs/wifihealth.txt
						echo_t "5G_AuthRequest:$check_apstats_iw5_au_req" >> /rdklogs/logs/wifihealth.txt
						echo_t "5G_AuthResponse:$check_apstats_iw5_au_resp" >> /rdklogs/logs/wifihealth.txt
						echo_t "5G_TxPackets:$check_apstats_iw5_tx_pkts" >> /rdklogs/logs/wifihealth.txt
						echo_t "5G_TxBytes:$check_apstats_iw5_tx_bytes" >> /rdklogs/logs/wifihealth.txt
						echo_t "5G_Tx_Packet_Delta:`expr $check_apstats_iw5_tx_pkts - $prev_apstats_iw5_tx_pkts`" >> /rdklogs/logs/wifihealth.txt
						prev_apstats_iw5_tx_pkts=$check_apstats_iw5_tx_pkts
						echo_t "5G_RxPackets:$check_apstats_iw5_rx_pkts" >> /rdklogs/logs/wifihealth.txt
						echo_t "5G_RxBytes:$check_apstats_iw5_rx_bytes" >> /rdklogs/logs/wifihealth.txt
						echo_t "5G_Rx_Packet_Delta:`expr $check_apstats_iw5_rx_pkts - $prev_apstats_iw5_rx_pkts`" >> /rdklogs/logs/wifihealth.txt
						prev_apstats_iw5_rx_pkts=$check_apstats_iw5_rx_pkts

						iwpriv ath1 get_dl_fa_stats
						fi
						vap_activity=`dmesg | grep VAP_ACTIVITY_ath0 | tail -1`
						if [ "$vap_activity" != "" ] ; then
						    echo_t "WIFI_PS_CLIENTS_1:`echo $vap_activity | cut -d"," -f2 `"  >> /rdklogs/logs/wifihealth.txt
						    echo_t "WIFI_PS_CLIENTS_DATA_QUEUE_LEN_1:`echo $vap_activity | cut -d"," -f3`"  >> /rdklogs/logs/wifihealth.txt
						    echo_t "WIFI_PS_CLIENTS_DATA_QUEUE_BYTES_1:`echo $vap_activity | cut -d"," -f4`"  >> /rdklogs/logs/wifihealth.txt
						    echo_t "WIFI_PS_CLIENTS_DATA_FRAME_LEN_1:`echo $vap_activity | cut -d"," -f5`"  >> /rdklogs/logs/wifihealth.txt
						    echo_t "WIFI_PS_CLIENTS_DATA_FRAME_COUNT_1:`echo $vap_activity | cut -d"," -f6`"  >> /rdklogs/logs/wifihealth.txt
						fi

						vap_activity=`dmesg | grep VAP_ACTIVITY_ath1 | tail -1`
						if [ "$vap_activity" != "" ] ; then
						    echo_t "WIFI_PS_CLIENTS_2:`echo $vap_activity | cut -d"," -f2 `"  >> /rdklogs/logs/wifihealth.txt
						    echo_t "WIFI_PS_CLIENTS_DATA_QUEUE_LEN_2:`echo $vap_activity | cut -d"," -f3`"  >> /rdklogs/logs/wifihealth.txt
						    echo_t "WIFI_PS_CLIENTS_DATA_QUEUE_BYTES_2:`echo $vap_activity | cut -d"," -f4`"  >> /rdklogs/logs/wifihealth.txt
						    echo_t "WIFI_PS_CLIENTS_DATA_FRAME_LEN_2:`echo $vap_activity | cut -d"," -f5`"  >> /rdklogs/logs/wifihealth.txt
						    echo_t "WIFI_PS_CLIENTS_DATA_FRAME_COUNT_2:`echo $vap_activity | cut -d"," -f6`"  >> /rdklogs/logs/wifihealth.txt
						fi
						tmp=`dmesg | grep "NF Timeout AR_PHY_AGC_CONTROL"`
						if [ "$tmp" == "$check_dmesg_NF_TIMEOUT" ]; then 
							check_dmesg_NF_TIMEOUT=""
						else
							check_dmesg_NF_TIMEOUT="$tmp"
						fi
						if [ "$check_dmesg_NF_TIMEOUT" != "" ]; then
							echo_t "NF Calibration issue occurred"
						fi
						check_dmesg_NF_TIMEOUT="$tmp"
						tmp=`dmesg | grep "TX OVERFLOW"`
						if [ "$tmp" == "$check_dmesg_TX_OVERFLOW" ]; then 
							check_dmesg_TX_OVERFLOW=""
						else
							check_dmesg_TX_OVERFLOW="$tmp"
						fi
						if [ "$check_dmesg_TX_OVERFLOW" != "" ]; then
							echo_t "TX OVERFLOW issue occurred"
						fi
						check_dmesg_TX_OVERFLOW="$tmp"
						tmp=`dmesg | grep "Already waiting for utilization"`
						if [ "$tmp" == "$check_dmesg_CHSCAN_STUCK" ]; then 
							check_dmesg_CHSCAN_STUCK=""
						else
							check_dmesg_CHSCAN_STUCK="$tmp"
						fi
						if [ "$check_dmesg_CHSCAN_STUCK" != "" ]; then
							echo_t "ACS stuck issue occurred"
						fi
						check_dmesg_CHSCAN_STUCK="$tmp"
						tmp=`dmesg | grep "WAL_DBGID_TX_AC_BUFFER_SET ( 0xdead"`
						if [ "$tmp" == "$check_dmesg_RATE" ]; then 
							check_dmesg_RATE=""
						else
							check_dmesg_RATE="$tmp"
						fi
						if [ "$check_dmesg_RATE" != "" ]; then
							echo_t "Rate Adaptation failure seen"
						fi
						check_dmesg_RATE="$tmp"
						tmp=`dmesg | grep "having same AID"`
						if [ "$tmp" == "$check_dmesg_duplicate_aid" ]; then 
							check_dmesg_duplicate_aid=""
						else
							check_dmesg_duplicate_aid="$tmp"
						fi
						if [ "$check_dmesg_duplicate_aid" != "" ]; then
							echo_t "Duplicate AID issue seen"
						fi
						check_dmesg_duplicate_aid="$tmp"
                                                wlanconfig ath0 list sta | grep -v "AID" > /tmp/aid
						awk 'x[$2]++ == 1 { print  "WLAN_CONFIG_AID_2G is duplicated"}' /tmp/aid >> /rdklogs/logs/AtomConsolelog.txt.0
                                                wlanconfig ath1 list sta | grep -v "AID" > /tmp/aid
						awk 'x[$2]++ == 1 { print  "WLAN_CONFIG_AID_5G is duplicated"}' /tmp/aid >> /rdklogs/logs/AtomConsolelog.txt.0

                                                tmp=`dmesg | grep "ath_bstuck_tasklet: stuck beacon"`
                                                if [ "$tmp" == "$check_dmesg_BEACONSTUCK" ]; then
                                                        check_dmesg_BEACONSTUCK=""
                                                else
                                                        check_dmesg_BEACONSTUCK="$tmp"
                                                fi
                                                if [ "$check_dmesg_BEACONSTUCK" != "" ]; then
                                                        echo_t "Beacon stuck failure seen"
                                                fi
                                                check_dmesg_BEACONSTUCK="$tmp"

                    fi
					if [ $time -eq 1800 ]; then
						time=0

                        check_lspci_2g_pcie=`lspci | grep "03:00.0 Class 0200: 168c:abcd"` 
                        check_target_asserted=`dmesg | grep "TARGET ASSERTED"` 

						tmp=`dmesg | grep "resetting hardware for Rx stuck"`
                                                tmp_dmesg_dump=`dmesg | grep "wps_gpio Tainted"`
						if [ "$tmp" == "$check_dmesg" ]; then 
							check_dmesg=""
						else
							check_dmesg="$tmp"
						fi
						if [ "$check_dmesg" != "" ]; then
							echo_t "Resetting WiFi hardware for Rx stuck"
						fi
						check_dmesg="$tmp"

						if [ "$tmp_dmesg_dump" == "$check_dmesg_wps_gpio_dump" ]; then 
							check_dmesg_wps_gpio_dump=""
						else
							check_dmesg_wps_gpio_dump="$tmp_dmesg_dump"
						fi
						if [ "$check_dmesg_wps_gpio_dump" != "" ]; then
							echo_t "ATOM_WIFI_KERNEL_MODULE_DUMP : wps_gpio related kernel_dump seen"
						fi
                                                check_dmesg_wps_gpio_dump="$tmp_dmesg_dump"
						if [ "$check_lspci_2g_pcie" != "" ]; then
							echo_t "PCIE device_class of 2G radio has abcd in it"
						fi
						if [ "$check_target_asserted" != "" ]; then
							echo_t "TARGET_ASSERTED"
                                                      
						fi
						if [ "$check_radio_intf_up" != "" ]; then
							echo_t "RADIO_NOT_UP"
                                                       
						fi
						if [ "$check_target_asserted" != "" ] || [ "$check_radio_intf_up" != "" ]; then
							echo_t "skipping hostapd restart"
							continue
						fi
					fi
					
				fi
			else
				AP_UP_COUNTER=$(($AP_UP_COUNTER + 1))
				echo_t "APUP is running"
				if [ $AP_UP_COUNTER -eq 3 ]; then
					echo_t "APUP stuck"
					# extra precaution to force module removal in extreme case of apup stuck permanently, apdown does not force removal
					#module dependencies have been taken care of and being removed in correct order
					# wifi will restart cleanly
					# when actual root cause is fixed this block will not execute
                                        touch /tmp/process_monitor_restartwifi
                                        killall hostapd
                                        sleep 1
                                        WiFi_PID=`pidof CcspWifiSsp`
                                        kill -9 $WiFi_PID
                                        sleep 1
                                        killall lbd
                                        sleep 1
                                        killall radstat
					sleep 1
                                        rmmod -f ath_pktlog
                                        sleep 1
                                        rmmod -f umac
                                        sleep 1
                                        rmmod -f hst_tx99
                                         sleep 1
					rmmod -f ath_dfs
                                        sleep 1
                                        rmmod -f ath_dev  
                                        sleep 1   
					rmmod -f ath_spectral
                                        sleep 1
					rmmod -f ath_rate_atheros  
                                        sleep 1
					rmmod -f ath_hal
                                        sleep 1
					rmmod -f asf 
                                        sleep 1   
					rmmod -f adf
                                        sleep 1
                                        WiFi_PID=`pidof CcspWifiSsp`
                                        kill -9 $WiFi_PID
                                        #kill -9 $HOSTAPD_PID
                                        AP_UP_COUNTER=0
                                        FASTDOWN_COUNTER=0
					kill -9 $APUP_PID
                                        restart_wifi
					#WIFI_RESTART=1
				fi
			fi

			if [ "$WIFI_RESTART" == "1" ]; then

				sleep 60
				check_ap_enable5=`grep AP_ENABLE_2:=1 /tmp/cfg_list.txt | cut -d"=" -f2`
				check_ap_enable2=`grep AP_ENABLE:=1 /tmp/cfg_list.txt | cut -d"=" -f2`
				check_radio=`grep AP_RADIO_ENABLED /tmp/cfg_list.txt`
				if [ "$check_radio" != "" ]; then
					check_radio_enable5=`grep AP_RADIO_ENABLED:=1 /tmp/cfg_list.txt| cut -d"=" -f2`
					check_radio_enable2=`grep AP_RADIO_ENABLED_2:=1 /tmp/cfg_list.txt| cut -d"=" -f2`
				 else
					check_radio_enable5=`grep RADIO_ENABLE_2:=1 /tmp/cfg_list.txt | cut -d"=" -f2`
					check_radio_enable2=`grep RADIO_ENABLE:=1 /tmp/cfg_list.txt | cut -d"=" -f2`

				fi
				is_at_least_one_radio_up=0
				if [ "$check_radio_enable2" == "1" ] || [ "$check_radio_enable5" == "1" ]; then
					is_at_least_one_radio_up=1
				fi
				echo "is_at_least_one_radio_up=$is_at_least_one_radio_up"
                                LOOP_COUNTER=0
				while [ $LOOP_COUNTER -lt 3 ] ; do
					if [ "$is_at_least_one_radio_up" == "1" ] && [ $uptime -gt 600 ] && [ "$(pidof apup)" == "" ] && [ "$(pidof fastdown)" == "" ] && [ "$(pidof apdown)" == "" ]  && [ "$(pidof aphealth_log.sh)" == "" ]; then
						#RDKB-30035 START
						if [ "$isNativeHostapdDisabled" == "1" ]; then
							break
						fi
						#RDKB-30035 END
						if [ "$(pidof hostapd)" != "" ] && [ "$HOSTAPD_RESTART" == "1" ]; then
                                                	break
						fi
						echo_t "resetting radios"
						dmcli eRT setv Device.X_CISCO_COM_DeviceControl.RebootDevice string Wifi
						HOSTAPD_RESTART_COUNTER=$(($HOSTAPD_RESTART_COUNTER + 1))
                                                sleep 120
                                                break
					else
						echo_t "eligibility check before resetting radios failed"
                                                LOOP_COUNTER=$(($LOOP_COUNTER + 1))
						sleep 60
					fi
				done
				#RDKB-30035 START
				if [ "$isNativeHostapdDisabled" != "1" ] && [ "$(pidof hostapd)" == "" ] && [ "$(pidof apup)" == "" ] && [ "$(pidof fastdown)" == "" ] && [ "$(pidof apdown)" == "" ]; then
                                	ifconfig ath0 up
					ifconfig ath1 up
					HOSTAPD_RESTART_COUNTER=$(($HOSTAPD_RESTART_COUNTER + 1))
                                        if [ "`syscfg get mesh_ovs_enable`" == "true" ]; then ifconfig eth_udma0 down; fi
					killall hostapd; rm /var/run/hostapd/*; sleep 2; hostapd `cat /tmp/conf_filename` -e /tmp/entropy -P /tmp/hostapd.pid 2>&1
					if [ "`syscfg get mesh_ovs_enable`" == "true" ]; then ifconfig eth_udma0 up; fi
				fi
			fi
                        if [ "$incorrect_hostapd_config" == "1" ] && [ "$isNativeHostapdDisabled" != "1" ]; then
                                echo_t "Restarting hostapd"
                                wifi_api wifi_restartHostApd
                                incorrect_hostapd_config=0
                        fi

		fi
	  fi
	fi

	cd /usr/ccsp/webpa
	Webpa_PID=`pidof webpa`
	if [ "$Webpa_PID" == "" ]; then
		echo_t "WebPA_process is not running, restarting it "
		t2CountNotify "SYS_SH_WebPA_restart"
		if [ -f /usr/bin/webpa ];then
			/usr/bin/webpa &
		fi
	fi

        cd /usr/ccsp/harvester
        Harvester_PID=`pidof harvester`
        cosa_start_PID=`pidof cosa_start.sh`
        if [ "$Harvester_PID" == "" ] && [ "$cosa_start_PID" == "" ]; then
                echo_t "Harvester process is not running, restarting it"
                $BINPATH/harvester &
        fi

       if [ "$BOX_TYPE" = "XB3" ] && [ -f "/etc/webgui_atom.sh" ]
       then
          Lighttpd_PID=`pidof lighttpd`
          if [ "$Lighttpd_PID" = "" ]
          then
          	isPortKilled=`netstat -anp | awk '/:21515 */ {split($NF,a,"/"); print a[2],a[1]}' | cut -f2 -d" "`
		if [ "$isPortKilled" != "" ]
		    then
			 Process_PID=`netstat -anp | awk '/:21515 */ {split($NF,a,"/"); print a[2],a[1]}'`
		         echo_t "Port 21515 is still alive. Killing processes $Process_PID"
		         kill -9 $isPortKilled
		 fi         	
             echo_t "RDKB_PROCESS_CRASHED : Lighttpd is not running in ATOM, restarting lighttpd"
             sh /etc/webgui_atom.sh &
          fi
       fi
   
       if [ -f $TELNET_SCRIPT_PATH/arping_to_host ]
       then
           $TELNET_SCRIPT_PATH/arping_to_host
       else
           echo_t "arping_to_host not found"
       fi
	
	#Checking the ntpd is running or not in ATOM
	NTPD_PID=`pidof ntpd`
	if [ "$NTPD_PID" = "" ] && [ $uptime -gt 900 ]; then
			echo_t "RDKB_PROCESS_CRASHED : NTPD is not running in ATOM, restarting NTPD"
			systemctl restart ntpc.service
			#ntpd -p $ARM_INTERFACE_IP
	fi

        
#MESH-492 Checking if Mesh bridges br12/br13 has a valid IP for XB3 devices
	if [ "$MESH_ENABLE" == "true" ]; then
 	 if [ "$MODEL_NUM" == "DPC3941" ] || [ "$MODEL_NUM" == "TG1682G" ] || [ "$MODEL_NUM" == "DPC3939" ] || [ "$MODEL_NUM" == "TG1682" ]; then

                #Check for Vaps present, else create it
                meshap="12 13"
                need_apup=false
                for index in $meshap
                do
                 vap_exist=`ip a show ath$index up`
                 if [ $? -eq 0 ]; then
                  echo "ath$index is present"
                 else
                  echo "ath$index not present"
                  dmcli eRT setv Device.WiFi.SSID.`expr "$index" + 1`.Enable bool true
                  need_apup=true
                 fi
                done
                if $need_apup ; then
                 echo "Performing a wifi init for bringing mesh Vaps"
                 wifi_api wifi_init
                else
                 echo "all good with mesh vaps"
                fi

        	MESHBR24_IP=`ifconfig br12 | grep 'inet addr' | cut -d: -f2 | awk '{print $1}'`
                MESHBR50_IP=`ifconfig br13 | grep 'inet addr' | cut -d: -f2 | awk '{print $1}'`
                if [ "$MESHBR24_IP" != "169.254.0.1" ] || [ "$MESHBR50_IP" != "169.254.1.1" ]; then
			echo_t "[RDKB_PLATFORM_ERROR] : Mesh Bridges lost IP addresses, Setting the mesh IPs now"
                	sh /usr/ccsp/wifi/mesh_setip.sh
                else
                	echo_t "RDKB_SELFHEAL : Mesh Bridges have valid IPs"
		fi
	 fi
        fi
#Checking if rpcserver is running
	RPCSERVER_PID=`pidof rpcserver`
	if [ "$RPCSERVER_PID" = "" ] && [ -f /usr/bin/rpcserver ]; then
			echo_t "RDKB_PROCESS_CRASHED : RPCSERVER is not running on ATOM, restarting "
			/usr/bin/rpcserver &
	fi
#checking the for number of Zombie process and listing them
	Zombie_check

    	#Checking D process running or not
    	check_D_process=`ps -w | grep " DW " | grep -v grep`
	if [ "$check_D_process" = "" ]; then
		echo_t "[RDKB_SELFHEAL] : There is no D process running in this device"
	else
		Running_D_Process=$(echo $check_D_process | awk '{ printf "%10s\n", $5 }' | sed 'H;1h;$!d;x;y/\n/ /' | sed 's/ * /,/g')
		echo_t "[RDKB_SELFHEAL] : D process is running in this device,$Running_D_Process"
	fi
done
