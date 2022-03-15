#!/bin/sh
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
#This script is used to log parameters for each radio

LOG_FOLDER="/rdklogs/logs"
WiFi_Health_LogFile="$LOG_FOLDER/wifihealth.txt"
source /etc/log_timestamp.sh
if [ -f /etc/device.properties ];then
source /etc/device.properties
fi

source /lib/rdk/t2Shared_api.sh

exec 3>&1 4>&2 >>$WiFi_Health_LogFile 2>&1

if [ -f /tmp/process_monitor_restartwifi ]; then
	echo_t "process monitor restart_wifi is in progress, exiting radiohealth.sh"
	exit 0;
fi

logfolder="/tmp/wifihealth"
INDEX_LIST="0 2 4 6 8 10 12 14"
Interfaces_Active=""

if [ ! -d "$logfolder" ] ; then
	mkdir "$logfolder";
fi

#TCCBR-4090 - Adding markers for chipset failures
if [ "x$BOX_TYPE" == "xTCCBR" ] || [ "x$BOX_TYPE" == "xXF3" ]; then
#print status of wifi adapter, it will return either up,down
#or "adaptor not found in case of issue"
	wl -i wl0 bss > /tmp/wifihealth/tmp_output 2>&1
	if [ $? -ne 0 ]; then
		WL0_STATUS=`cat /tmp/wifihealth/tmp_output | cut -f2 -d":" | awk '{$1=$1};1'`
	else
		WL0_STATUS=`cat /tmp/wifihealth/tmp_output`
	fi
	wl -i wl1 bss > /tmp/wifihealth/tmp_output 2>&1
	if [ $? -ne 0 ]; then
		WL1_STATUS=`cat /tmp/wifihealth/tmp_output | cut -f2 -d":" | awk '{$1=$1};1'`
	else
		WL1_STATUS=`cat /tmp/wifihealth/tmp_output`
	fi
	echo_t "WIFI_WL0_STATUS: $WL0_STATUS"
	echo_t "WIFI_WL1_STATUS: $WL1_STATUS"
	if [ "$WL0_STATUS" == "wl driver adapter not found" ]; then
		t2CountNotify "WIFI_ERROR_WL0_NotFound"
	fi

	if [ "$WL1_STATUS" == "wl driver adapter not found" ]; then
                t2CountNotify "WIFI_ERROR_WL1_NotFound"
        fi

#In case of corrupted nvram, SSID goes NULL
	wl -i wl0 ssid > /tmp/wifihealth/tmp_output 2>&1
	if [ $? -eq 0 ]; then
		WL0_SSID=`cat /tmp/wifihealth/tmp_output | grep "Current SSID:"  | awk -F 'Current SSID:' '{print $2}'`
		if [ "$WL0_STATUS" == "up" ] && [ "${#WL0_SSID}" -eq 2 ]; then
			echo_t "WIFI_ERROR: WL0 SSID is empty"
			t2CountNotify "WIFI_ERROR_WL0_SSIDEmpty"
		fi
	fi
	wl -i wl1 ssid > /tmp/wifihealth/tmp_output 2>&1
	if [ $? -eq 0 ]; then
		WL1_SSID=`cat /tmp/wifihealth/tmp_output | grep "Current SSID:"  | awk -F 'Current SSID:' '{print $2}'`
		if [ "$WL1_STATUS" == "up" ] && [ "${#WL1_SSID}" -eq 2 ]; then
			echo_t "WIFI_ERROR: WL1 SSID is empty"
			t2CountNotify "WIFI_ERROR_WL1_SSIDEmpty"
		fi
	fi
#In nvram corrupted case,Field observed size is less between
# 4k to 14k.in normal case sie is around 26k, so checking
#currently boundary as 14k.
#Evn with boundary in some cases, size looks fine but still
#corrupted so adding some default parameters check
#if any one of the above conditon fails, say nvram corrupted
	if [ -f /data/nvram ];then	
		IS_NVRM_CORRUPT=-1
		WL1_DFLT_PARAM_LIST="ecbd_enable wl1_acs_boot_only wl1_corerev wl1_country_code wl1_country_rev"
		WL0_DFLT_PARAM_LIST="wl0_acs_boot_only wl0_corerev wl0_country_code wl0_country_rev"
                CHK_PARAM_LIST="$WL0_DFLT_PARAM_LIST $WL1_DFLT_PARAM_LIST"
		for param in $CHK_PARAM_LIST
		do
			VAL=`nvram get $param`
			if [ "x$VAL" == "x" ];then
				echo_t "WIFI_ERROR: Unable to get value for parameter $param"
				IS_NVRM_CORRUPT=1;
				break
			fi 
			
		done
		NVRM_SIZE=`du -c /data/nvram | tail -1 | awk '{print $1}'`
		if [ $NVRM_SIZE -le 14 ] || [ "$IS_NVRM_CORRUPT" -eq 1 ];then
			echo_t "WIFI_ERROR: Nvram File corrupted"
                        t2CountNotify "WIFI_ERROR_NvramCorrupt"
		fi
	fi		
# In some cases, we are seeing status as Not associated and also
#in some cases, even it shows associated BSSID is empty
	wl -i wl0 status > /tmp/wifihealth/tmp_output 2>&1
        if [ $? -eq 0 ]; then
                WL0_ASSOC_STATUS=`cat /tmp/wifihealth/tmp_output | grep "Not associated"`
                if [ "x$WL0_ASSOC_STATUS" != "x" ]; then
                        echo_t "WIFI_ERROR: WL0 SSID not Associated"
                else
			WL0_BSSID_EMPTY=`cat /tmp/wifihealth/tmp_output | grep "BSSID: 00:00:00:00:00:00"`
			if [ "x$WL0_BSSID_EMPTY" != "x" ]; then
				echo_t "WIFI_ERROR: WL0 BSSID is empty"
			fi
		fi
        fi
	wl -i wl1 status > /tmp/wifihealth/tmp_output 2>&1
        if [ $? -eq 0 ]; then
                WL1_ASSOC_STATUS=`cat /tmp/wifihealth/tmp_output | grep "Not associated"`
                if  [ "x$WL1_ASSOC_STATUS" != "x" ]; then
                        echo_t "WIFI_ERROR: WL1 SSID not Associated"
                else
			WL1_BSSID_EMPTY=`cat /tmp/wifihealth/tmp_output | grep "BSSID: 00:00:00:00:00:00"`
			if [ "x$WL1_BSSID_EMPTY" != "x" ]; then
				echo_t "WIFI_ERROR: WL1 BSSID is empty"
			fi
		fi
        fi
	
#log fab id and ver every hour
	current_time=$(date +%s)
	if [ ! -f /tmp/curfabidloggedtime ];then
		last_loggedtime=0
	else
		last_loggedtime=`cat /tmp/curfabidloggedtime`
	fi
	difference_time=$(( current_time - last_loggedtime ))
	if [ $difference_time -ge 3600 ];then
		wl -i wl0 ver > /tmp/wifihealth/tmp_output 2>&1
                if [ $? -ne 0 ]; then
                        WL0_VER=`cat /tmp/wifihealth/tmp_output | cut -f2 -d":" | awk '{$1=$1};1'`
		else
			WL0_VER=`cat /tmp/wifihealth/tmp_output | tail -1 | tr -s [:space:] ' ' | cut -f7 -d" "`
                fi

                echo_t "WIFI_WL0_VER: $WL0_VER"
                wl -i wl1 ver > /tmp/wifihealth/tmp_output 2>&1
                if [ $? -ne 0 ]; then
                        WL1_VER=`cat /tmp/wifihealth/tmp_output | cut -f2 -d":" | awk '{$1=$1};1'`
		else
			WL1_VER=`cat /tmp/wifihealth/tmp_output | tail -1 | tr -s [:space:] ' ' | cut -f7 -d" "`
                fi
                echo_t "WIFI_WL1_VER: $WL1_VER"
                wl -i wl0 fabid > /tmp/wifihealth/tmp_output 2>&1
                if [ $? -ne 0 ]; then
                        WL0_FABID=`cat /tmp/wifihealth/tmp_output | cut -f2 -d":" | awk '{$1=$1};1'`
		else
			WL0_FABID=`cat /tmp/wifihealth/tmp_output`
                fi      
                echo_t "WIFI_WL0_FABID: $WL0_FABID"
                wl -i wl1 fabid > /tmp/wifihealth/tmp_output 2>&1
                if [ $? -ne 0 ]; then
                        WL1_FABID=`cat /tmp/wifihealth/tmp_output | cut -f2 -d":" | awk '{$1=$1};1'`
		else
			WL1_FABID=`cat /tmp/wifihealth/tmp_output`
                fi
                echo_t "WIFI_WL1_FABID: $WL1_FABID"
		echo $current_time > /tmp/curfabidloggedtime
	fi
		
fi
THRESHOLD_REACHED_2G=0
THRESHOLD_REACHED_5G=0
RADIO_UTIL_2G=`wifi_api wifi_getRadioBandUtilization 0`
RADIO_UTIL_5G=`wifi_api wifi_getRadioBandUtilization 1`
AutoChannelEnable_5G=""
AutoChannelEnable_5G=""

CHANNEL_THREASHOLD_2G=`psmcli get eRT.com.cisco.spvtg.ccsp.Device.WiFi.Radio.1.SetChanUtilThreshold`
if [ "$CHANNEL_THREASHOLD_2G" == "" ] ; then
	CHANNEL_THREASHOLD_2G=90;
fi

CHANNEL_THREASHOLD_5G=`psmcli get eRT.com.cisco.spvtg.ccsp.Device.WiFi.Radio.2.SetChanUtilThreshold`
if [ "$CHANNEL_THREASHOLD_5G" == "" ] ; then
	CHANNEL_THREASHOLD_5G=90;
fi

#short term workaround before wifi_api avaliabel
#bu1=`rdk_band_steering_hal wifi_getRadioBandUtilization 0 | grep ":" | cut -d":" -f2 | tr -d " %"`
#bu2=`rdk_band_steering_hal wifi_getRadioBandUtilization 1 | grep ":" | cut -d":" -f2 | tr -d " %"`

if [ "$RADIO_UTIL_2G" == "" ] ; then
	RADIO_UTIL_2G=0;
fi
if [ "$RADIO_UTIL_5G" == "" ] ; then
        RADIO_UTIL_5G=0;
fi

if [ "$RADIO_UTIL_2G" -ge "$CHANNEL_THREASHOLD_2G" ];then
	THRESHOLD_REACHED_2G=1
	sleep 60;
	RADIO_UTIL_2G=`wifi_api wifi_getRadioBandUtilization 0`
	echo_t "WIFI_BANDUTILIZATION_1_ITER1:$RADIO_UTIL_2G"
	if [ "$RADIO_UTIL_2G" -lt "$CHANNEL_THREASHOLD_2G" ];then
		THRESHOLD_REACHED_2G=0
	fi
	sleep 120
	RADIO_UTIL_2G=`wifi_api wifi_getRadioBandUtilization 0`
	echo_t "WIFI_BANDUTILIZATION_1_ITER2:$RADIO_UTIL_2G"
	if [ "$RADIO_UTIL_2G" -lt "$CHANNEL_THREASHOLD_2G" ];then
		THRESHOLD_REACHED_2G=0
	fi

fi

if [ "$RADIO_UTIL_5G" -ge "$CHANNEL_THREASHOLD_5G" ];then
	THRESHOLD_REACHED_5G=1
	sleep 60;
	RADIO_UTIL_5G=`wifi_api wifi_getRadioBandUtilization 1`
	echo_t "WIFI_BANDUTILIZATION_2_ITER1:$RADIO_UTIL_5G"
	if [ "$RADIO_UTIL_5G" -lt "$CHANNEL_THREASHOLD_5G" ];then
		THRESHOLD_REACHED_5G=0
	fi
	sleep 120
	RADIO_UTIL_5G=`wifi_api wifi_getRadioBandUtilization 1`
	echo_t "WIFI_BANDUTILIZATION_2_ITER2:$RADIO_UTIL_5G"
	if [ "$RADIO_UTIL_5G" -lt "$CHANNEL_THREASHOLD_5G" ];then
		THRESHOLD_REACHED_5G=0
	fi

fi

if [ "$THRESHOLD_REACHED_2G" -eq 0 ] && [ "$THRESHOLD_REACHED_5G" -eq 0 ];then
	echo_t "WIFI_BANDUTILIZATION for 2G and 5G are within the threshold, no action needed, exiting.."
	exit
fi

AutoChannelEnable_2G=`dmcli eRT getv Device.WiFi.Radio.1.AutoChannelEnable  | grep value | awk '{print $5}'`
if [ "$AutoChannelEnable_2G" == "" ] ; then
	AutoChannelEnable_2G=true;
fi
AutoChannelEnable_5G=`dmcli eRT getv Device.WiFi.Radio.2.AutoChannelEnable  | grep value | awk '{print $5}'`
if [ "$AutoChannelEnable_5G" == "" ] ; then
	AutoChannelEnable_5G=true;
fi
if [ "$AutoChannelEnable_2G" = "false" ] && [ "$AutoChannelEnable_5G" = "false" ];then
	echo_t "WIFI_BANDUTILIZATION : AutoChannelEnable is disabled for 2G and 5G, no action needed, exiting.."
	exit
fi

ChanUtilSelfHealEnable_2G=`psmcli get eRT.com.cisco.spvtg.ccsp.Device.WiFi.Radio.1.ChanUtilSelfHealEnable`
if [ "$ChanUtilSelfHealEnable_2G" == "" ] ; then
	ChanUtilSelfHealEnable_2G=0;
fi
ChanUtilSelfHealEnable_5G=`psmcli get eRT.com.cisco.spvtg.ccsp.Device.WiFi.Radio.2.ChanUtilSelfHealEnable`
if [ "$ChanUtilSelfHealEnable_5G" == "" ] ; then
	ChanUtilSelfHealEnable_5G=0;
fi

calculateLastActionTime()
{
	lastActiontakentimeforChanUtil=`syscfg get lastActiontakentimeforChanUtil`
	if [ "$lastActiontakentimeforChanUtil" != "" ];then
		currTime=$(date -u +"%s")
		time_diff_in_seconds=$(($currTime-$lastActiontakentimeforChanUtil))
		Num_Of_Secs_PerDay=86400
		echo "time_diff_in_seconds = $time_diff_in_seconds"
		if [ "$time_diff_in_seconds" -ge "$Num_Of_Secs_PerDay" ];then
			lastActiontakentimeforChanUtil=0;
		fi
	fi
}

if [ "$THRESHOLD_REACHED_2G" -eq 1 ];then

	if [ "$AutoChannelEnable_2G" = "true" ];then

		if [ "$ChanUtilSelfHealEnable_2G" != "0" ];then

			calculateLastActionTime
			if [ "$lastActiontakentimeforChanUtil" == "" ] || [ "$lastActiontakentimeforChanUtil" == "0" ];then
				echo_t "ChanUtilSelfHealEnable value is $ChanUtilSelfHealEnable_2G"
				if [ "$ChanUtilSelfHealEnable_2G" = "1" ];then
					echo_t "WIFI_BANDUTILIZATION : Threshold value ($CHANNEL_THREASHOLD_2G) is reached, resetting 2.4 WiFi"
					for index in $INDEX_LIST
					do
						interface_state=`ifconfig ath$index | grep UP`
						echo "ath$index : $interface_state"
						if [ "$interface_state" != "" ];then
							ifconfig ath$index down
							Interfaces_Active="$Interfaces_Active $index"
						fi
					done
					sleep 1
		
					for index in $Interfaces_Active
					do
						iwconfig ath$index channel 0
					done

					sleep 1

					for index in $Interfaces_Active
					do
						ifconfig ath$index up
					done
		
				elif [ "$ChanUtilSelfHealEnable_2G" = "2" ]; then

					if [ -f /etc/ath/fast_down.sh ];then
						FASTDOWN_PID=`pidof fast_down.sh`
					else
						FASTDOWN_PID=`pidof apdown`
					fi
					APUP_PID=`pidof apup`

					if [ "$APUP_PID" != "" ]; then
						echo_t "WIFI_BANDUTILIZATION : apup is running..."
						exit
					elif [ "$FASTDOWN_PID" != "" ]; then
						echo_t "WIFI_BANDUTILIZATION : apdown is running..."
						exit
					else
						echo_t "WIFI_BANDUTILIZATION : Threshold value is reached, resetting WiFi"
						dmcli eRT setv Device.X_CISCO_COM_DeviceControl.RebootDevice string Wifi
					fi

				else
					echo_t "WIFI_BANDUTILIZATION : Wrong value is set to ChanUtilSelfHealEnable"
				fi

				if [ "$ChanUtilSelfHealEnable_2G" = "1" ] || [ "$ChanUtilSelfHealEnable_2G" = "2" ];then
					storeWiFiRebootTime=$(date -u +"%s")
					syscfg set lastActiontakentimeforChanUtil "$storeWiFiRebootTime"
					syscfg commit
				fi
			else
				echo_t "WIFI_BANDUTILIZATION_2G : THRESHOLD_REACHED but lastActiontakentimeforChanUtil is less than 24 hrs, skipping wifi-reset.."
			fi
		else
			echo_t "WIFI_BANDUTILIZATION_2G : THRESHOLD_REACHED but selfheal is not enabled, no action taken"
		fi
	else
		echo_t "WIFI_BANDUTILIZATION_2G : THRESHOLD_REACHED but Autochannel selection is not enabled, no action taken"
	fi
fi


if [ "$THRESHOLD_REACHED_5G" -eq 1 ];then

	if [ "$AutoChannelEnable_5G" = "true" ];then

		if [ "$ChanUtilSelfHealEnable_5G" = "2" ];then

			calculateLastActionTime
			if [ "$lastActiontakentimeforChanUtil" == "" ] || [ "$lastActiontakentimeforChanUtil" == "0" ];then
				echo_t "ChanUtilSelfHealEnable value is $ChanUtilSelfHealEnable_5G"
				echo_t "WIFI_BANDUTILIZATION : Threshold value ($CHANNEL_THREASHOLD_5G) is reached, resetting 5GHz WiFi"
				dmcli eRT setv Device.X_CISCO_COM_DeviceControl.RebootDevice string Wifi
		
				storeWiFiRebootTime=$(date -u +"%s")
				syscfg set lastActiontakentimeforChanUtil "$storeWiFiRebootTime"
				syscfg commit
			else
				echo_t "WIFI_BANDUTILIZATION_5G : THRESHOLD_REACHED but lastActiontakentimeforChanUtil is less than 24 hrs, skipping wifi-reset.."
			fi
		else
			echo_t "WIFI_BANDUTILIZATION_5G : THRESHOLD_REACHED but selfheal is not enabled, no action taken"
		fi
	else
		echo_t "WIFI_BANDUTILIZATION_5G : THRESHOLD_REACHED but Autochannel selection is not enabled, no action taken"
	fi
fi
