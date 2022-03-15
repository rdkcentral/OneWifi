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

#This script is used to log parameters for each AP

if [ -f /etc/device.properties ]
then
    source /etc/device.properties
fi

if [ "$BOX_TYPE" == "TCCBR" ] || [ "$BOX_TYPE" == "XF3" ] || [ "$BOX_TYPE" == "HUB4" ] || [ "$MODEL_NUM" == "CGM4331COM" ]; then
    ssid1="wl0"
    ssid2="wl1"
elif [ "$MODEL_NUM" == "TG4482A" ]; then
    ssid1="wlan0"
    ssid2="wlan2"
else
    ssid1="ath0"
    ssid2="ath1"
fi

logfolder="/tmp/wifihealth"
oneMB=1048576;
period=60;
source /etc/log_timestamp.sh

if [ ! -d "$logfolder" ] ; then
	mkdir "$logfolder";
fi

rx1_0=`cat "$logfolder/rx1_0"`
rx2_0=`cat "$logfolder/rx2_0"`

if [ "$rx1_0" == "" ] ; then
	rx1_0=0;
fi
if [ "$rx2_0" == "" ] ; then
        rx2_0=0;
fi

rx1=`ifconfig "$ssid1" | grep "RX bytes" | cut -d':' -f2 | cut -d' ' -f1`
rx2=`ifconfig "$ssid2" | grep "RX bytes" | cut -d':' -f2 | cut -d' ' -f1`

if [ "$rx1" == "" ] ; then
        rx1=0;
fi
if [ "$rx2" == "" ] ; then
        rx2=0;
fi

echo "$rx1" > $logfolder/rx1_0;
echo "$rx2" > $logfolder/rx2_0;

rx1d=$(($rx1-$rx1_0))
rx2d=$(($rx2-$rx2_0))

rx1_mb=$(($rx1/$oneMB))
rx2_mb=$(($rx2/$oneMB))

rx1d_mb=$(($rx1d/$oneMB))
rx2d_mb=$(($rx1d/$oneMB))

echo_t "WIFI_RX_1:$rx1_mb"
echo_t "WIFI_RXDELTA_1:$rx1d_mb"

echo_t "WIFI_RX_2:$rx2_mb"
echo_t "WIFI_RXDELTA_2:$rx2d_mb"


if [ -e "/sbin/iwconfig" ] ; then
	l1=`iwconfig $ssid1 | grep "Link Quality"`
	l2=`iwconfig $ssid2 | grep "Link Quality"`
	if [ "$l1" != "" ] ; then
		lq1=`echo $l1 | cut -d"=" -f2 | cut -d" " -f1`
		sl1=`echo $l1 | cut -d"=" -f3 | cut -d" " -f1`
		nl1=`echo $l1 | cut -d"=" -f4 | cut -d" " -f1`
		echo_t "WIFI_LINKQUALITY_1:$lq1"
		echo_t "WIFI_SIGNALLEVEL_1:$sl1"
		echo_t "WIFI_NOISELEVEL_1:$nl1"
	fi
	if [ "$l2" != "" ] ; then
		lq2=`echo $l2 | cut -d"=" -f2 | cut -d" " -f1`
		sl2=`echo $l2 | cut -d"=" -f3 | cut -d" " -f1`
		nl2=`echo $l2 | cut -d"=" -f4 | cut -d" " -f1`
		echo_t "WIFI_LINKQUALITY_2:$lq2"
		echo_t "WIFI_SIGNALLEVEL_2:$sl2"
		echo_t "WIFI_NOISELEVEL_2:$nl2"
	fi
fi

if [ -e "/usr/bin/wl" ] ; then
        l1=`wl -i $ssid1 status | grep "SNR:"`
        l2=`wl -i $ssid2 status | grep "SNR:"`
        if [ "$l1" != "" ] ; then
                lq1=`echo $l1 | awk '{print $7}'`
                sl1=`echo $l1 | awk '{print $4}'`
                nl1=`echo $l1 | awk '{print $10}'`
                echo_t "$tm WIFI_LINKQUALITY_1:$lq1"
                echo_t "$tm WIFI_SIGNALLEVEL_1:$sl1"
                echo_t "$tm WIFI_NOISELEVEL_1:$nl1"
        fi
        if [ "$l2" != "" ] ; then
                lq2=`echo $l2 | awk '{print $7}'`
                sl2=`echo $l2 | awk '{print $4}'`
                nl2=`echo $l2 | awk '{print $10}'`
                echo_t "$tm WIFI_LINKQUALITY_2:$lq2"
                echo_t "$tm WIFI_SIGNALLEVEL_2:$sl2"
                echo_t "$tm WIFI_NOISELEVEL_2:$nl2"
        fi
fi

if [ -e "/sbin/cfg" ] ; then
	check_radio=`cfg -e | grep AP_RADIO_ENABLED`
fi
if [ "$check_radio" != "" ]; then

	excess_retry_0=`cat "$logfolder/excess_retry_0"`
	phy_2_0=`cat "$logfolder/phy_2_0"`
	phy_5_0=`cat "$logfolder/phy_5_0"`
	CRC_2_0=`cat "$logfolder/CRC_2_0"`
	CRC_5_0=`cat "$logfolder/CRC_5_0"`

	if [ "$excess_retry_0" == "" ] ; then
		excess_retry_0=0;
	fi
	if [ "$phy_2_0" == "" ] ; then
		phy_2_0=0;
	fi
	if [ "$phy_5_0" == "" ] ; then
		phy_5_0=0;
	fi
	if [ "$CRC_2_0" == "" ] ; then
		CRC_2_0=0;
	fi
	if [ "$CRC_5_0" == "" ] ; then
		CRC_5_0=0;
	fi
	excess_retry_1=`athstats | grep "excess retries" | cut -d":" -f2`
        phy_2_1=`apstats -r -i wifi1 | grep "Rx PHY errors" | cut -d"=" -f2`
        phy_5_1=`apstats -r -i wifi0 | grep "Rx PHY errors" | cut -d"=" -f2`
        CRC_2_1=`apstats -r -i wifi1 | grep "Rx CRC errors" | cut -d"=" -f2`
        CRC_5_1=`apstats -r -i wifi0 | grep "Rx CRC errors" | cut -d"=" -f2`

	if [ "$excess_retry_1" == "" ] ; then
		excess_retry_1=0;
	fi
	if [ "$phy_2_1" == "" ] ; then
		phy_2_1=0;
	fi
	if [ "$phy_5_1!" == "" ] ; then
		phy_5_1=0;
	fi
	if [ "$CRC_2_1" == "" ] ; then
		CRC_2_1=0;
	fi
	if [ "$CRC_5_1" == "" ] ; then
		CRC_5_1=0;
	fi

	echo "$excess_retry_1" > $logfolder/excess_retry_0;
	echo "$phy_2_1" > $logfolder/phy_2_0;
	echo "$phy_5_1" > $logfolder/phy_5_0;
	echo "$CRC_2_1" > $logfolder/CRC_2_0;
	echo "$CRC_5_1" > $logfolder/CRC_5_0;

	excess_retry_1d=$(($excess_retry_1-$excess_retry_0))
	phy_2_1d=$(($phy_2_1-$phy_2_0))
	phy_5_1d=$(($phy_5_1-$phy_5_0))
	CRC_2_1d=$(($CRC_2_1-$CRC_2_0))
	CRC_5_1d=$(($CRC_5_1-$CRC_5_0))


	excess_retry_1d_mb=$(($excess_retry_1d/$period))
	phy_2_1d_mb=$(($phy_2_1d/$period))
	phy_5_1d_mb=$(($phy_5_1d/$period))
	CRC_2_1d_mb=$(($CRC_2_1d/$period))
	CRC_5_1d_mb=$(($CRC_5_1d/$period))
	echo_t "WIFI_EXCESS_RETRYCOUNT_PER_MINUTE:$excess_retry_1d_mb"
	echo_t "WIFI_PHY_ERROR_PER_MINUTE_1:$phy_2_1d_mb"
	echo_t "WIFI_PHY_ERROR_PER_MINUTE_2:$phy_5_1d_mb"
	echo_t "WIFI_CRC_ERROR_PER_MINUTE_1:$CRC_2_1d_mb"
	echo_t "WIFI_CRC_ERROR_PER_MINUTE_2:$CRC_5_1d_mb"
        stats=`athstats | grep "Tx MCS STATS:" -A 2 | grep "mcs 0- mcs 4 STATS:" | cut -d":" -f2`
	stats=`echo -n "${stats//[[:space:]]/}"`
        echo_t "WIFI_MCS_TX_0_TO_4:$stats"
	stats=`athstats | grep "Tx MCS STATS:" -A 2 | grep "mcs 5- mcs 9 STATS:" | cut -d":" -f2`
	stats=`echo -n "${stats//[[:space:]]/}"`
        echo_t "WIFI_MCS_TX_5_TO_9:$stats"
        stats=`athstats | grep "Rx MCS STATS:" -A 2 | grep "mcs 0- mcs 4 STATS:" | cut -d":" -f2`
	stats=`echo -n "${stats//[[:space:]]/}"`
        echo_t "WIFI_MCS_RX_0_TO_4:$stats"
	stats=`athstats | grep "Rx MCS STATS:" -A 2 | grep "mcs 5- mcs 9 STATS:" | cut -d":" -f2`
	stats=`echo -n "${stats//[[:space:]]/}"`
        echo_t "WIFI_MCS_RX_5_TO_9:$stats"
fi

#beacon rate
for i in 0 2 4 6 8 10; do
	a=`wifi_api wifi_getApEnable $i | grep -i TRUE`
	if [ "$a" != "" ]; then
		if [ "$BOX_TYPE" == "HUB4" ]; then
			br=`wifi_api wifi_getApBeaconRate $i | grep -i out_str | sed 's/out_str: //' | sed 's/Mbps//'`
		else
			br=`wifi_api wifi_getApBeaconRate $i | grep -i Mbps | sed 's/out_str: //' | sed 's/Mbps//'`
		fi
		if [ "$br" != "" ]; then
			ins=$((i+1));
			echo_t "WIFI_BEACON_RATE_$ins:$br"
		fi
	fi
done
