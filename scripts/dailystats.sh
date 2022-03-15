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
ssid1="0"
ssid2="1"
source /etc/log_timestamp.sh

enable1=`wifi_api wifi_getApWpsEnable $ssid1 | grep TRUE`
enable2=`wifi_api wifi_getApWpsEnable $ssid2 | grep TRUE`
configpbc1=`wifi_api wifi_getApWpsConfigMethodsEnabled $ssid1 | grep PushButton`
configpbc2=`wifi_api wifi_getApWpsConfigMethodsEnabled $ssid2 | grep PushButton`
configpin1=`wifi_api wifi_getApWpsConfigMethodsEnabled $ssid1 | grep Keypad`
configpin2=`wifi_api wifi_getApWpsConfigMethodsEnabled $ssid2 | grep Keypad`

if [ "$enable1" != "" ] ; then
	echo_t "RDKB_WPS_ENABLED_1:TRUE"
else
	echo_t "RDKB_WPS_ENABLED_1:FALSE"
fi
if [ "$enable2" != "" ] ; then
	echo_t "RDKB_WPS_ENABLED_2:TRUE"
else
	echo_t "RDKB_WPS_ENABLED_2:FALSE"
fi
if [ "$configpbc1" != "" ] ; then
	echo_t "RDKB_WPS_PBC_CONFIGURED_1:TRUE"
else
	echo_t "RDKB_WPS_PBC_CONFIGURED_1:FALSE"
fi
if [ "$configpbc2" != "" ] ; then
	echo_t "RDKB_WPS_PBC_CONFIGURED_2:TRUE"
else
	echo_t "RDKB_WPS_PBC_CONFIGURED_2:FALSE"
fi
if [ "$configpin1" != "" ] ; then
	echo_t "RDKB_WPS_PIN_CONFIGURED_1:TRUE"
else
	echo_t "RDKB_WPS_PIN_CONFIGURED_1:FALSE"
fi
if [ "$configpin2" != "" ] ; then
	echo_t "RDKB_WPS_PIN_CONFIGURED_2:TRUE"
else
	echo_t "RDKB_WPS_PIN_CONFIGURED_2:FALSE"
fi	
