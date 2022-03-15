#!/bin/sh
##########################################################################
# If not stated otherwise in this file or this component's LICENSE
# file the following copyright and licenses apply:
#
# Copyright 2015 RDK Management
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
##########################################################################

source /etc/log_timestamp.sh

if [ -f /etc/device.properties ]
then
    source /etc/device.properties
fi

vAPStats_Directory="/nvram/wifihealth"
vAPStats_up_t0_tmpfile="/tmp/wifihealth/up_t0"
vAPStats_up_ct_tmpfile="/tmp/wifihealth/up_ct"
vAPStats_up_t0_nvramfile="/nvram/wifihealth/up_t0"
vAPStats_up_ct_nvramfile="/nvram/wifihealth/up_ct"

echo_t "Taking copy of WiFi vAP SSID statistics from /tmp/wifihealth/ directory" >> $WIFI_CONSOLE_LOG_NAME

if [ ! -d $vAPStats_Directory ]
then
	mkdir $vAPStats_Directory
fi

if [ -f $vAPStats_up_t0_tmpfile ]
then
	cp $vAPStats_up_t0_tmpfile $vAPStats_up_t0_nvramfile
fi

if [ -f $vAPStats_up_ct_tmpfile ]
then
	cp $vAPStats_up_ct_tmpfile $vAPStats_up_ct_nvramfile
fi
