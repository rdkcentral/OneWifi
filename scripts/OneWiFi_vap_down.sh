#!/bin/sh
####################################################################################
# If not stated otherwise in this file or this component's LICENSE file the
# following copyright and licenses apply:
#
#  Copyright 2025 RDK Management
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
##################################################################################

LOG_FILE="/rdklogs/logs/wifi_selfheal.txt"
MODEL_NUM=`grep MODEL_NUM /etc/device.properties | cut -d "=" -f2`
CGM43="CGM4331COM"
CGM49="CGM4981COM"
TG4="TG4482A"

if [ "$MODEL_NUM" == "$CGM49" ] || [ "$MODEL_NUM" == "$CGM43" ] || [ "${MODEL_NUM}" = "CGM601TCOM" ] || [ "${MODEL_NUM}" = "CWA438TCOM" ] || [ "${MODEL_NUM}" = "SG417DBCT" ]; then
    for i in 0 1
    do
        ifconfig wl"$i" down
        for j in 1 2 3 4 5 6 7
        do
            ifconfig wl"$i"."$j" down
        done
    done
    echo "all vaps are going to down state..." >> $LOG_FILE
fi

if [ "$MODEL_NUM" == "$CGM49" ] || [ "${MODEL_NUM}" = "CGM601TCOM" ] || [ "${MODEL_NUM}" = "CWA438TCOM" ] || [ "${MODEL_NUM}" = "SG417DBCT" ]; then
    for i in 2
    do
        ifconfig wl"$i" down
        for j in 1 2 3 4 5 6 7
        do
            ifconfig wl"$i"."$j" down
        done
        echo "third radio vaps are going to down state"
    done
fi

if [ "$MODEL_NUM" == "$TG4" ]; then
    for i in 0 2
    do
        for j in 0 1 2 3 4 5 6
        do
            ifconfig wlan"$i"."$j" down
        done
    done

    for i in 1 3
    do
        ifconfig wlan"$i" down
    done

    echo "all vaps are going to down state..." >> $LOG_FILE
fi
