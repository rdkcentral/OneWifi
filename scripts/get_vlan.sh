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

if [ $# -ne 1 ]; then
        exit 1
fi

iface=$1

case $1 in

wlan0.2 | wl0.3)
        lan=brlan2;;
wlan2.2 | wl1.3)
        lan=brlan3;;
wl0.4)
        lan=brlan16;;
wl1.4)
        lan=brlan17;;
wlan0.4 | wl0.5)
        lan=brlan4;;
wlan2.4 | wl1.5)
        lan=brlan5;;
wl2.3)
        lan=bropen6g;;
wl2.4) 
        lan=brlan18;;
wl2.5)
        lan=brsecure6g;;
*)
        exit 1
esac

vlan=`brctl show | grep $lan | awk '{print $4}' | cut -d '.' -f2`
if [ "X$vlan" != "X" ]; then
        echo $vlan
else
        exit 1
fi
