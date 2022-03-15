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
source /etc/log_timestamp.sh
source /lib/rdk/t2Shared_api.sh

buf=`wifi_api wifi_getBandSteeringEnable  | grep "TRUE"`


if [ "$buf" == "" ] ; then
	buf="false"
else
	buf="true"
fi

echo_t "BANDSTEERING_ENABLE_STATUS:$buf"

if [ -f /lib/rdk/wifi_bs_viable_check.sh ]; then
        /lib/rdk/wifi_bs_viable_check.sh
        rc=$?
        if [ "$rc" == "0" ]; then
                echo_t "RDKB_BANDSTEERING_DISABLED_STATUS:false"
		echo_t "All parameters are matching, Band Steering is viable."
		if [ "$buf" == "true" ] ; then
			echo_t "Bandsteering is enabled as All parameters are matching"
                        t2CountNotify "WIFI_INFO_BSEnabled"
		fi
		
		
        else
                echo_t "RDKB_BANDSTEERING_DISABLED_STATUS:true"
		echo_t "Band Steering is not viable."
        fi
else
        echo_t "RDKB_BANDSTEERING_DISABLED_STATUS:false"
fi
