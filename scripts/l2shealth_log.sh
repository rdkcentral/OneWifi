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

uptime=$(cut -d. -f1 /proc/uptime)
echo "before running l2shealth.sh printing top" >> /rdklogs/logs/AtomConsolelog.txt.0
top -n1 -b > /tmp/top.txt
cat /tmp/top.txt >> /rdklogs/logs/AtomConsolelog.txt.0
if [ $uptime -gt 1800 ] && [ "$(pidof CcspWifiSsp)" != "" ] && [ "$(pidof apup)" == "" ] && [ "$(pidof fastdown)" == "" ] && [ "$(pidof apdown)" == "" ]  && [ "$(pidof aphealth.sh)" == "" ] && [ "$(pidof radiohealth.sh)" == "" ] && [ "$(pidof aphealth_log.sh)" == "" ] && [ "$(pidof bandsteering.sh)" == "" ] && [ "$(pidof l2shealth.sh)" == "" ]  && [ "$(pidof log_mem_cpu_info_atom.sh)" == "" ] && [ "$(pidof dailystats.sh)" == "" ] && [ "$(pidof dailystats_log.sh)" == "" ] ; then
	/usr/ccsp/wifi/l2shealth.sh >> /rdklogs/logs/AtomConsolelog.txt.0
        echo "top after running l2shealth.sh" >> /rdklogs/logs/AtomConsolelog.txt.0
        top -n1 -b > /tmp/top.txt
        cat /tmp/top.txt >> /rdklogs/logs/AtomConsolelog.txt.0
else
        echo "skipping l2shealth.sh run" >> /rdklogs/logs/AtomConsolelog.txt.0
	
fi

