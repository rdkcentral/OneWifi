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


arm_hours=0
arm_days=0
arm_minutes=0

ARM_RPC_IP=`cat /etc/device.properties | grep ARM_ARPING_IP | cut -f 2 -d"="`

ARM_CCSP_RESTART="/usr/ccsp/ccsp_restart.sh"


uptime_out=`rpcclient $ARM_RPC_IP uptime | grep load`

echo "RPC : $uptime_out"

isUpforDays=`echo $uptime_out | grep day`


if [ "$isUpforDays" = "" ]
then
    arm_days=0
    notInDays=`echo $uptime_out | awk -F, '{sub(".*up ",x,$1);print $1}'`
    
    # Check whether we have got any hour field
    isMoreThanHour=`echo $uptime_out | awk -F, '{sub(".*up ",x,$1);print $1}' | grep ":"`
    if [ "$isMoreThanHour" != "" ]
    then
        arm_hours=`echo $isMoreThanHour | tr -d " " | cut -f1 -d:`
        arm_minutes=`echo $isMoreThanHour | tr -d " " | cut -f2 -d:`
    else
        arm_hours=0
        arm_minutes=`echo $notInDays | cut -f1 -d" "`
    fi
    
else
    # Get days and uptime
    upInDays=`echo $uptime_out | awk -F, '{sub(".*up ",x,$1);print $1,$2}'`
    
    arm_days=`echo $upInDays | cut -f1 -d" "` 
    if [ "$arm_days" -eq 1 ]
    then
        # Check whether we have got any hour field
        isHourPresent=`echo $upInDays | awk -F, '{sub(".*day ",x,$1);print $1}' | grep ":"`
    else
        # Check whether we have got any hour field
        isHourPresent=`echo $upInDays | awk -F, '{sub(".*days ",x,$1);print $1}' | grep ":"`
    fi

    if [ "$isHourPresent" != "" ]
    then
       arm_hours=`echo $isHourPresent | tr -d " " | cut -f1 -d:`
       arm_minutes=`echo $isHourPresent | cut -f2 -d":"`
    else
       arm_hours=0    
    fi
fi
    
echo "ARM_UPTIMEDAY:$arm_days" 
echo "ARM_UPTIMEHR:$arm_hours" 
echo "ARM_UPTIMEMIN:$arm_minutes"



##############################################################################

# ATOM UPTIME SECTION


atom_hours=0
atom_days=0
atom_minutes=0


isUpforDays=`uptime | grep day`

if [ "$isUpforDays" = "" ]
then
    atom_days=0
    notInDays=`uptime | awk -F, '{sub(".*up ",x,$1);print $1}'`
    
    # Check whether we have got any hour field
    isMoreThanHour=`uptime | awk -F, '{sub(".*up ",x,$1);print $1}' | grep ":"`
    if [ "$isMoreThanHour" != "" ]
    then
        atom_hours=`echo $isMoreThanHour | tr -d " " | cut -f1 -d:`
        atom_minutes=`echo $isMoreThanHour | tr -d " " | cut -f2 -d:`
    else
        atom_hours=0
        atom_minutes=`echo $notInDays | cut -f1 -d" "`
    fi
    
else
    # Get days and uptime
    upInDays=`uptime | awk -F, '{sub(".*up ",x,$1);print $1,$2}'`
    
    atom_days=`echo $upInDays | cut -f1 -d" "`
    if [ "$atom_days" -eq 1 ]
    then
        # Check whether we have got any hour field
        isHourPresent=`echo $upInDays | awk -F, '{sub(".*day ",x,$1);print $1}' | grep ":"`
    else
        # Check whether we have got any hour field
        isHourPresent=`echo $upInDays | awk -F, '{sub(".*days ",x,$1);print $1}' | grep ":"`
    fi

    if [ "$isHourPresent" != "" ]
    then
       atom_hours=`echo $isHourPresent | tr -d " " | cut -f1 -d:`
       atom_minutes=`echo $isHourPresent | cut -f2 -d":"`
    else
       atom_hours=0
    fi
fi

echo "ATOM_UPTIMEDAY:$atom_days" 
echo "ATOM_UPTIMEHR:$atom_hours"
echo "ATOM_UPTIMEMIN:$atom_minutes"


if [ $arm_days -ne 0 ] && [ $atom_days -lt $arm_days ]; then
	echo "RDKB: Uptime of ARM is greater than atom Restarting Ccsp"
	rpcclient $ARM_RPC_IP sh $ARM_CCSP_RESTART
elif [ $arm_hours -ne 0 ] && [ $atom_hours -lt $arm_hours ]; then
	echo "RDKB: Uptime of ARM is greater than atom Restarting Ccsp"
	rpcclient $ARM_RPC_IP sh $ARM_CCSP_RESTART
elif [ $arm_minutes -ne 0 ] && [ $atom_minutes -lt $arm_minutes ]; then
	diff=$((arm_minutes - atom_minutes))
	echo "arm and atom diff in min : $diff "
	if [ $diff -gt 1 ];then
	echo "RDKB: Uptime of ARM is greater than atom Restarting Ccsp"
	    rpcclient $ARM_RPC_IP sh $ARM_CCSP_RESTART
	fi
fi
