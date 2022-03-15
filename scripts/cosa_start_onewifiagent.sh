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
#######################################################################
#   Copyright [2014] [Cisco Systems, Inc.]
# 
#   Licensed under the Apache License, Version 2.0 (the \"License\");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
# 
#       http://www.apache.org/licenses/LICENSE-2.0
# 
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an \"AS IS\" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
#######################################################################

BINPATH="/usr/bin"

if [ -f /etc/device.properties ]
then
    source /etc/device.properties
fi

CRONFILE=$CRON_SPOOL"/root"
CRONFILE_BK="/tmp/cron_tab$$.txt"

killall OneWifi

DEVICEMODELEXISTS=`cat /etc/device.properties | grep DEVICE_MODEL | cut -f2 -d=`
if [[ $DEVICEMODELEXISTS == "TCHXB3" ]]; then
        # have IP address for dbus config generated
        vconfig add eth0 500
        ifconfig eth0.500 169.254.101.2

fi

source /etc/utopia/service.d/log_capture_path.sh
export LD_LIBRARY_PATH=$PWD:.:$PWD/../../lib:$PWD/../../.:/lib:/usr/lib:$LD_LIBRARY_PATH
export LOG4C_RCPATH=/etc


# enable core files on atom
ulimit -c unlimited
echo "/tmp/core.%e.%p" > /proc/sys/kernel/core_pattern

cp -f ccsp_msg.cfg /tmp

Subsys="eRT."

echo "Elected subsystem is $Subsys"

sleep 1



if [ -e ./wifi ]; then
	cd wifi 
	if [ "x"$Subsys = "x" ];then
        echo "****STARTING CCSPWIFI WITHOUT SUBSYS***"
    	$BINPATH/OneWifi &
	else
        echo "****STARTING CCSPWIFI WITH SUBSYS***"
    	echo "$BINPATH/OneWifi -subsys $Subsys &"
    	$BINPATH/OneWifi -subsys $Subsys &
	fi
fi

if [[ $DEVICEMODELEXISTS == "TCHXB3" ]]; then
        echo "starting process monitor script"
        sh /usr/ccsp/wifi/process_monitor_atom.sh &

fi

echo "Start monitoring wifi system statistics"
if [ -f $CRONFILE ]
then
	# Dump existing cron jobs to a file & add new job
	crontab -l -c $CRON_SPOOL > $CRONFILE_BK
	# Check whether specific cron job is existing or not
	existing_cron=$(grep "aphealth_log.sh" $CRONFILE_BK)
	
	if [ -z "$existing_cron" ]; then
		echo "1 * * * *  /usr/ccsp/wifi/aphealth_log.sh" >> $CRONFILE_BK
		crontab $CRONFILE_BK -c $CRON_SPOOL
	fi
	
	rm -rf $CRONFILE_BK
fi
