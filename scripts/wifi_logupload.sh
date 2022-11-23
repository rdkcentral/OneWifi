#/************************************************************************************
#  If not stated otherwise in this file or this component's LICENSE file the
#  following copyright and licenses apply:
  
#  Copyright 2018 RDK Management
  
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
  
#  http://www.apache.org/licenses/LICENSE-2.0
  
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
# **************************************************************************/

if [ -f /etc/device.properties ]
then
    source /etc/device.properties
fi

CRONFILE=$CRON_SPOOL"/root"
CRONFILE_BK="/tmp/cron_tab$$.txt"
ENTRY_ADDED=0

start_cron_job()
{
    echo "Start copying tmp wifilogs to /rdklogs/logs"
    if [ -f $CRONFILE ]
      then
        # Dump existing cron jobs to a file & add new job
        crontab -l -c $CRON_SPOOL > $CRONFILE_BK

        # Check whether specific cron jobs are existing or not
        copy_wifi_logs=$(grep "copy_wifi_logs.sh" $CRONFILE_BK)

        if [ -z "$copy_wifi_logs" ]; then
            echo "*/30 * * * *  /usr/ccsp/wifi/copy_wifi_logs.sh" >> $CRONFILE_BK
            ENTRY_ADDED=1
        fi

        if [ $ENTRY_ADDED -eq 1 ]; then
            crontab $CRONFILE_BK -c $CRON_SPOOL
            touch "/nvram/wifi_log_upload"
        fi

        rm -rf $CRONFILE_BK
    fi
}
stop_cron_job()
{
    crontab -l | grep -v 'copy_wifi_logs.sh'| crontab -
    rm -f  "/nvram/wifi_log_upload"
}

if [ $1 == "start" ]; then
    start_cron_job
else
    stop_cron_job

fi
