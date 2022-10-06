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
