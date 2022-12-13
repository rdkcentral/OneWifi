if [ -f /etc/device.properties ]
then
    source /etc/device.properties
fi

CRONFILE=$CRON_SPOOL"/root"
CRONFILE_BK="/tmp/cron_selfheal$$.txt"


start_cron_job()
{

    if [ -f $CRONFILE ]
      then
        # Dump existing cron jobs to a file & add new job
        crontab -l -c $CRON_SPOOL > $CRONFILE_BK

        # Check whether specific cron jobs are existing or not
        self_heal_run=$(grep "wifi_self_heal_command.sh" $CRONFILE_BK)

        if [ -z "$self_heal_run" ]; then
            echo "0 */1 * * *  /usr/ccsp/wifi/wifi_self_heal_command.sh" >> $CRONFILE_BK
            crontab $CRONFILE_BK -c $CRON_SPOOL
        fi
        rm -rf $CRONFILE_BK
        rm -rf "/nvram/wifi_self_heal"
    fi
}
stop_cron_job()
{
    crontab -l | grep -v 'wifi_self_heal_command.sh'| crontab -
    touch "/nvram/wifi_self_heal"
}

if [ $1 == "start" ]; then
    start_cron_job
else
    stop_cron_job

fi
