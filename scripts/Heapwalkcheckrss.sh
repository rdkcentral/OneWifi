#!/bin/sh


tmpfile1="/tmp/HeapResultField.txt"
tmpfile2="/tmp/HeapwalkFinalResultField.txt"
tmpfile3="/tmp/HeapwalkFinalOutputField.txt"


if [ -f "$tmpfile1" ]; then
    rm "$tmpfile1"
fi
if [ -f "$tmpfile2" ]; then
    rm "$tmpfile2"
fi
if [ -f "$tmpfile3" ]; then
    rm "$tmpfile3"
fi


sleep 300


log_file="/rdklogs/logs/Heapwalkrss_log.txt"


# Get the current date and time
current_date=$(date)


# Echo the date and time
echo "Current date and time: $current_date" >> "$log_file"
RSSInterval_minutes=$1
RSSInterval=$((RSSInterval_minutes * 60))
RSSThreshold=$2
RSSMaxLimit=$3
HeapwalkDuration=$4
HeapwalkInterval=$5
HeapwalkDurationInSeconds=$((HeapwalkDuration * 60))


echo "RSS Interval: $RSSInterval" >> "$log_file"
echo "RSS Threshold: $RSSThreshold" >> "$log_file"
echo "RSS Max Limit : $RSSMaxLimit" >> "$log_file"
echo "Heapwalk Duration: $HeapwalkDuration" >> "$log_file"
echo "Heapwalk Interval: $HeapwalkInterval" >> "$log_file"


device=`deviceinfo.sh -mo`
if [[ $device == "CGM4331COM" ]]; then
    max_radio=16
else
    max_radio=24
fi

#to get the assoclist
echo "AssocList Before starting RSS script : " >> "$log_file"
for((i=1;i<=max_radio;i++)); do
    numdevices=`dmcli eRT getv Device.WiFi.AccessPoint.$i.AssociatedDeviceNumberOfEntries | grep "value:" | cut -f2- -d:| cut -f2- -d:`
    echo "VAP INDEX $i : $numdevices" >> "$log_file"
done


#to check for onewifi process
onewifi_pid=$(ps | grep "/usr/bin/OneWifi -subsys eRT\." | grep -v grep | awk '{print $1}')


    memleakutil <<EOF> /tmp/HeapResultField.txt
$onewifi_pid
4
7
EOF
echo "$(date '+%Y-%m-%d %H:%M:%S') Overall HEAPWALK is marked as walked at starting" >> "$log_file"
sleep 300
STATUS_FILE="/proc/$onewifi_pid/status"
if [ ! -f "$STATUS_FILE" ]; then
  echo "$(date '+%Y-%m-%d %H:%M:%S') Process with PID $onewifi_pid does not exist." >> "$log_file"
  exit 1
fi
initial_vmrss=$(grep -i 'VmRSS' "$STATUS_FILE" | awk '{print $2}')
echo "$(date '+%Y-%m-%d %H:%M:%S') Initial RSS : $initial_vmrss" >> "$log_file"

while true; do
    echo "$(date '+%Y-%m-%d %H:%M:%S') Sleeping for $RSSInterval" >> "$log_file"
    sleep $RSSInterval
    onewifi_pid2=$(ps | grep "/usr/bin/OneWifi -subsys eRT\." | grep -v grep | awk '{print $1}')
    if [ -z "$onewifi_pid2" ]; then
        echo "$(date '+%Y-%m-%d %H:%M:%S') Onewifi process not found" >> "$log_file"
        exit 1
    fi
    if [ $onewifi_pid != $onewifi_pid2 ]; then
        echo "$(date '+%Y-%m-%d %H:%M:%S') Onewifi pid changed. Exiting the script" >> "$log_file"
        exit 1
    fi
    STATUS_FILE="/proc/$onewifi_pid2/status"
    if [ ! -f "$STATUS_FILE" ]; then
        echo "$(date '+%Y-%m-%d %H:%M:%S') Process with PID $onewifi_pid does not exist." >> "$log_file"
        exit 1
    fi
    current_vmrss=$(grep -i 'VmRSS' "$STATUS_FILE" | awk '{print $2}')
    echo "$(date '+%Y-%m-%d %H:%M:%S') Current RSS : $current_vmrss" >> "$log_file"
    rss_diff=$((current_vmrss - initial_vmrss))
    echo "$(date '+%Y-%m-%d %H:%M:%S') RSS Diff: $rss_diff" >> "$log_file"
    if [ "$rss_diff" -gt "$RSShreshold" ] || [ "$current_vmrss" -gt "$RSSMaxLimit" ]; then
        heapwalk_pid=$(ps | grep -i "HeapwalkField" | grep -v grep |  awk '{print $1}')
        echo "$(date '+%Y-%m-%d %H:%M:%S') HeapwalkField.sh pid : $heapwalk_pid" >> "$log_file"
        if [ -z "$heapwalk_pid" ]; then
            /usr/ccsp/wifi/HeapwalkField.sh "$RSSInterval" "$RSSThreshold" "$RSSMaxLimit" "$HeapwalkDuration" "$HeapwalkInterval" &
            echo "$(date '+%Y-%m-%d %H:%M:%S') RSS increased. Running the other script." >> "$log_file"
            sleep "$HeapwalkDurationInSeconds"
        else
            echo "$(date '+%Y-%m-%d %H:%M:%S') Process already running" >> "$log_file"
        fi
    else
        echo "$(date '+%Y-%m-%d %H:%M:%S') RSS is not increased. Continuing with the script" >> "$log_file"
    fi
    initial_vmrss=$current_vmrss
    echo "$(date '+%Y-%m-%d %H:%M:%S') Initial RSS : $initial_vmrss" >> "$log_file"
done