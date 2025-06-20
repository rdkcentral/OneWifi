#!/bin/sh

log_file="/rdklogs/logs/Heapwalk_log.txt"

# Get the current date and time
current_date=$(date)

# Echo the date and time
echo "Current date and time: $current_date" >> "$log_file"

RSSInterval=$1
RSSThreshold=$2
RSSMaxLimit=$3
HeapwalkDuration=$4
HeapwalkInterval=$5

device=`deviceinfo.sh -mo`
if [[ $device == "CGM4331COM" ]]; then
    max_radio=16
else
    max_radio=24
fi

# Convert the input values to seconds
duration=$((HeapwalkDuration * 60))  # Convert duration from minutes to seconds
interval=$((HeapwalkInterval * 60))  # Convert interval from minutes to seconds
end_time=$((SECONDS + duration))

echo "$(date '+%Y-%m-%d %H:%M:%S') Duration: $duration seconds" >> "$log_file"
echo "$(date '+%Y-%m-%d %H:%M:%S') Interval: $interval seconds" >> "$log_file"
echo "$(date '+%Y-%m-%d %H:%M:%S') End Time: $end_time seconds" >> "$log_file"

    #to get the assoclist
echo "Assoclist at starting of the HeapwalkField Script" >> "$log_file"
for((i=1;i<=max_radio;i++)); do
    numdevices=`dmcli eRT getv Device.WiFi.AccessPoint.$i.AssociatedDeviceNumberOfEntries | grep "value:" | cut -f2- -d:| cut -f2- -d:`
    echo "VAP INDEX $i : $numdevices" >> "$log_file"
done

# Check if the Onewifi process is running
initial_pid=$(ps | grep "/usr/bin/OneWifi -subsys eRT\." | grep -v grep | awk '{print $1}')
# Check if PID is provided
if [ -z "$initial_pid" ]; then
    echo "$(date '+%Y-%m-%d %H:%M:%S') Onewifi process not found." >> "$log_file"
    exit 1
fi

sleep 120

# Loop to run the script every interval for the duration
echo "$(date '+%Y-%m-%d %H:%M:%S') Current SECONDS: $SECONDS"  >> "$log_file"
while [ $SECONDS -lt $end_time ]; do
current_pid=$(ps | grep "/usr/bin/OneWifi -subsys eRT\." | grep -v grep | awk '{print $1}')
if [ -z "$current_pid" ]; then
    echo "$(date '+%Y-%m-%d %H:%M:%S') Onewifi process not found." >> "$log_file"
    exit 1
fi

if [ "$current_pid" != "$initial_pid" ]; then
    echo "$(date '+%Y-%m-%d %H:%M:%S') PID has changed. Exiting." >> "$log_file"
    exit 1
else
    # Run memleakutil with input provided directly in the script
    memleakutil <<EOF > /tmp/HeapResultField.txt
$current_pid
1
0
7
EOF
echo "$(date '+%Y-%m-%d %H:%M:%S') Output has been sent to HeapResultField.txt" >> "$log_file"

    input_file="/tmp/HeapResultField.txt"
    output_file="/tmp/HeapwalkFinalResultField.txt"
    # Use grep to extract lines matching the pattern and save them to the output file
    grep -E "0x[0-9a-f]+ [0-9]+ 0x[0-9a-f]+ [0-9]+ [0-9]+" "$input_file" >> "$output_file"
    echo "$(date '+%Y-%m-%d %H:%M:%S') Lines matching the pattern have been extracted to $output_file." >> "$log_file"
fi

# Wait for the interval
echo "$(date '+%Y-%m-%d %H:%M:%S') $SECONDS before interval" >> "$log_file"
sleep $interval
echo "$(date '+%Y-%m-%d %H:%M:%S') $SECONDS after interval" >> "$log_file"
done

temp_file=$(mktemp)
# Process the file
while read -r line; do
    # Extract the 3rd and 4th columns
    pair=$(echo "$line" | awk '{print $3,$4}')
    echo "$pair"
done < "/tmp/HeapwalkFinalResultField.txt" | sort | uniq -c | sort -k1,1nr > "$temp_file"

# Format the output and redirect to the final output file
while read -r count pair; do
    echo "$pair $count"
done < "$temp_file" > /tmp/HeapwalkFinalOutputField.txt

# Remove the temporary file
rm "$temp_file"
echo "$(date '+%Y-%m-%d %H:%M:%S') Completed the Heapwalk repeated count" >> "$log_file"

finaloutput_file="/rdklogs/logs/HeapwalkOutputField.txt"
pid=$(ps | grep "/usr/bin/OneWifi -subsys eRT\." | grep -v grep | awk '{print $1}')
if [ -z "$pid" ]; then
    echo "$(date '+%Y-%m-%d %H:%M:%S') Onewifi process not found while entering the memory map usage" >> "$log_file"
    exit 1
fi
echo "$(date '+%Y-%m-%d %H:%M:%S') Entering the Memory map phase" >> "$log_file"
# Path to the maps file
maps_file="/proc/$pid/maps"

sanitize_hex() {
    # Remove any leading '0x' prefix
    echo "$1" | sed 's/^0x//'
}

# Function to convert hex to decimal using printf
hex_to_dec() {
    # Sanitize the hex input
    local hex=$(sanitize_hex "$1")
    # Convert to decimal
    printf "%d\n" "0x$hex"
}

# Function to convert decimal to hexadecimal
decimal_to_hex() {
    printf "%X\n" "$1"
}

# Function to check the address and use addr2line
check_address() {
local size=$1
local address=$2
local count=$3
local address_dec=$(hex_to_dec "$address")

# Read the maps file line by line
while read -r line; do
    local start=$(echo $line | awk '{print $1}' | cut -d'-' -f1)
    local end=$(echo $line | awk '{print $1}' | cut -d'-' -f2)
    local file_path=$(echo $line | awk '{print $6}')
    local start_dec=$(hex_to_dec "$start")
    local end_dec=$(hex_to_dec "$end")

    # Check if the address falls within the range and the file path is /usr/bin/OneWifi
    if [[ $address_dec -ge $start_dec && $address_dec -lt $end_dec ]]; then
        if [[ $file_path == "/usr/bin/OneWifi" ]]; then
            local offset=$((address_dec - start_dec))
            decimal=$(decimal_to_hex "$offset")
            echo -e "SIZE:$size RETURN_ADDRESS:0x$decimal COUNT:$count File_path:$file_path" >> "$finaloutput_file"
            return 0
        elif [[ $file_path == "/usr/lib/libwifi.so.0.0.0" ]]; then
            local offset=$((address_dec - start_dec))
            decimal=$(decimal_to_hex "$offset")
            echo -e "SIZE:$size RETURN_ADDRESS:0x$decimal COUNT:$count File_path:$file_path" >> "$finaloutput_file"
            return 0
        fi
    fi
done < "/proc/$pid/maps"
# If the address does not fall within any region, print a message to finaloutput.txt
#echo "$size $address $count Address does not fall within any region" >> "$finaloutput_file"
}

# Read each line from heapwalkfinaloutput.txt and check each address
while read -r size address count; do
    check_address "$size" "$address" "$count"
done < "/tmp/HeapwalkFinalOutputField.txt"

echo "$(date '+%Y-%m-%d %H:%M:%S') Processing complete. Results saved to HeapwalkOutputField.txt" >> "$log_file"

rm /tmp/HeapResultField.txt
rm /tmp/HeapwalkFinalResultField.txt
rm /tmp/HeapwalkFinalOutputField.txt

dmcli eRT setv Device.DeviceInfo.X_RDKCENTRAL-COM_xOpsDeviceMgmt.Logging.xOpsDMUploadLogsNow bool true
dmcli eRT setv Device.WiFi.MemwrapTool.Enable bool false