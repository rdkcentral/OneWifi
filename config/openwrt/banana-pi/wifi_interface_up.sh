#!/bin/sh

/etc/init.d/wpad stop

iw phy phy0 interface add wifi0 type __ap
iw phy phy0 interface add wifi0.1 type __ap
iw phy phy0 interface add wifi0.2 type __ap
iw phy phy0 interface add wifi1 type __ap
iw phy phy0 interface add wifi1.1 type __ap
iw phy phy0 interface add wifi1.2 type __ap
iw phy phy0 interface add wifi1.3 type __ap
iw phy phy0 interface add wifi2 type __ap
#iw phy phy0 interface add wifi2.1 type __ap
#iw phy phy0 interface add wifi2.2 type __ap
iw phy phy0 interface add mld0 type __ap radios all

#Derive the initial wifi mac address from eth0 or erouter0 address
#as they are unique for each Banana PI
if [ -e "/sys/class/net/erouter0/address" ]; then
	primary_addr="$(cat /sys/class/net/erouter0/address)"
	echo "Reading mac:$primary_addr from erouter0"
	#Convert the mac address into hex and increment by 1
	primary_wifi_mac=$(echo $primary_addr | tr -d ':')
	primary_wifi_mac=$((0x$primary_wifi_mac + 1))
elif [ -e "/sys/class/net/eth0/address" ]; then
        primary_addr="$(cat /sys/class/net/eth0/address)"
        echo "Reading mac:$primary_addr from eth0"
	primary_wifi_mac=$(echo $primary_addr | tr -d ':')
	primary_wifi_mac=$((0x$primary_wifi_mac + 1))
else
	primary_addr="$(cat /sys/class/ieee80211/phy0/macaddress)"
	primary_wifi_mac=$(echo $primary_addr | tr -d ':')
	primary_wifi_mac=$((0x$primary_wifi_mac + 0))
fi

#Obtain the wifi0 mac address from primary_wifi_mac by converting to str format
mac_incr=$(($primary_wifi_mac + 0))
wifi0_mac=$(printf "%012x" $mac_incr | sed 's/../&:/g;s/:$//')
#Increment again by 1 to get wifi0.1_mac
mac_incr=$(($mac_incr + 1))
wifi0_1_mac=$(printf "%012x" $mac_incr | sed 's/../&:/g;s/:$//')
#Increment again by 1 to get wifi0.2_mac
mac_incr=$(($mac_incr + 1))
wifi0_2_mac=$(printf "%012x" $mac_incr | sed 's/../&:/g;s/:$//')
#Increment primary_wifi_mac by 0x10 (decimal 16) to get wifi1 address
mac_incr=$(($primary_wifi_mac + 16))
wifi1_mac=$(printf "%012x" $mac_incr | sed 's/../&:/g;s/:$//')
#Increment again by 1 to get wifi1.1 address
mac_incr=$(($mac_incr + 1))
wifi1_1_mac=$(printf "%012x" $mac_incr | sed 's/../&:/g;s/:$//')
#Increment again by 1 to get wifi1.2 address
mac_incr=$(($mac_incr + 1))
wifi1_2_mac=$(printf "%012x" $mac_incr | sed 's/../&:/g;s/:$//')
#Increment again by 1 to get wifi1.3 address
mac_incr=$(($mac_incr + 1))
wifi1_3_mac=$(printf "%012x" $mac_incr | sed 's/../&:/g;s/:$//')
#Increment primary_wifi_mac by 0x20 (decimal 32) to get wifi2 address
mac_incr=$(($primary_wifi_mac + 32))
wifi2_mac=$(printf "%012x" $mac_incr | sed 's/../&:/g;s/:$//')
#Increment again by 1 to get wifi2.1 address
#mac_incr=$(($mac_incr + 1))
#wifi2_1_mac=$(printf "%012x" $mac_incr | sed 's/../&:/g;s/:$//')
#Increment again by 1 to get wifi2.2 address
#mac_incr=$(($mac_incr + 1))
#wifi2_2_mac=$(printf "%012x" $mac_incr | sed 's/../&:/g;s/:$//')
#print the mac address
echo $wifi0_mac
echo $wifi0_1_mac
echo $wifi0_2_mac
echo $wifi1_mac
echo $wifi1_1_mac
echo $wifi1_2_mac
echo $wifi1_3_mac
echo $wifi2_mac
#echo $wifi2_1_mac
#echo $wifi2_2_mac

#Update the mac address using ip link command
ifconfig wifi0 down
ifconfig wifi0.1 down
ifconfig wifi0.2 down
ifconfig wifi1 down
ifconfig wifi1.1 down
ifconfig wifi1.2 down
ifconfig wifi1.3 down
ifconfig wifi2 down
#ifconfig wifi2.1 down
#ifconfig wifi2.2 down
ip link set dev wifi0 address $wifi0_mac
ip link set dev wifi0.1 address $wifi0_1_mac
ip link set dev wifi0.2 address $wifi0_2_mac
ip link set dev wifi1 address $wifi1_mac
ip link set dev wifi1.1 address $wifi1_1_mac
ip link set dev wifi1.2 address $wifi1_2_mac
ip link set dev wifi1.3 address $wifi1_3_mac
ip link set dev wifi2 address $wifi2_mac
#ip link set dev wifi2.1 address $wifi2_1_mac
#ip link set dev wifi2.2 address $wifi2_2_mac
ifconfig wifi0 up
ifconfig wifi0.1 up
ifconfig wifi0.2 up
ifconfig wifi1 up
ifconfig wifi1.1 up
ifconfig wifi1.2 up
ifconfig wifi1.3 up
ifconfig wifi2 up
#ifconfig wifi2.1 up
#ifconfig wifi2.2 up

# Set MLD interface address as wifi2 MAC address + 1
prefix="${wifi2_mac%:*}"
last_byte="${wifi2_mac##*:}"

new_byte=$(printf "%02X" $(( (0x$last_byte + 1) & 0xFF )))
new_mac="$prefix:$new_byte"

ip link set dev "mld0" down
ip link set dev "mld0" address "$new_mac"

#Copy configuration file to nvram
mkdir -p /nvram
cp InterfaceMap.json /nvram/.

# Create the EasyMeshCfg.json which will have the al_mac_address
# same as that of sta wifi_1_3_mac
al_mac_addr=$wifi1_3_mac
colocated_mode=0
backhaul_ssid="mesh_backhaul"
backhaul_keypassphrase="test-backhaul"
sta_4addr_mode_enabled=true

# Write the JSON data to the file
output_file="/nvram/EasymeshCfg.json"
write_easymeshcfg=true
# Don't overwrite if colocated_mode is set to 1
if [ -f "$output_file" ]; then
    echo "Checking existing ${output_file} for Colocated_mode..."
    # Attempt to read the Colocated_mode value using jsonfilter
    # Redirect stderr to /dev/null to suppress errors if the file is not valid JSON or key is missing
    existing_colocated_mode=$(jsonfilter -i "$output_file" -e '@.Colocated_mode' 2>/dev/null)

    if [ "$existing_colocated_mode" = "1" ]; then
        echo "Colocated_mode is already 1 in ${output_file}. Skipping file creation."
        write_easymeshcfg=false
    else
        echo "Colocated_mode is not 1 (or not found) in existing ${output_file}. Proceeding to create/overwrite."
    fi
else
    echo "${output_file} does not exist. Proceeding to create the file."
fi

# Proceed to write the file only if write_easymeshcfg is true
if [ "$write_easymeshcfg" = true ]; then
    # Construct the JSON string
    json_data=$(cat <<EOF
{
  "AL_MAC_ADDR": "${al_mac_addr}",
  "Colocated_mode": ${colocated_mode},
  "Backhaul_SSID": "${backhaul_ssid}",
  "Backhaul_KeyPassphrase": "${backhaul_keypassphrase}",
  "sta_4addr_mode_enabled": ${sta_4addr_mode_enabled}
}
EOF
)

    # Write the JSON data to the file
    echo "$json_data" > "$output_file"

    # Print a confirmation message
    echo "Successfully created ${output_file} with the following content:"
    cat "$output_file"
else
	echo "No changes made to ${output_file}."
fi

# Increase socket buffer to 2MB to support larger Netlink RX/TX buffers
sysctl -w net.core.rmem_max=2097152
sysctl -w net.core.wmem_max=2097152
