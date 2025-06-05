#!/bin/sh

/etc/init.d/wpad stop

iw phy phy0 interface add wifi0 type __ap
iw phy phy0 interface add wifi1 type __ap
iw phy phy0 interface add wifi1.1 type __ap
iw phy phy0 interface add wifi1.2 type __ap
iw phy phy0 interface add wifi2 type __ap

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
wifi0_mac=$(printf "%012x" $primary_wifi_mac | sed 's/../&:/g;s/:$//')
#Increment primary_wifi_mac by 1 to get wifi1_mac
mac_incr=$(($primary_wifi_mac + 1))
wifi1_mac=$(printf "%012x" $mac_incr | sed 's/../&:/g;s/:$//')
#Increment again by 1 to get wifi1.1 address
mac_incr=$(($mac_incr + 1))
wifi1_1_mac=$(printf "%012x" $mac_incr | sed 's/../&:/g;s/:$//')
#Increment again by 1 to get wifi1.2 address
mac_incr=$(($mac_incr + 1))
wifi1_2_mac=$(printf "%012x" $mac_incr | sed 's/../&:/g;s/:$//')
#Increment again by 1 to get wifi2 address
mac_incr=$(($mac_incr + 1))
wifi2_mac=$(printf "%012x" $mac_incr | sed 's/../&:/g;s/:$//')
#print the mac address
echo $wifi0_mac
echo $wifi1_mac
echo $wifi1_1_mac
echo $wifi1_2_mac
echo $wifi2_mac

#Update the mac address using ip link command
ifconfig wifi0 down
ifconfig wifi1 down
ifconfig wifi1.1 down
ifconfig wifi1.2 down
ifconfig wifi2 down
ip link set dev wifi0 address $wifi0_mac
ip link set dev wifi1 address $wifi1_mac
ip link set dev wifi1.1 address $wifi1_1_mac
ip link set dev wifi1.2 address $wifi1_2_mac
ip link set dev wifi2 address $wifi2_mac
ifconfig wifi0 up
ifconfig wifi1 up
ifconfig wifi1.1 up
ifconfig wifi1.2 up
ifconfig wifi2 up

# Create the EasyMeshCfg.json which will have the al_mac_address
# same as that of wifi_1_1_mac
al_mac_addr=$wifi1_1_mac
colocated_mode=0
backhaul_ssid="mesh_backhaul"
backhaul_keypassphrase="test-backhaul"
sta_4addr_mode_enabled=true

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
output_file="EasymeshCfg.json"
echo "$json_data" > "$output_file"

# Print a confirmation message
echo "Successfully created ${output_file} with the following content:"
cat "$output_file"

#Copy configuration file to nvram
mkdir -p /nvram
cp InterfaceMap.json /nvram/.
cp EasymeshCfg.json /nvram/.
