#! /bin/sh
##########################################################################
# If not stated otherwise in this file or this component's LICENSE
# file the following copyright and licenses apply:
#
# Copyright 2018 RDK Management
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
#Prints mesh status every 12 hours
source /etc/log_timestamp.sh
source /lib/rdk/t2Shared_api.sh

if [ $# -eq 0 ]; then
enable=`syscfg get mesh_enable`
if [ "$enable" == "true" ]; then
 echo_t "Meshwifi has been enabled"  >> /rdklogs/logs/MeshAgentLog.txt.0
 t2CountNotify "WIFI_INFO_mesh_enabled"
 Pods_12=`dmcli eRT retv Device.WiFi.AccessPoint.13.AssociatedDeviceNumberOfEntries`
 Pods_13=`dmcli eRT retv Device.WiFi.AccessPoint.14.AssociatedDeviceNumberOfEntries`

 #echo_t "Pods connected count: 2.4GHz= $Pods_12, 5GHz= $Pods_13" >> /rdklogs/logs/MeshAgentLog.txt.0
 echo_t "CONNECTED_Pods:Total_WiFi-2.4G_Pods=$Pods_12" >> /rdklogs/logs/MeshAgentLog.txt.0
 t2ValNotify "Total_2G_PodClients_split" "$Pods_12"
 echo_t "CONNECTED_Pods:Total_WiFi-5.0G_Pods=$Pods_13" >> /rdklogs/logs/MeshAgentLog.txt.0
 t2ValNotify "Total_5G_PodClients_split" "$Pods_13"
else
 echo_t "Meshwifi has been disabled"  >> /rdklogs/logs/MeshAgentLog.txt.0
fi

#Print mac address of wifi and ethernet pod macs

#WiFi Pod
maclist="POD_BACKHAUL_MAC:"
linktype="POD_BACKHAUL_LINK:"
ports="POD_BACKHAUL_PORT:"
pod_found=false

for vap in 12 13; do
 if [ $Pods_$vap -gt 0 ]; then
  cliMac=`dmcli eRT getv Device.WiFi.AccessPoint.$((vap+1)).AssociatedDevice. | grep -w MACAddress -A1 | grep -w "value:" | sed "s/.*value: //g"`
  for mac in $cliMac; do 
   maclist="$maclist $mac,"
   linktype="$linktype WiFi,"
   ports="$ports $vap"
   pod_found=true
  done
 else
  echo "Nothing on $vap vap"
 fi
done

#Ethernet Pod
OPENSYNC_ENABLE=`syscfg get opensync`
if [ "$OPENSYNC_ENABLE" == "true" ];then
 pod_mac=`/usr/opensync/tools/ovsh s Node_Config -w module==eth | grep -i value | cut -d'|' -f2`
else
 pod_mac=`/usr/plume/tools/ovsh s Node_Config -w module==eth | grep -i value | cut -d'|' -f2`
fi
for i in $(echo $pod_mac | sed "s/,/ /g"); do
 podmac2=$(echo $i | sed 's/\(..\)/\1:/g;s/:$//' )
 echo "checking $podmac2"
 for port in 1 2 3 4; do
  check=`dmcli eRT getv Device.Ethernet.Interface.$port.X_RDKCENTRAL-COM_AssociatedDevice. | grep -i $podmac2`
  if [ "$check" != "" ]; then
   echo "Pod mac $podmac2 found in $port address"
   maclist="$maclist $podmac2,"
  linktype="$linktype Ethernet,"
  ports="$ports $port"
  phy_rate=`dmcli eRT getv Device.Ethernet.Interface.$port.CurrentBitRate | grep -i value | cut -d":" -f3`
  echo_t "Ethernet backhaul network: Port: $port, cli-addr: $podmac2 , Link Phy-Rate:$phy_rate Mbps" >> /rdklogs/logs/MeshAgentLog.txt.0
  pod_found=true
  fi
 done 
done

echo $maclist
if $pod_found; then
 echo_t "$maclist"  >> /rdklogs/logs/MeshAgentLog.txt.0
 echo_t "$linktype" >> /rdklogs/logs/MeshAgentLog.txt.0
 echo_t "$ports"    >> /rdklogs/logs/MeshAgentLog.txt.0
fi
else
 if [ "$1" == "0" ]; then
  echo_t "pod_detected:xhs_port" >> /rdklogs/logs/MeshAgentLog.txt.0
 else
  echo_t "pod_detected:unsupported_port" >> /rdklogs/logs/MeshAgentLog.txt.0
 fi
fi

if [ "$OPENSYNC_ENABLE" == "true" ] && [ -d "/sys/module/openvswitch" ];then
 VIF_CONFIG_CHECK=`/usr/opensync/tools/ovsh s Wifi_VIF_Config -w ssid==we.connect.yellowstone`
else
 VIF_CONFIG_CHECK=`/usr/plume/tools/ovsh s Wifi_VIF_Config -w ssid==we.connect.yellowstone`
fi
if [ "$VIF_CONFIG_CHECK" != "" ] && [ "$pod_mac" != "" ]; then
    SSID_NAME_12=`dmcli eRT getv Device.WiFi.SSID.13.SSID | grep value | awk '{print $5}'`
    SSID_NAME_13=`dmcli eRT getv Device.WiFi.SSID.14.SSID | grep value | awk '{print $5}'`
    if [ "$SSID_NAME_12" != "we.connect.yellowstone" ]; then
        echo_t "2G SSID is still default for pod customer" >> /rdklogs/logs/MeshAgentLog.txt.0
    fi

    if [ "$SSID_NAME_13" != "we.connect.yellowstone" ]; then
        echo_t "5G SSID is still default for pod customer" >> /rdklogs/logs/MeshAgentLog.txt.0
    fi
fi
