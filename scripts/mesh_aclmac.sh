#!/bin/sh
######################################################################################
# If not stated otherwise in this file or this component's LICENSE file the
# following copyright and licenses apply:

#  Copyright 2018 RDK Management

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

# http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#######################################################################################
#by zqiu

#mesh_aclmac.sh allow
#mesh_aclmac.sh restore
#mesh_aclmac.sh add <MAC>
#mesh_aclmac.sh del <MAC>
#mesh_aclmac.sh flush
#mesh_aclmac.sh show

########### Functions #################
usage() 
{
	echo "Usage: $0 <restore|add <MAC>|del <MAC>|flush|show>"
	echo "Example: $0 show"
}

########### Parser #################
if [ "$1" == "" ] ; then
	usage;
	exit 0;
fi


function list_include_idx {
  local list="$1"
  local idx="$2"
  if [[ $list =~ (^|[ ])"$idx"($|[ ]) ]] ; then
    return 0
  else
    return 1
  fi
}

MacFilterList=`psmcli get eRT.com.cisco.spvtg.ccsp.tr181pa.Device.WiFi.AccessPoint.13.MacFilterList`
count=`echo $MacFilterList | cut -d":" -f1`
list=`echo $MacFilterList | cut -d":" -f2 | tr "," " "`

while : ; do
case $1 in
  allow)
	wifi_api  wifi_setApMacAddressControlMode 12 2
	wifi_api  wifi_setApMacAddressControlMode 13 2
	exit 0;
	shift 1
    ;;
	
  restore)
	#psm --> (cosa_wifi_apis.c will restore) 
	if [ "$count" == "0" ] || [ "$list" == "" ]; then
		exit 0;
	fi
	for idx in $list; do
		mac=`psmcli get eRT.com.cisco.spvtg.ccsp.tr181pa.Device.WiFi.AccessPoint.13.MacFilter.$idx`
		wifi_api wifi_addApAclDevice 12 $mac
		wifi_api wifi_addApAclDevice 13 $mac
	done
	exit 0;
	shift 1
    ;;

  flush)    
	if [ "$count" == "0" ] || [ "$list" == "" ]; then
		exit 0;
	fi
	#clean all in psm 
	#clean all in driver
	for idx in $list; do
		mac=`psmcli get eRT.com.cisco.spvtg.ccsp.tr181pa.Device.WiFi.AccessPoint.13.MacFilter.$idx`
		psmcli del eRT.com.cisco.spvtg.ccsp.tr181pa.Device.WiFi.AccessPoint.13.MacFilter.$idx
		psmcli del eRT.com.cisco.spvtg.ccsp.tr181pa.Device.WiFi.AccessPoint.13.MacFilterDevice.$idx
		psmcli del eRT.com.cisco.spvtg.ccsp.tr181pa.Device.WiFi.AccessPoint.14.MacFilter.$idx
		psmcli del eRT.com.cisco.spvtg.ccsp.tr181pa.Device.WiFi.AccessPoint.14.MacFilterDevice.$idx
		if [ "$mac" != "" ]; then
			wifi_api wifi_delApAclDevice 12 $mac
			wifi_api wifi_delApAclDevice 13 $mac
		fi
	done
	psmcli set eRT.com.cisco.spvtg.ccsp.tr181pa.Device.WiFi.AccessPoint.13.MacFilterList "0:"
	psmcli set eRT.com.cisco.spvtg.ccsp.tr181pa.Device.WiFi.AccessPoint.14.MacFilterList "0:"	
	exit 0;
	shift 1
    ;;
	
  add)
    mac=$2;
	
	for idx in $list; do
		omac=`psmcli get eRT.com.cisco.spvtg.ccsp.tr181pa.Device.WiFi.AccessPoint.13.MacFilter.$idx`
		if [ "$mac" == "$omac" ]; then
			exit 0;
		fi
	done
	newlist="";
	newcount=$((count+1));
	newidx=0;
	#add to psm
	for idx in {1..64}; do
		if [[ $list =~ (^|[ ])"$idx"($|[ ]) ]] ; then			
			continue
		else
			newidx=$idx
			break
		fi	   
	done
	newlist=$list" $newidx"
	newlist="$newcount:"`echo "$newlist" | tr " " "\n" | sort -n | tr "\n" "," | sed -e 's/^[,]*//' -e 's/[,]*$//'`	
	psmcli set eRT.com.cisco.spvtg.ccsp.tr181pa.Device.WiFi.AccessPoint.13.MacFilterList "$newlist"
	psmcli set eRT.com.cisco.spvtg.ccsp.tr181pa.Device.WiFi.AccessPoint.13.MacFilter.$newidx  $mac
	psmcli set eRT.com.cisco.spvtg.ccsp.tr181pa.Device.WiFi.AccessPoint.13.MacFilterDevice.$newidx "mesh backhaul"
	psmcli set eRT.com.cisco.spvtg.ccsp.tr181pa.Device.WiFi.AccessPoint.14.MacFilterList "$newlist"
	psmcli set eRT.com.cisco.spvtg.ccsp.tr181pa.Device.WiFi.AccessPoint.14.MacFilter.$newidx  $mac
	psmcli set eRT.com.cisco.spvtg.ccsp.tr181pa.Device.WiFi.AccessPoint.14.MacFilterDevice.$newidx "mesh backhaul"
	#add to driver
	wifi_api wifi_addApAclDevice 12 $mac
	wifi_api wifi_addApAclDevice 13 $mac
	exit 0;
    shift 2
    ;;
	
  del)
    dmac=$2;
	if [ "$count" == "0" ] || [ "$list" == "" ]; then
		exit 0;
	fi
	for idx in $list; do
		mac=`psmcli get eRT.com.cisco.spvtg.ccsp.tr181pa.Device.WiFi.AccessPoint.13.MacFilter.$idx`
		if [ "$mac" == "$dmac" ]; then
			#del from psm
			psmcli del eRT.com.cisco.spvtg.ccsp.tr181pa.Device.WiFi.AccessPoint.13.MacFilter.$idx
			psmcli del eRT.com.cisco.spvtg.ccsp.tr181pa.Device.WiFi.AccessPoint.13.MacFilterDevice.$idx
			psmcli del eRT.com.cisco.spvtg.ccsp.tr181pa.Device.WiFi.AccessPoint.14.MacFilter.$idx
			psmcli del eRT.com.cisco.spvtg.ccsp.tr181pa.Device.WiFi.AccessPoint.14.MacFilterDevice.$idx	
			newcount=$((count-1));
			newlist="$newcount:"`echo "$list" | tr " " "," | sed -e "s/\<$idx\>//" -e 's/,,/,/' -e 's/^[,]//' -e 's/[,]$//'`
			psmcli set eRT.com.cisco.spvtg.ccsp.tr181pa.Device.WiFi.AccessPoint.13.MacFilterList "$newlist"
			psmcli set eRT.com.cisco.spvtg.ccsp.tr181pa.Device.WiFi.AccessPoint.14.MacFilterList "$newlist"
			#del from driver			
			wifi_api wifi_delApAclDevice 12 $mac
			wifi_api wifi_delApAclDevice 13 $mac
			break
		fi
	done
	exit 0;
    shift 2
    ;;
	
  show)
	#show
	if [ "$count" == "0" ] || [ "$list" == "" ]; then
		exit 0;
	fi
	#dump psm
	for idx in $list; do
		psmcli get eRT.com.cisco.spvtg.ccsp.tr181pa.Device.WiFi.AccessPoint.13.MacFilter.$idx
	done
	exit 0;
    ;;
	
  *)
	usage;
	exit 0;
	;;
esac
done



