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

#zhicheng_qiu@comcast.com
#this script is for Puma6 platform only

ap_addr() {
    if [ "$2" ]; then
        NM="$2"
    else
        NM="255.255.255.0"
    fi
    if [ "$1" ]; then
        IP="$1"
    else
        IP="255.253.252.100"
    fi
    #
    n="${NM%.*}";m="${NM##*.}"
    l="${IP%.*}";r="${IP##*.}";c=""
    if [ "$m" = "0" ]; then
        c=".254"
        m="${n##*.}";n="${n%.*}"
        r="${l##*.}";l="${l%.*}"
        if [ "$m" = "0" ]; then
            c=".255$c"
            m="${n##*.}";n="${n%.*}"
            r="${l##*.}";l="${l%.*}"
            if [ "$m" = "0" ]; then
                c=".255$c"
                m=$n
                r=$l;l=""
            fi
        fi
    else
        let m=$m+1
    fi
    let s=256-$m
    let r=$r/$s*$s
    let r=$r+$s-1
    if [ "$l" ]; then
        SNW="$l.$r$c"
    else
        SNW="$r$c"
    fi

    echo $SNW
}

if [ "$2" != "" ] ; then
	ip=$1;
	mask=$2;
else
    eval "`psmcli get -e gw_ip dmsb.l3net.4.V4Addr mask dmsb.l3net.4.V4SubnetMask`"
    ip="`ap_addr $gw_ip $mask`"
fi

net=`echo $ip | cut -d"." -f1,2,3`.0
if [ "$mask" == "255.255.255.128" ]; then
	nmask=25;
elif [ "$mask" == "255.255.0.0" ]; then
	nmask=16;
elif [ "$mask" == "255.0.0.0" ]; then
	nmask=8;
else
	nmask=24;
fi

ifconfig br0 $ip netmask $mask up
ip route add table main  $net/$nmask dev br0  proto kernel  scope link  src $ip
ip route add table local local $ip dev br0  proto kernel  scope host  src $ip
ip route del 224.0.0.0/4 dev eth0
ip route add 224.0.0.0/4 dev br0
iptables -F
iptables -I INPUT -i br0 ! -d $ip -j DROP

#DNS
#rpcclient $ARM_ARPING_IP "cat /etc/resolv.conf" | grep nameserver | grep -v 127.0.0.1 > /etc/resolv.conf

