#!/bin/sh
LOG_FILE="/rdklogs/logs/wifi_selfheal.txt"
MODEL_NUM=`grep MODEL_NUM /etc/device.properties | cut -d "=" -f2`

if [ "$MODEL_NUM" == "CGM4981COM" ] || [ "$MODEL_NUM" == "CGM4331COM" ] || [ "${MODEL_NUM}" = "CGM601TCOM" ] || [ "${MODEL_NUM}" = "SG417DBCT" ]; then
    for i in 0 1
    do
        ifconfig wl"$i" down
        for j in 1 2 3 4 5 6 7
        do
            ifconfig wl"$i"."$j" down
        done
    done
    echo "all vaps are going to down state..." >> $LOG_FILE
fi

if [ "$MODEL_NUM" == "CGM4981COM" ] || [ "${MODEL_NUM}" = "CGM601TCOM" ] || [ "${MODEL_NUM}" = "SG417DBCT" ]; then
    for i in 2
    do
        ifconfig wl"$i" down
        for j in 1 2 3 4 5 6 7
        do
            ifconfig wl"$i"."$j" down
        done
        echo "third radio vaps are going to down state"
    done
fi

if [ "$MODEL_NUM" == "TG4482A" ]; then
    for i in 0 2
    do
        for j in 0 1 2 3 4 5 6
        do
            ifconfig wlan"$i"."$j" down
        done
    done

    for i in 1 3
    do
        ifconfig wlan"$i" down
    done

    echo "all vaps are going to down state..." >> $LOG_FILE
fi
