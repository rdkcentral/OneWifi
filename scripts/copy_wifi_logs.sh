/usr/ccsp/wifi/wifi_db_ovsh s Wifi_Radio_Config -c > /tmp/wifidb_data
/usr/ccsp/wifi/wifi_db_ovsh s Wifi_Rfc_Config -c >> /tmp/wifidb_data
/usr/ccsp/wifi/wifi_db_ovsh s Wifi_VAP_Config -c >> /tmp/wifidb_data
/usr/ccsp/wifi/wifi_db_ovsh s Wifi_Interworking_Config -c >> /tmp/wifidb_data
/usr/ccsp/wifi/wifi_db_ovsh s Wifi_Security_Config -c >> /tmp/wifidb_data
/usr/ccsp/wifi/wifi_db_ovsh s Wifi_MacFilter_Config -c >> /tmp/wifidb_data

if [ -f /tmp/wifiCtrl ]; then
    cat  /tmp/wifiCtrl >> /rdklogs/logs/wifiCtrl && echo -n "" >/tmp/wifiCtrl
fi

if [ -f /tmp/wifiDMCLI ]; then
    cat /tmp/wifiDMCLI >> /rdklogs/logs/wifiDMCLI && echo -n "" >/tmp/wifiDMCLI
fi

if [ -f /tmp/wifiDb ]; then
    cat  /tmp/wifiDb >> /rdklogs/logs/wifiDb && echo -n "" >/tmp/wifiDb
fi

if [ -f /tmp/wifiHal ]; then
    cat /tmp/wifiHal>> /rdklogs/logs/wifiHal && echo -n "" >/tmp/wifiHal
fi

if [ -f /tmp/wifiMgr ]; then
	cat /tmp/wifiMgr >>/rdklogs/logs/wifiMgr && echo -n "" >/tmp/wifiMgr
fi

if [ -f /tmp/wifiMon ]; then
    cat /tmp/wifiMon >> /rdklogs/logs/wifiMon && echo -n "" >/tmp/wifiMon
fi

if [ -f /tmp/wifiPasspoint ]; then
    cat /tmp/wifiPasspoint >>/rdklogs/logs/wifiPasspoint && echo -n "" >/tmp/wifiPasspoint
fi

if [ -f /tmp/wifiPsm ]; then
    cat /tmp/wifiPsm >> /rdklogs/logs/wifiPsm && echo -n "" >/tmp/wifiPsm
fi

if [ -f /tmp/wifiWebConfig ]; then
    cat /tmp/wifiWebConfig >> /rdklogs/logs/wifiWebConfig && echo -n "" >/tmp/wifiWebConfig
fi

if [ -f /tmp/wifilibhostap ]; then
    cat /tmp/wifilibhostap >> /rdklogs/logs/wifilibhostap && echo -n "" >/tmp/wifilibhostap
fi

if [ -f /tmp/wifiLib ]; then
    cat /tmp/wifiLib >> /rdklogs/logs/wifiLib && echo -n "" >/tmp/wifiLib
fi
if [ -f /tmp/wifiDPP ]; then
    cat /tmp/wifiwifiDPP >> /rdklogs/logs/wifiDPP && echo -n "" >/tmp/wifiDPP
fi
if [ -f /tmp/wifidb_data ]; then
    cat /tmp/wifidb_data >> /rdklogs/logs/wifidb_data && echo -n "" >/tmp/wifidb_data
fi
echo "copied files from /tmp/ to /rdklogs/logs and made tmp logs empty"
