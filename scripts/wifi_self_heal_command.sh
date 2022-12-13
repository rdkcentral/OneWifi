
if [ `LTime H | sed 's/^0*//'` == 2 ]; then
	echo "executed wifi_self_heal_command.sh" >>/rdklogs/logs/wifiDMCLI.txt
	dmcli eRT setv Device.WiFi.AccessPoint.1.X_CISCO_COM_BssMaxNumSta int 100
	dmcli eRT setv Device.WiFi.AccessPoint.2.X_CISCO_COM_BssMaxNumSta int 100
	dmcli eRT setv Device.WiFi.AccessPoint.3.X_CISCO_COM_BssMaxNumSta int 100
	dmcli eRT setv Device.WiFi.AccessPoint.4.X_CISCO_COM_BssMaxNumSta int 100
	dmcli eRT setv Device.WiFi.ApplyAccessPointSettings bool true
fi

