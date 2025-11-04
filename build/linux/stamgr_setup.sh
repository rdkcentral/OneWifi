#!/bin/sh

ONEWIFI_DIR=$(pwd)
STA_MGR_DIR="$(pwd)/../WiFiStaManager"

cd ..
git clone -b 25Q3_sprint https://gerrit.teamccp.com/rdk/rdkb/components/opensource/ccsp/WiFiStaManager/generic WiFiStaManager
if [ -d "$STA_MGR_DIR" ]; then
       echo "copying sta_mgr..."
       mv -r $STA_MGR_DIR/* $ONEWIFI_DIR/source/apps/sta_mgr
fi

#return back to initial directory
cd $ONEWIFI_DIR
