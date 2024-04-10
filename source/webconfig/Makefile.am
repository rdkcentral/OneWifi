##########################################################################
# If not stated otherwise in this file or this component's LICENSE
# file the following copyright and licenses apply:
#
# Copyright 2015 RDK Management
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
if LIBWEBCONFIG
AM_CFLAGS = -D_ANSC_LINUX
AM_CFLAGS += -D_ANSC_USER
if CCSP_ARCH_ARM
AM_CFLAGS += -D_ANSC_LITTLE_ENDIAN_
endif

if CCSP_ARCH_ATOM
AM_CFLAGS += -D_ANSC_LITTLE_ENDIAN_
endif

if CCSP_ARCH_PC
AM_CFLAGS += -D_ANSC_LITTLE_ENDIAN_
endif

AM_LDFLAGS =  -L$(top_builddir)/../hal/lib
AM_LDFLAGS += -lwebconfig_framework
AM_LDFLAGS += -lsecure_wrapper
AM_LDFLAGS += -lev
AM_LDFLAGS += -lpthread
AM_LDFLAGS += -ldl
AM_LDFLAGS += -ljansson
AM_LDFLAGS += -lrt
if CCSP_COMMON_SUPPORT

if !HAL_IPC
AM_LDFLAGS += -lhal_wifi
endif

AM_LDFLAGS += -L$(top_builddir)/../CcspCommonLibrary/lib
AM_LDFLAGS += -lccsp_common
AM_LDFLAGS += -lrdk_wifihal
endif #CCSP_COMMON_SUPPORT

AM_CPPFLAGS = -Wall -Werror
ACLOCAL_AMFLAGS = -I m4
hardware_platform = i686-linux-gnu

lib_LTLIBRARIES=libwifi_webconfig.la

libwifi_webconfig_la_CPPFLAGS = -I/var/tmp/pc-rdkb/include/dbus-1.0 -I$(top_srcdir)/../CcspCommonLibrary/source/ccsp/custom -I$(top_srcdir)/../CcspCommonLibrary/source/ccsp/include -I$(top_srcdir)/../CcspCommonLibrary/source/debug_api/include -I$(top_srcdir)/../CcspCommonLibrary/source/cosa/include -I$(top_srcdir)/../CcspCommonLibrary/source/cosa/include/linux -I$(top_srcdir)/../CcspCommonLibrary/source/ccsp/components/include -I$(top_srcdir)/../CcspCommonLibrary/source/cosa/package/slap/include -I$(top_srcdir)/../hal/include -I$(top_srcdir)/../CcspCommonLibrary/source/util_api/http/include -I$(top_srcdir)/../CcspCommonLibrary/source/util_api/ansc/include -I$(top_srcdir)/../CcspCommonLibrary/source/ccsp/components/common/MessageBusHelper/include -I$(top_srcdir)/../CcspCommonLibrary/source/ccsp/components/common/PoamIrepFolder -I$(top_srcdir)/include/wifi_ssp -I$(top_srcdir)/./include -I$(top_srcdir)/source/core -I$(top_srcdir)/source/stats -I$(top_srcdir)/source/db -I$(top_srcdir)/lib/ovsdb -I$(top_srcdir)/lib/json_util -I$(top_srcdir)/lib/ds -I$(top_srcdir)/lib/common -I$(top_srcdir)/lib/pjs -I$(top_srcdir)/lib/log -I$(top_srcdir)/lib/const -I$(top_srcdir)/lib/schema -I$(top_srcdir)/lib/osp -I$(top_srcdir)/lib/osa -I$(top_srcdir)/lib/psfs -I$(top_srcdir)/lib/qm -I$(top_srcdir)/source/utils -I$(top_srcdir)/source/core/services -I$(top_srcdir)/source/apps  -I$(top_srcdir)/source/apps/analytics -I$(top_srcdir)/source/apps/levl -I$(top_srcdir)/source/apps/cac -I$(top_srcdir)/source/apps/sm -I$(top_srcdir)/source/apps/csi -I$(top_srcdir)/source/apps/motion -I$(top_srcdir)/source/apps/whix -I$(top_srcdir)/source/apps/harvester -I$(top_srcdir)/source/apps/blaster -I$(top_srcdir)/source/apps/ocs $(CPPFLAGS)

if ONEWIFI_DML_SUPPORT
libwifi_webconfig_la_CPPFLAGS += -I$(top_srcdir)/source/dml/wifi_ssp -I$(top_srcdir)/source/dml/tr_181/ml -I$(top_srcdir)/source/dml/tr_181/sbapi -I$(top_srcdir)/include/tr_181/ml
endif

libwifi_webconfig_la_CFLAGS =  $(SYSTEMD_CFLAGS)
libwifi_webconfig_la_CFLAGS += $(DML_ENABLE_FLAG)
libwifi_webconfig_la_CFLAGS += $(CCSP_COMMON_FLAG)

libwifi_webconfig_la_SOURCES = wifi_webconfig.c wifi_encoder.c wifi_decoder.c wifi_ovsdb_translator.c  wifi_webconfig_home.c wifi_webconfig_mesh.c wifi_webconfig_private.c wifi_webconfig_radio.c  wifi_webconfig_xfinity.c wifi_webconfig_associated_client.c wifi_webconfig_wifiapi_radio.c wifi_webconfig_wifiapi_vap.c wifi_webconfig_macfilter.c wifi_webconfig_blaster.c wifi_webconfig_harvester.c wifi_webconfig_wifi_config.c wifi_webconfig_csi.c wifi_webconfig_mesh_sta.c wifi_webconfig_mesh_backhaul.c wifi_webconfig_null.c wifi_webconfig_stats_config.c wifi_webconfig_steering_config.c wifi_webconfig_steering_clients.c wifi_webconfig_lnf.c wifi_webconfig_vif_neighbors.c wifi_webconfig_mesh_backhaul_sta.c wifi_webconfig_dml.c wifi_webconfig_levl.c wifi_webconfig_cac.c

libwifi_webconfig_la_SOURCES +=  $(top_srcdir)/lib/common/util.c $(top_srcdir)/source/utils/wifi_util.c $(top_srcdir)/source/utils/collection.c

libwifi_webconfig_la_LDFLAGS = -rdynamic -lwebconfig_framework -lsecure_wrapper $(SYSTEMD_LDFLAGS) -lsecure_wrapper -lmsgpackc -lcjson -lm -ljansson -lssl -lcrypto -shared

libwifi_webconfig_la_CPPFLAGS += -I${PKG_CONFIG_SYSROOT_DIR}${includedir}/rdk-wifi-libhostap/ -I${PKG_CONFIG_SYSROOT_DIR}${includedir}/rdk-wifi-libhostap/src/ -I${PKG_CONFIG_SYSROOT_DIR}${includedir}/rdk-wifi-libhostap/src/ap -I${PKG_CONFIG_SYSROOT_DIR}${includedir}/rdk-wifi-libhostap/src/utils -I${PKG_CONFIG_SYSROOT_DIR}${includedir}/rdk-wifi-libhostap/src/drivers/ -I$(PKG_CONFIG_SYSROOT_DIR)$(includedir)/qca/qca-wifi/os/linux/include/ -I${PKG_CONFIG_SYSROOT_DIR}${libdir}/ -DEXTERNAL_USE_ONLY

libwifi_webconfig_la_CPPFLAGS += -I${PKG_CONFIG_SYSROOT_DIR}${includedir}/opensync_headers

AM_CFLAGS += -DCONFIG_WPS -DCONFIG_IEEE80211R_AP -DCONFIG_IEEE80211R -DCONFIG_ETH_P_OUI -DCONFIG_IEEE80211W
AM_CFLAGS += -DEAP_SERVER_FAST

include_HEADERS =  $(top_srcdir)/source/utils/wifi_util.h
endif
