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

if !HAL_IPC
AM_LDFLAGS += -lhal_wifi
endif

AM_LDFLAGS += -lwebconfig_framework
AM_LDFLAGS += -lsecure_wrapper
AM_LDFLAGS += -lev
AM_LDFLAGS += -lpthread
AM_LDFLAGS += -ldl
AM_LDFLAGS += -ljansson
AM_LDFLAGS += -lrt
if CCSP_COMMON_SUPPORT
AM_LDFLAGS += -L$(top_builddir)/../CcspCommonLibrary/lib
AM_LDFLAGS += -lccsp_common
AM_LDFLAGS += -lrdk_wifihal
endif

AM_CPPFLAGS = -Wall -Werror
ACLOCAL_AMFLAGS = -I m4
hardware_platform = i686-linux-gnu

lib_LTLIBRARIES=libwifi_utils.la

libwifi_utils_la_CPPFLAGS = -I/var/tmp/pc-rdkb/include/dbus-1.0 -I$(top_srcdir)/../CcspCommonLibrary/source/ccsp/custom -I$(top_srcdir)/../CcspCommonLibrary/source/ccsp/include -I$(top_srcdir)/../CcspCommonLibrary/source/debug_api/include -I$(top_srcdir)/../CcspCommonLibrary/source/cosa/include -I$(top_srcdir)/../CcspCommonLibrary/source/cosa/include/linux -I$(top_srcdir)/../CcspCommonLibrary/source/ccsp/components/include -I$(top_srcdir)/../CcspCommonLibrary/source/cosa/package/slap/include -I$(top_srcdir)/../hal/include -I$(top_srcdir)/../CcspCommonLibrary/source/util_api/http/include -I$(top_srcdir)/../CcspCommonLibrary/source/util_api/ansc/include  -I$(top_srcdir)/source/dml/wifi_ssp -I$(top_srcdir)/source/dml/dml_webconfig -I$(top_srcdir)/source/dml/tr_181/ml -I$(top_srcdir)/source/dml/tr_181/sbapi -I$(top_srcdir)/include/tr_181/ml -I$(top_srcdir)/../CcspCommonLibrary/source/ccsp/components/common/MessageBusHelper/include -I$(top_srcdir)/../CcspCommonLibrary/source/ccsp/components/common/PoamIrepFolder -I$(top_srcdir)/include/wifi_ssp -I$(top_srcdir)/./include -I$(top_srcdir)/source/core -I$(top_srcdir)/source/stats -I$(top_srcdir)/source/db -I$(top_srcdir)/lib/ovsdb -I$(top_srcdir)/lib/inc -I$(top_srcdir)/lib/json_util -I$(top_srcdir)/lib/ds -I$(top_srcdir)/lib/common -I$(top_srcdir)/lib/pjs -I$(top_srcdir)/lib/log -I$(top_srcdir)/lib/const -I$(top_srcdir)/lib/schema -I$(top_srcdir)/lib/osp -I$(top_srcdir)/lib/osa -I$(top_srcdir)/lib/psfs -I$(top_srcdir)/lib/qm -I$(top_srcdir)/source/core/services -I$(top_srcdir)/source/apps  -I$(top_srcdir)/source/apps/analytics -I$(top_srcdir)/source/apps/levl -I$(top_srcdir)/source/apps/cac -I$(top_srcdir)/source/apps/sm -I$(top_srcdir)/source/apps/motion -I$(top_srcdir)/source/apps/csi -I$(top_srcdir)/source/apps/whix -I$(top_srcdir)/source/apps/harvester -I$(top_srcdir)/source/apps/blaster -I$(top_srcdir)/source/apps/ocs $(CPPFLAGS)

libwifi_utils_la_CFLAGS =  $(SYSTEMD_CFLAGS)
libwifi_utils_la_CFLAGS += $(DML_ENABLE_FLAG)
libwifi_utils_la_CFLAGS += $(CCSP_COMMON_FLAG)
libwifi_utils_la_SOURCES = wifi_validator.c
libwifi_utils_la_SOURCES += ext_blaster.pb-c.c


libwifi_utils_la_LDFLAGS = -rdynamic -lwebconfig_framework -lsecure_wrapper $(SYSTEMD_LDFLAGS) -lsecure_wrapper -lmsgpackc -lcjson -lm -ljansson -static

if CCSP_COMMON_SUPPORT
libwifi_utils_la_LDFLAGS += -lccsp_common -lsyscfg -lprint_uptime -lsysevent -lrdk_wifihal

if !HAL_IPC
libwifi_utils_la_LDFLAGS += -lhal_wifi
endif

endif #CCSP_COMMON_SUPPORT

libwifi_utils_la_CPPFLAGS += -I${PKG_CONFIG_SYSROOT_DIR}${includedir}/rdk-wifi-libhostap/ -I${PKG_CONFIG_SYSROOT_DIR}${includedir}/rdk-wifi-libhostap/src/ -I${PKG_CONFIG_SYSROOT_DIR}${includedir}/rdk-wifi-libhostap/src/ap -I${PKG_CONFIG_SYSROOT_DIR}${includedir}/rdk-wifi-libhostap/src/utils -I${PKG_CONFIG_SYSROOT_DIR}${includedir}/rdk-wifi-libhostap/src/drivers/ -I$(PKG_CONFIG_SYSROOT_DIR)$(includedir)/qca/qca-wifi/os/linux/include/ -I${PKG_CONFIG_SYSROOT_DIR}${libdir}/ -DEXTERNAL_USE_ONLY

AM_CFLAGS += -DCONFIG_WPS -DCONFIG_IEEE80211R_AP -DCONFIG_IEEE80211R -DCONFIG_ETH_P_OUI -DCONFIG_IEEE80211W
AM_CFLAGS += -DEAP_SERVER_FAST

include_HEADERS =  wifi_validator.h ext_blaster.pb-c.h

bin_PROGRAMS = wifi_db_ovsh
wifi_db_ovsh_SOURCES = ovsh.c
wifi_db_ovsh_LDFLAGS = -ljansson
wifi_db_ovsh_CPPFLAGS = -I$(top_srcdir)/lib/ovsdb -I$(top_srcdir)/lib/common -I$(top_srcdir)/lib/osa -I$(top_srcdir)/lib/ds -I$(top_srcdir)/lib/pjs -I$(top_srcdir)/lib/json_util -I$(top_srcdir)/lib/schema -I$(top_srcdir)/lib/const -I$(top_srcdir)/lib/log -I$(top_srcdir)/lib/inc
