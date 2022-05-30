##########################################################################
# If not stated otherwise in this file or this component's Licenses.txt
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

AM_LDFLAGS = -L$(top_builddir)/../CcspCommonLibrary/lib
AM_LDFLAGS += -lccsp_common
AM_LDFLAGS += -L$(top_builddir)/../hal/lib
AM_LDFLAGS += -lrdk_wifihal -lhal_wifi
AM_LDFLAGS += -lwebconfig_framework
AM_LDFLAGS += -lsecure_wrapper
AM_LDFLAGS += -lev
AM_LDFLAGS += -lpthread
AM_LDFLAGS += -ldl
AM_LDFLAGS += -ljansson
AM_LDFLAGS += -lrt

AM_CPPFLAGS = -Wall -Werror
ACLOCAL_AMFLAGS = -I m4
hardware_platform = i686-linux-gnu

lib_LTLIBRARIES=libwifi_utils.la

libwifi_utils_la_CPPFLAGS = -I/var/tmp/pc-rdkb/include/dbus-1.0 -I$(top_srcdir)/../CcspCommonLibrary/source/ccsp/custom -I$(top_srcdir)/../CcspCommonLibrary/source/ccsp/include -I$(top_srcdir)/../CcspCommonLibrary/source/debug_api/include -I$(top_srcdir)/../CcspCommonLibrary/source/cosa/include -I$(top_srcdir)/../CcspCommonLibrary/source/cosa/include/linux -I$(top_srcdir)/../CcspCommonLibrary/source/ccsp/components/include -I$(top_srcdir)/../CcspCommonLibrary/source/cosa/package/slap/include -I$(top_srcdir)/../hal/include -I$(top_srcdir)/../CcspCommonLibrary/source/util_api/http/include -I$(top_srcdir)/../CcspCommonLibrary/source/util_api/ansc/include  -I$(top_srcdir)/source/dml/wifi_ssp -I$(top_srcdir)/source/dml/dml_webconfig -I$(top_srcdir)/source/dml/tr_181/ml -I$(top_srcdir)/source/dml/tr_181/sbapi -I$(top_srcdir)/include/tr_181/ml -I$(top_srcdir)/../CcspCommonLibrary/source/ccsp/components/common/MessageBusHelper/include -I$(top_srcdir)/../CcspCommonLibrary/source/ccsp/components/common/PoamIrepFolder -I$(top_srcdir)/include/wifi_ssp -I$(top_srcdir)/./include -I$(top_srcdir)/source/core -I$(top_srcdir)/source/stats -I$(top_srcdir)/source/db -I$(top_srcdir)/lib/ovsdb -I$(top_srcdir)/lib/inc -I$(top_srcdir)/lib/json_util -I$(top_srcdir)/lib/ds -I$(top_srcdir)/lib/common -I$(top_srcdir)/lib/pjs -I$(top_srcdir)/lib/log -I$(top_srcdir)/lib/const -I$(top_srcdir)/lib/schema -I$(top_srcdir)/lib/osp -I$(top_srcdir)/lib/osa -I$(top_srcdir)/lib/psfs -I$(top_srcdir)/lib/qm -I$(top_srcdir)/source/core/services $(CPPFLAGS)
libwifi_utils_la_CFLAGS =  $(SYSTEMD_CFLAGS)

libwifi_utils_la_SOURCES = wifi_validator.c

libwifi_utils_la_LDFLAGS = -lccsp_common -rdynamic -lsyscfg -lwebconfig_framework -lprint_uptime -lsecure_wrapper $(SYSTEMD_LDFLAGS) -lsecure_wrapper -lsysevent -lmsgpackc -lcjson -lrdk_wifihal -lhal_wifi -lm -ljansson -static

libwifi_utils_la_CPPFLAGS += -I${PKG_CONFIG_SYSROOT_DIR}${includedir}/rdk-wifi-libhostap/ -I${PKG_CONFIG_SYSROOT_DIR}${includedir}/rdk-wifi-libhostap/src/ -I${PKG_CONFIG_SYSROOT_DIR}${includedir}/rdk-wifi-libhostap/src/ap -I${PKG_CONFIG_SYSROOT_DIR}${includedir}/rdk-wifi-libhostap/src/utils -I${PKG_CONFIG_SYSROOT_DIR}${includedir}/rdk-wifi-libhostap/src/drivers/ -I$(PKG_CONFIG_SYSROOT_DIR)$(includedir)/qca/qca-wifi/os/linux/include/ -I${PKG_CONFIG_SYSROOT_DIR}${libdir}/ -DEXTERNAL_USE_ONLY

AM_CFLAGS += -DCONFIG_WPS -DCONFIG_IEEE80211R_AP -DCONFIG_IEEE80211R -DCONFIG_ETH_P_OUI -DCONFIG_IEEE80211W
AM_CFLAGS += -DEAP_SERVER_FAST

include_HEADERS =  wifi_validator.h
