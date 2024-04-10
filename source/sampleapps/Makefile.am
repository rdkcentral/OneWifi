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
AM_LDFLAGS = -L$(top_builddir)/source/sysevent/lib
AM_LDFLAGS += -lsysevent
AM_LDFLAGS += -L$(top_builddir)/source/utils/
AM_LDFLAGS += -lwifi_utils
if WITH_LIBWEBCONFIG
AM_LDFLAGS += -L$(top_builddir)/source/webconfig/
endif 
AM_LDFLAGS += -lwifi_webconfig


AM_CPPFLAGS = -Wall -Werror
ACLOCAL_AMFLAGS = -I m4
hardware_platform = i686-linux-gnu

bin_PROGRAMS = onewifi_component_test_app
onewifi_component_test_app_CPPFLAGS = $(CPPFLAGS)  -I$(top_srcdir)/./include -I${PKG_CONFIG_SYSROOT_DIR}$(includedir)/rbus -I$(top_srcdir)/../hal/include -I$(top_srcdir)/source/dml/tr_181/sbapi -I$(top_srcdir)/source/core -I$(top_srcdir)/source/stats -I$(top_srcdir)/source/utils -I$(top_srcdir)/source/core -I$(top_srcdir)/source/db -I$(top_srcdir)/source/dml/wifi_ssp -I$(top_srcdir)/./include -I$(top_srcdir)/./lib/ovsdb -I$(top_srcdir)/./lib/ds -I$(top_srcdir)/lib/common -I$(top_srcdir)/lib/pjs -I$(top_srcdir)/lib/log -I$(top_srcdir)/lib/const -I$(top_srcdir)/lib/schema -I$(top_srcdir)/lib/osp -I$(top_srcdir)/lib/osa -I$(top_srcdir)/lib/psfs -I$(top_srcdir)/lib/qm -I$(top_srcdir)/./lib/json_util/ -I$(top_srcdir)/source/dml/dml_webconfig -I$(top_srcdir)/source/core/services -I$(top_srcdir)/source/apps  -I$(top_srcdir)/source/apps/analytics -I$(top_srcdir)/source/apps/levl -I$(top_srcdir)/source/apps/cac -I$(top_srcdir)/source/apps/sm -I$(top_srcdir)/source/apps/motion -I$(top_srcdir)/source/apps/csi -I$(top_srcdir)/source/apps/whix -I$(top_srcdir)/source/apps/harvester -I$(top_srcdir)/source/apps/blaster -I$(top_srcdir)/source/apps/ocs

onewifi_component_test_app_SOURCES = wifi_webconfig_consumer.c webconfig_consumer_apis.c webconfig_consumer_cli.c

onewifi_component_test_app_SOURCES += $(top_srcdir)/source/utils/collection.c $(top_srcdir)/source/utils/scheduler.c

onewifi_component_test_app_LDFLAGS = -lsysevent -lrbus
onewifi_component_test_app_LDFLAGS += -L$(top_builddir)/source/utils/
onewifi_component_test_app_LDFLAGS += -lwifi_utils
if WITH_LIBWEBCONFIG
onewifi_component_test_app_LDFLAGS += -L$(top_builddir)/source/webconfig/
endif
onewifi_component_test_app_LDFLAGS += -lwifi_webconfig
onewifi_component_test_app_CPPFLAGS += -I${PKG_CONFIG_SYSROOT_DIR}${includedir}/opensync_headers

onewifi_component_test_app_CFLAGS = $(DML_ENABLE_FLAG)
onewifi_component_test_app_CFLAGS += $(CCSP_COMMON_FLAG)
onewifi_component_test_app_CFLAGS += $(JOURNALCTL_ENABLE_FLAG)

bin_PROGRAMS += wifi_events_consumer
wifi_events_consumer_CPPFLAGS = $(CPPFLAGS)  -I$(top_srcdir)/./include -I${PKG_CONFIG_SYSROOT_DIR}$(includedir)/rbus -I$(top_srcdir)/../hal/include -I$(top_srcdir)/source/TR-181/sbapi  -I$(top_srcdir)/source/TR-181/lib/common -I$(top_srcdir)/source/stats
wifi_events_consumer_SOURCES = wifievents_consumer_sample.c
wifi_events_consumer_LDFLAGS = -lsysevent -lrbus

