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
if CCSP_COMMON_SUPPORT
if !HAL_IPC
AM_LDFLAGS += -lhal_wifi
endif
endif
AM_LDFLAGS += -lwebconfig_framework
AM_LDFLAGS += -lsecure_wrapper
AM_LDFLAGS += -lev
AM_LDFLAGS += -lpthread
AM_LDFLAGS += -ldl
AM_LDFLAGS += -ljansson
AM_LDFLAGS += -lrt
AM_LDFLAGS += -L$(top_builddir)/source/utils/
AM_LDFLAGS += -lwifi_utils
if WITH_LIBWEBCONFIG
AM_LDFLAGS += -L$(top_builddir)/source/webconfig/
endif
AM_LDFLAGS += -lwifi_webconfig
if CCSP_COMMON_SUPPORT
AM_LDFLAGS += -L$(top_builddir)/../CcspCommonLibrary/lib
AM_LDFLAGS += -lccsp_common
AM_LDFLAGS += -lrdk_wifihal
else
AM_LDFLAGS += -lcjson
endif

AM_CPPFLAGS = -Wall -Werror

ACLOCAL_AMFLAGS = -I m4
hardware_platform = i686-linux-gnu
bin_PROGRAMS = OneWifi

OneWifi_CPPFLAGS = -I/var/tmp/pc-rdkb/include/dbus-1.0 -I$(top_srcdir)/../CcspCommonLibrary/source/ccsp/custom -I$(top_srcdir)/../CcspCommonLibrary/source/ccsp/include -I$(top_srcdir)/../CcspCommonLibrary/source/debug_api/include -I$(top_srcdir)/../CcspCommonLibrary/source/cosa/include -I$(top_srcdir)/../CcspCommonLibrary/source/cosa/include/linux -I$(top_srcdir)/../CcspCommonLibrary/source/ccsp/components/include -I$(top_srcdir)/../CcspCommonLibrary/source/cosa/package/slap/include -I$(top_srcdir)/../hal/include -I$(top_srcdir)/../CcspCommonLibrary/source/util_api/http/include -I$(top_srcdir)/../CcspCommonLibrary/source/util_api/ansc/include -I$(top_srcdir)/../CcspCommonLibrary/source/ccsp/components/common/MessageBusHelper/include -I$(top_srcdir)/../CcspCommonLibrary/source/ccsp/components/common/PoamIrepFolder -I$(top_srcdir)/include/wifi_ssp -I$(top_srcdir)/./include -I$(top_srcdir)/source/core -I$(top_srcdir)/source/db -I$(top_srcdir)/lib/ovsdb -I$(top_srcdir)/lib/inc -I$(top_srcdir)/lib/json_util -I$(top_srcdir)/lib/ds -I$(top_srcdir)/lib/common -I$(top_srcdir)/lib/pjs -I$(top_srcdir)/lib/log -I$(top_srcdir)/lib/const -I$(top_srcdir)/lib/schema -I$(top_srcdir)/lib/osp -I$(top_srcdir)/lib/osa -I$(top_srcdir)/lib/psfs -I$(top_srcdir)/lib/qm -I$(top_srcdir)/source/utils -I$(top_srcdir)/source/core/services -I$(top_srcdir)/source/stats -I$(top_srcdir)/lib/pktgen -I$(top_srcdir)/source/stubs -I$(top_srcdir)/lib/datapipeline $(CPPFLAGS)

if ONEWIFI_DML_SUPPORT
OneWifi_CPPFLAGS += -I$(top_srcdir)/source/dml/wifi_ssp -I$(top_srcdir)/source/dml/dml_webconfig -I$(top_srcdir)/source/dml/tr_181/ml -I$(top_srcdir)/source/dml/tr_181/sbapi -I$(top_srcdir)/include/tr_181/ml -I$(top_srcdir)/source/apps  -I$(top_srcdir)/source/apps/analytics -I$(top_srcdir)/source/apps/levl -I$(top_srcdir)/source/apps/sm -I$(top_srcdir)/source/apps/csi -I$(top_srcdir)/source/apps/motion -I$(top_srcdir)/source/apps/whix  -I$(top_srcdir)/source/apps/harvester -I$(top_srcdir)/source/apps/blaster -I$(top_srcdir)/source/apps/ocs 
else
OneWifi_CPPFLAGS += -I$(top_srcdir)/source/apps -I$(top_srcdir)/source/apps/blaster
endif

OneWifi_CFLAGS =  $(SYSTEMD_CFLAGS)
OneWifi_CFLAGS += $(DML_ENABLE_FLAG)
OneWifi_CFLAGS += $(CCSP_COMMON_FLAG)
OneWifi_CFLAGS += $(JOURNALCTL_ENABLE_FLAG)
OneWifi_CFLAGS += $(SM_APP_FLAG)
OneWifi_CFLAGS += -I${PKG_CONFIG_SYSROOT_DIR}/usr/include/protobuf-c

OneWifi_SOURCES = wifi_mgr.c wifi_ctrl.c wifi_passpoint.c wifi_8021x.c wifi_data_plane.c wifi_ctrl_queue_handlers.c wifi_ctrl_rbus_handlers.c wifi_ctrl_webconfig.c wifi_ctrl_wifiapi_handlers.c

OneWifi_SOURCES += $(top_srcdir)/source/db/wifi_db.c $(top_srcdir)/source/db/wifi_db_apis.c

OneWifi_SOURCES += $(top_srcdir)/source/core/services/vap_svc.c  $(top_srcdir)/source/core/services/vap_svc_mesh_gw.c $(top_srcdir)/source/core/services/vap_svc_private.c $(top_srcdir)/source/core/services/vap_svc_public.c $(top_srcdir)/source/core/wifi_events.c

if CCSP_COMMON_SUPPORT
OneWifi_SOURCES += $(top_srcdir)/source/core/services/vap_svc_mesh_ext.c
endif

OneWifi_SOURCES += $(top_srcdir)/source/utils/jsonconv.c $(top_srcdir)/source/utils/collection.c $(top_srcdir)/source/utils/scheduler.c $(top_srcdir)/source/utils/caps.c
OneWifi_SOURCES += $(top_srcdir)/source/stats/wifi_monitor.c $(top_srcdir)/source/utils/ext_blaster.pb-c.c $(top_srcdir)/source/stats/wifi_stats.c $(top_srcdir)/source/stats/wifi_stats_radio_channel.c $(top_srcdir)/source/stats/wifi_stats_neighbor_report.c $(top_srcdir)/source/stats/wifi_stats_radio_diagnostics.c $(top_srcdir)/source/stats/wifi_stats_assoc_client.c $(top_srcdir)/source/stats/wifi_stats_radio_temperature.c

OneWifi_SOURCES += $(top_srcdir)/source/stubs/wifi_stubs.c

if CCSP_COMMON_SUPPORT
OneWifi_SOURCES += wifi_easy_connect.c
OneWifi_SOURCES += $(top_srcdir)/source/stats/wifi_associated_devices_msmt.c
OneWifi_SOURCES += $(top_srcdir)/lib/log/log_journal.c
OneWifi_SOURCES += $(top_srcdir)/source/apps/wifi_apps.c $(top_srcdir)/source/apps/wifi_apps_mgr.c $(top_srcdir)/source/apps/analytics/wifi_analytics.c $(top_srcdir)/source/apps/levl/wifi_levl.c $(top_srcdir)/source/apps/csi/wifi_csi.c $(top_srcdir)/source/apps/motion/wifi_motion.c $(top_srcdir)/source/apps/whix/wifi_whix.c $(top_srcdir)/source/apps/harvester/wifi_harvester.c  $(top_srcdir)/source/apps/blaster/wifi_blaster.c $(top_srcdir)/source/apps/blaster/wifi_single_client_msmt.c  $(top_srcdir)/source/apps/ocs/wifi_ocs.c
else
OneWifi_SOURCES += $(top_srcdir)/source/apps/wifi_apps.c $(top_srcdir)/source/apps/wifi_apps_mgr.c $(top_srcdir)/source/apps/blaster/wifi_blaster.c $(top_srcdir)/source/apps/blaster/wifi_single_client_msmt.c
endif

if SM_APP_SUPPORT
OneWifi_SOURCES += $(top_srcdir)/source/apps/sm/wifi_sm.c $(top_srcdir)/source/apps/sm/sm_utils.c $(top_srcdir)/source/apps/sm/sm_report.c $(top_srcdir)/source/apps/sm/sm_client_cache.c $(top_srcdir)/source/apps/sm/sm_client_report.c $(top_srcdir)/source/apps/sm/sm_survey_cache.c $(top_srcdir)/source/apps/sm/sm_survey_report.c $(top_srcdir)/source/apps/sm/sm_neighbor_cache.c $(top_srcdir)/source/apps/sm/sm_neighbor_report.c
endif
if ONEWIFI_CAC_APP_SUPPORT
OneWifi_SOURCES += $(top_srcdir)/source/apps/cac/wifi_cac.c
OneWifi_CPPFLAGS += -I$(top_srcdir)/source/apps/cac/
endif
if ONEWIFI_DML_SUPPORT
OneWifi_SOURCES += $(top_srcdir)/source/dml/wifi_ssp/ssp_main.c $(top_srcdir)/source/dml/wifi_ssp/ssp_loop.c $(top_srcdir)/source/dml/wifi_ssp/ssp_messagebus_interface.c $(top_srcdir)/source/dml/wifi_ssp/ssp_action.c $(top_srcdir)/source/dml/wifi_ssp/dm_pack_datamodel.c  $(top_srcdir)/source/dml/tr_181/sbapi/webpa_interface.c $(top_srcdir)/source/dml/tr_181/sbapi/webpa_interface_without_seshat.c $(top_srcdir)/source/dml/tr_181/sbapi/webpa_interface_with_seshat.c  $(top_srcdir)/source/dml/tr_181/sbapi/cosa_dbus_api.c
endif

OneWifi_SOURCES += $(top_srcdir)/lib/common/os_time.c $(top_srcdir)/lib/common/util.c $(top_srcdir)/lib/common/monitor.c $(top_srcdir)/lib/common/os.c $(top_srcdir)/lib/common/os_util.c $(top_srcdir)/lib/common/os_exec.c $(top_srcdir)/lib/const/const.c $(top_srcdir)/lib/ds/ds_tree.c $(top_srcdir)/lib/json_util/string.c $(top_srcdir)/lib/json_util/memdbg.c $(top_srcdir)/lib/json_util/future.c $(top_srcdir)/lib/log/log.c $(top_srcdir)/lib/log/log_syslog.c $(top_srcdir)/lib/log/log_stdout.c $(top_srcdir)/lib/log/log_traceback.c $(top_srcdir)/lib/osa/os_backtrace.c $(top_srcdir)/lib/osa/os_socket.c $(top_srcdir)/lib/osa/os_nif_linux.c $(top_srcdir)/lib/osa/os_regex.c $(top_srcdir)/lib/osa/os_proc.c $(top_srcdir)/lib/osa/os_file_ops.c $(top_srcdir)/lib/osa/os_file.c $(top_srcdir)/lib/osa/os_random.c $(top_srcdir)/lib/ovsdb/ovsdb.c $(top_srcdir)/lib/ovsdb/ovsdb_method.c $(top_srcdir)/lib/ovsdb/ovsdb_update.c $(top_srcdir)/lib/ovsdb/ovsdb_sync.c $(top_srcdir)/lib/ovsdb/ovsdb_sync_api.c $(top_srcdir)/lib/ovsdb/ovsdb_table.c $(top_srcdir)/lib/ovsdb/ovsdb_cache.c $(top_srcdir)/lib/ovsdb/ovsdb_utils.c $(top_srcdir)/lib/pjs/pjs_array.c $(top_srcdir)/lib/pjs/pjs_ovs_basic.c $(top_srcdir)/lib/pjs/pjs_basic.c $(top_srcdir)/lib/pjs/pjs_types.c $(top_srcdir)/lib/pjs/pjs_ovs_set.c $(top_srcdir)/lib/pjs/pjs_ovs_map.c $(top_srcdir)/lib/qm/qm_conn.c $(top_srcdir)/lib/schema/schema.c $(top_srcdir)/lib/pktgen/pktgen.c $(top_srcdir)/lib/datapipeline/dppline.c $(top_srcdir)/lib/datapipeline/opensync_stats.pb-c.c $(top_srcdir)/lib/datapipeline/osp_unit_rdk.c $(top_srcdir)/lib/datapipeline/devinfo.c

OneWifi_LDFLAGS = -rdynamic -lwebconfig_framework -lsecure_wrapper $(SYSTEMD_LDFLAGS) -luuid -lsecure_wrapper -lmsgpackc -lcjson  -lm -ljansson -lev -lprotobuf-c -ltrower-base64 

if CCSP_COMMON_SUPPORT
OneWifi_LDFLAGS += -lccsp_common -lutapi -lsyscfg -lprint_uptime -lsysevent -lrdk_wifihal -lavro
endif

OneWifi_CPPFLAGS += -I${PKG_CONFIG_SYSROOT_DIR}${includedir}/rdk-wifi-libhostap/ -I${PKG_CONFIG_SYSROOT_DIR}${includedir}/rdk-wifi-libhostap/src/ -I${PKG_CONFIG_SYSROOT_DIR}${includedir}/rdk-wifi-libhostap/src/ap -I${PKG_CONFIG_SYSROOT_DIR}${includedir}/rdk-wifi-libhostap/src/utils -I${PKG_CONFIG_SYSROOT_DIR}${includedir}/rdk-wifi-libhostap/src/drivers/ -I$(PKG_CONFIG_SYSROOT_DIR)$(includedir)/qca/qca-wifi/os/linux/include/ -I${PKG_CONFIG_SYSROOT_DIR}${libdir}/ -DEXTERNAL_USE_ONLY

AM_CFLAGS += -DCONFIG_WPS -DCONFIG_IEEE80211R_AP -DCONFIG_IEEE80211R -DCONFIG_ETH_P_OUI -DCONFIG_IEEE80211W
AM_CFLAGS += -DEAP_SERVER_FAST

if CCSP_COMMON_SUPPORT
OneWifi_LDFLAGS += -lhostap
OneWifi_LDFLAGS += -lnl-idiag-3
endif
OneWifi_LDFLAGS += -lnl-3
OneWifi_LDFLAGS += -lnl-genl-3
OneWifi_LDFLAGS += -lnl-route-3
OneWifi_LDFLAGS += -lnl-nf-3
OneWifi_LDFLAGS += -L$(top_builddir)/source/utils/
OneWifi_LDFLAGS += -lwifi_utils
if WITH_LIBWEBCONFIG
OneWifi_LDFLAGS += -L$(top_builddir)/source/webconfig/
endif
OneWifi_LDFLAGS += -lwifi_webconfig 
#OneWifi_LDFLAGS += -llibnl-3.la llibnl-genl-3.la llibnl-route-3.la llibnl-nf-3.la llibnl-idiag-3
