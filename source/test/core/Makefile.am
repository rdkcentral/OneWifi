#/************************************************************************************
#  If not stated otherwise in this file or this component's LICENSE file the
#  following copyright and licenses apply:
  
#  Copyright 2018 RDK Management
  
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
  
#  http://www.apache.org/licenses/LICENSE-2.0
  
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
# **************************************************************************/

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

AM_CFLAGS += -Wno-poison-system-directories -Wall -Werror -Wextra -Wno-unused-parameter -Wno-pointer-sign -Wno-sign-compare -Wno-type-limits -Wno-format-truncation
AM_CPPFLAGS = -Wall -Werror
AM_LDFLAGS = -L$(top_builddir)/../hal/lib
AM_LDFLAGS += -lrdk_wifihal
if !HAL_IPC
AM_LDFLAGS += -lhal_wifi
endif
AM_CFLAGS += -DWBCFG_MULTI_COMP_SUPPORT

ACLOCAL_AMFLAGS = -I m4
hardware_platform = i686-linux-gnu
bin_PROGRAMS = wifi_ctrl
wifi_ctrl_CPPFLAGS = -I$(top_srcdir)/../hal/include -I${PKG_CONFIG_SYSROOT_DIR}${includedir}/rdk-wifi-libhostap/ -I${PKG_CONFIG_SYSROOT_DIR}${includedir}/rdk-wifi-libhostap/src/ -I${PKG_CONFIG_SYSROOT_DIR}${includedir}/rdk-wifi-libhostap/src/utils/ -I${PKG_CONFIG_SYSROOT_DIR}${includedir}/rdk-wifi-libhostap/src/ap/ -I${PKG_CONFIG_SYSROOT_DIR}${includedir}/rdk-wifi-libhostap/src/driver -I$(top_srcdir)/source/dml/dml_webconfig -I$(top_srcdir)/source/dml/tr_181/sbapi -I$(top_srcdir)/source/dml/tr_181 -I${PKG_CONFIG_SYSROOT_DIR}${includedir}/rdk-wifi-libhostap/src/utils/ -I$(top_srcdir)/source/dml/tr_181/ml -I$(top_srcdir)/source/dml/tr_181 -I$(top_srcdir)/source/dml -I$(top_srcdir)source/test/core -I$(top_srcdir)/source/sampleapps -I$(top_srcdir)/./include -I${top_srcdir}/source/test/db -I$(top_srcdir)/lib/ovsdb -I$(top_srcdir)/lib/inc -I$(top_srcdir)/lib/json_util -I$(top_srcdir)/lib/ds -I$(top_srcdir)/lib/common -I$(top_srcdir)/lib/pjs -I$(top_srcdir)/lib/log -I$(top_srcdir)/lib/const -I$(top_srcdir)/lib/schema -I$(top_srcdir)/lib/osp -I$(top_srcdir)/lib/osa -I$(top_srcdir)/lib/psfs -I$(top_srcdir)/lib/qm $(CPPFLAGS)
wifi_ctrl_CPPFLAGS += -I$(top_srcdir)/source/utils 
wifi_ctrl_CFLAGS = -Wno-attributes
wifi_ctrl_SOURCES = wifi_ctrl.c ../db/wifi_ovsdb.c ../db/wifi_ovsdb_apis.c wifi_mgr.c
wifi_ctrl_LDFLAGS = -lcjson -lev -lpthread -lrdk_wifihal
if !HAL_IPC
wifi_ctrl_LDFLAGS += -lhal_wifi
endif
