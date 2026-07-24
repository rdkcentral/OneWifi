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

AM_CPPFLAGS = -Wall -Werror -std=c++11
AM_CXXFLAGS = -std=c++11
ACLOCAL_AMFLAGS = -I m4
hardware_platform = i686-linux-gnu
lib_LTLIBRARIES=libwifi_web_socket.la
libwifi_web_socket_la_LDFLAGS = -L$(top_builddir)/source/utils/

libwifi_web_socket_la_CPPFLAGS = -I$(top_srcdir)/../hal/include -I$(top_srcdir)/include/ -I$(top_srcdir)/source/utils/web_socket/inc/ -I$(top_srcdir)/source/utils -I$(top_srcdir)/source/platform/ -I${PKG_CONFIG_SYSROOT_DIR}${includedir}

libwifi_web_socket_la_CPPFLAGS += -I${PKG_CONFIG_SYSROOT_DIR}/usr/include/ccsp/

libwifi_web_socket_la_SOURCES = $(top_srcdir)/source/utils/web_socket/src/ws_client.cpp
libwifi_web_socket_la_LIBADD = -lssl -lcrypto -lpthread -lstdc++fs

noinst_HEADERS = $(top_srcdir)/source/utils/wifi_util.h
