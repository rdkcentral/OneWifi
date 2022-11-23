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

AM_CFLAGS = -DJSON_MEMDBG

noinst_LTLIBRARIES=libCcspWifiAgent_jsutil.la

libCcspWifiAgent_jsutil_la_SOURCES = string.c memdbg.c future.c

libCcspWifiAgent_jsutil_la_CPPFLAGS = -I$(top_srcdir)/source/WifiSsp/lib/common -I$(top_srcdir)/source/WifiSsp/lib/const -I$(top_srcdir)/source/WifiSsp/lib/ds -I$(top_srcdir)/source/WifiSsp/lib/inc -I$(top_srcdir)/source/WifiSsp/lib/log -I$(top_srcdir)/source/WifiSsp/lib/osa -I$(top_srcdir)/source/WifiSsp/lib/ovsdb -I$(top_srcdir)/source/WifiSsp/lib/pjs -I$(top_srcdir)/source/WifiSsp/lib/qm -I$(top_srcdir)/source/WifiSsp/lib/schema

libCcspWifiAgent_jsutil_la_LDFLAGS = -ljansson



