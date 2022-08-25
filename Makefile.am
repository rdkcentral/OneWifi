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

OPT_SRCDIR = source
SUBDIRS = $(OPT_SRCDIR)

lib_LTLIBRARIES=libwifi.la

libwifi_la_CPPFLAGS = -D_ANSC_LINUX -D_ANSC_USER -I$(top_srcdir)/../CcspCommonLibrary/source/ccsp/custom -I$(top_srcdir)/../CcspCommonLibrary/source/ccsp/include -I$(top_srcdir)/../CcspCommonLibrary/source/debug_api/include -I$(top_srcdir)/../CcspCommonLibrary/source/cosa/include -I$(top_srcdir)/../CcspCommonLibrary/source/cosa/include/linux -I$(top_srcdir)/../CcspCommonLibrary/source/ccsp/components/include -I$(top_srcdir)/../CcspCommonLibrary/source/cosa/package/slap/include -I$(top_srcdir)/../hal/include -I$(top_srcdir)/../CcspCommonLibrary/source/util_api/http/include -I$(top_srcdir)/../CcspCommonLibrary/source/util_api/ansc/include -I$(top_srcdir)/lib -I$(top_srcdir)/lib/common -I$(top_srcdir)/../CcspCommonLibrary/source/ccsp/components/common/MessageBusHelper/include -I$(top_srcdir)/../CcspCommonLibrary/source/ccsp/components/common/PoamIrepFolder -I$(top_srcdir)/include/wifi_ssp -I$(top_srcdir)/./include

if ONEWIFI_DML_SUPPORT
libwifi_la_CPPFLAGS +=-I$(top_srcdir)/source/dml/dml_webconfig -I$(top_srcdir)/source/dml/tr_181/ml -I$(top_srcdir)/source/dml/tr_181/sbapi -I$(top_srcdir)/include/tr_181/ml
endif

if CCSP_ARCH_ARM
libwifi_la_CPPFLAGS += -D_ANSC_LITTLE_ENDIAN_
endif

if CCSP_ARCH_ATOM
libwifi_la_CPPFLAGS += -D_ANSC_LITTLE_ENDIAN_
endif

libwifi_la_LDFLAGS=
libwifi_la_SOURCES=

if ONEWIFI_DML_SUPPORT
EXTRA_DEPENDENCIES= \
        source/dml/tr_181/sbapi/libCcspWifiAgent_sbapi.la \
        source/dml/tr_181/ml/libCcspWifiAgent_ml.la \
        source/dml/dml_webconfig/libCcspWifiAgent_dml_webconfig.la 
endif

libwifi_la_DEPENDENCIES= \
	$(EXTRA_DEPENDENCIES)

libwifi_la_LIBADD=$(libwifi_la_DEPENDENCIES)
