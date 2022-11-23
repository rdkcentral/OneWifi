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

AM_CPPFLAGS = -Wall -g -Werror
AM_CXXFLAGS = -std=c++11

ACLOCAL_AMFLAGS = -I m4
bin_PROGRAMS = OneWifi_gtest.bin wifi_api2
OneWifi_gtest_bin_CPPFLAGS = -I$(PKG_CONFIG_SYSROOT_DIR)$(includedir)/gtest -I${top_srcdir}/gtest/include -I${top_srcdir}/source -I${top_srcdir}/include
OneWifi_gtest_bin_SOURCES = webconfig_consumer_test.cpp \
                            gtest_main.cpp
OneWifi_gtest_bin_LDFLAGS = -lgtest -lgmock -lgcov

wifi_api2_CPPFLAGS = $(CPPFLAGS)
wifi_api2_SOURCES = wifi_api2.c
wifi_api2_LDFLAGS = -lrbus
