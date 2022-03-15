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