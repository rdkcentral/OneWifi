OS = $(shell uname)
PLATFORM = $(shell uname -a)

BASE_DIR := $(shell pwd)

ONE_WIFI_HOME = $(BASE_DIR)/../../../OneWifi/
WIFI_HAL_INTERFACE = $(BASE_DIR)/../../../halinterface/include
WIFI_RDK_HAL = $(BASE_DIR)/../../../rdk-wifi-hal
WIFI_HOSTAP_BASE = $(BASE_DIR)/../../../rdk-wifi-libhostap/source/hostap-2.10
WIFI_HOSTAP_SRC = $(WIFI_HOSTAP_BASE)/src
WIFI_HOSTAP_SUPPLICANT = $(WIFI_HOSTAP_BASE)/wpa_supplicant
ONE_WIFI_EM_HOME = $(BASE_DIR)/../../../unified-wifi-mesh

INSTALLDIR = $(BASE_DIR)/../../install
OBJDIR = obj
CC =  $(TARGET_CC) 
AR= $(AR) 
RM = -rm -rf
LDFLAGS= $(HOST_LDFLAGS)
