
# The PROGRAM macro defines the name of the program or project.  It
# allows the program name to be changed by editing in only one
# location
#
# You will need to:
# (1) Describe parameters here. ex: IN_SHAPEFILE is the input shapefile
# (2) Define parameters below this comment box. 
#       ex: IN_SHAPEFILE = /mycomp/data/shapefile.shp
# (3) Add the parameters to the run target at the end of this file
#       ex: ./$(PROGRAM) $(IN_SHAPEFILE)
#

#
# The INCLUDEDIRS macro contains a list of include directories
# to pass to the compiler so it can find necessary header files.
#
# The LIBDIRS macro contains a list of library directories
# to pass to the linker so it can find necessary libraries.
#
# The LIBS macro contains a list of libraries that the the
# executable must be linked against.
#

OS = $(shell uname)
PLATFORM = $(shell uname -a)

BASE_DIR := $(shell pwd)

ONE_WIFI_HOME = $(BASE_DIR)/
WIFI_HAL_INTERFACE = $(BASE_DIR)/../halinterface/include
WIFI_RDK_HAL = $(BASE_DIR)/../rdk-wifi-hal
WIFI_HOSTAP_BASE = $(BASE_DIR)/../rdk-wifi-libhostap/source/hostap-2.10
WIFI_HOSTAP_SRC = $(WIFI_HOSTAP_BASE)/src
WIFI_HOSTAP_SUPPLICANT = $(WIFI_HOSTAP_BASE)/wpa_supplicant
ONE_WIFI_EM_HOME = $(BASE_DIR)/../unified-wifi-mesh
WIFI_TROWER_BASE = $(BASE_DIR)/../trower-base64/include/

INSTALLDIR = $(BASE_DIR)/install
OBJDIR = obj
CXX = g++
CC = gcc
AR= ar cr
RM = -rm -rf
