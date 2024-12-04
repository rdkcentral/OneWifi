#
# The PROGRAM macro defines the name of the program or project.  It
# allows the program name to be changed by editing in only one
# location
#

#
# Command line parameters: Edit these parameters so that you can 
# easily run the sample by typing "make -f Makefile.Linux run".
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

include build/linux/makefile.inc


EASY_MESH_NODE = 1

# wifi hal rules
HAL_LIBRARY = $(INSTALLDIR)/lib/libwifihal.a
WEBCONFIG_LIBRARY = $(INSTALLDIR)/lib/libwebconfig.a
HE_BUS_LIBRARY = $(INSTALLDIR)/lib/libhebus.a

INCLUDE_HAL_LIB_DIRS = \
    -I$(ONE_WIFI_HOME)/include \
    -I$(WIFI_RDK_HAL)/src \
    -I$(WIFI_RDK_HAL)/util_crypto \
    -I$(WIFI_DEVICE_HAL)/  \
    -I$(WIFI_SYSCALL_WRAPPER)/source/ \
    -I$(WIFI_CJSON)/

INCLUDE_HOSTAP_LIB_DIRS = \
    -I$(WIFI_HOSTAP_BASE) \
    -I$(WIFI_HOSTAP_SUPPLICANT) \
    -I$(WIFI_HOSTAP_SRC) \
    -I$(WIFI_HOSTAP_SRC)/ap \
    -I$(WIFI_HOSTAP_SRC)/utils \
    -I$(WIFI_HOSTAP_SRC)/drivers \

EXCLUDE = $(WIFI_RDK_HAL)/src/wifi_hal_frame_test.c $(WIFI_RDK_HAL)/src/wifi_hal_dpp.c

HAL_LIB_SOURCES = $(filter-out $(EXCLUDE),$(wildcard $(WIFI_RDK_HAL)/src/*.c)) \
    $(wildcard $(WIFI_RDK_HAL)/platform/raspberry-pi/*.c) \
    $(wildcard $(WIFI_DEVICE_HAL)/*.c) \
    $(WIFI_HOSTAP_SRC)/ap/ieee802_11_auth.c \
    $(WIFI_HOSTAP_SRC)/ap/ap_config.c   \
    $(WIFI_HOSTAP_SRC)/ap/ieee802_11.c   \
    $(WIFI_HOSTAP_SRC)/ap/ieee802_11_shared.c   \
    $(WIFI_HOSTAP_SRC)/ap/ieee802_11_vht.c   \
    $(WIFI_HOSTAP_SRC)/ap/ieee802_11_he.c   \
    $(WIFI_HOSTAP_SRC)/ap/ieee802_11_ht.c   \
    $(WIFI_HOSTAP_SRC)/ap/ieee802_1x.c   \
    $(WIFI_HOSTAP_SRC)/ap/ap_mlme.c   \
    $(WIFI_HOSTAP_SRC)/ap/ap_list.c   \
    $(WIFI_HOSTAP_SRC)/ap/sta_info.c   \
    $(WIFI_HOSTAP_SRC)/ap/wpa_auth.c   \
    $(WIFI_HOSTAP_SRC)/ap/wpa_auth_ie.c   \
    $(WIFI_HOSTAP_SRC)/ap/wpa_auth_glue.c   \
    $(WIFI_HOSTAP_SRC)/ap/wps_hostapd.c   \
    $(WIFI_HOSTAP_SRC)/ap/pmksa_cache_auth.c   \
    $(WIFI_HOSTAP_SRC)/ap/eap_user_db.c   \
    $(WIFI_HOSTAP_SRC)/ap/tkip_countermeasures.c   \
    $(WIFI_HOSTAP_SRC)/ap/hostapd.c   \
    $(WIFI_HOSTAP_SRC)/ap/beacon.c   \
    $(WIFI_HOSTAP_SRC)/ap/rrm.c   \
    $(WIFI_HOSTAP_SRC)/ap/wmm.c   \
    $(WIFI_HOSTAP_SRC)/ap/authsrv.c   \
    $(WIFI_HOSTAP_SRC)/ap/bss_load.c   \
    $(WIFI_HOSTAP_SRC)/ap/vlan.c   \
    $(WIFI_HOSTAP_SRC)/ap/vlan_init.c   \
    $(WIFI_HOSTAP_SRC)/ap/vlan_ifconfig.c   \
    $(WIFI_HOSTAP_SRC)/ap/ap_drv_ops.c   \
    $(WIFI_HOSTAP_SRC)/ap/accounting.c   \
    $(WIFI_HOSTAP_SRC)/ap/neighbor_db.c   \
    $(WIFI_HOSTAP_SRC)/ap/drv_callbacks.c   \
    $(WIFI_HOSTAP_SRC)/ap/ctrl_iface_ap.c   \
    $(WIFI_HOSTAP_SRC)/ap/hw_features.c   \
    $(WIFI_HOSTAP_SRC)/ap/dfs.c   \
    $(WIFI_HOSTAP_SRC)/ap/utils.c   \
    $(WIFI_HOSTAP_SRC)/ap/greylist.c   \
    $(WIFI_HOSTAP_SRC)/eapol_auth/eapol_auth_sm.c   \
    $(WIFI_HOSTAP_SRC)/eap_server/eap_server.c   \
    $(WIFI_HOSTAP_SRC)/eap_server/eap_server_methods.c   \
    $(WIFI_HOSTAP_SRC)/eap_server/eap_server_gtc.c   \
    $(WIFI_HOSTAP_SRC)/eap_server/eap_server_identity.c   \
    $(WIFI_HOSTAP_SRC)/eap_server/eap_server_md5.c   \
    $(WIFI_HOSTAP_SRC)/eap_server/eap_server_mschapv2.c   \
    $(WIFI_HOSTAP_SRC)/eap_server/eap_server_peap.c   \
    $(WIFI_HOSTAP_SRC)/eap_server/eap_server_tls_common.c   \
    $(WIFI_HOSTAP_SRC)/eap_server/eap_server_tls.c   \
    $(WIFI_HOSTAP_SRC)/eap_server/eap_server_ttls.c \
    $(WIFI_HOSTAP_SRC)/eap_common/chap.c   \
    $(WIFI_HOSTAP_SRC)/eap_common/eap_peap_common.c   \
    $(WIFI_HOSTAP_SRC)/eap_common/eap_common.c   \
    $(WIFI_HOSTAP_SRC)/eap_common/eap_pwd_common.c   \
    $(wildcard $(WIFI_HOSTAP_SRC)/eap_peer/*.c) \
    $(WIFI_HOSTAP_SRC)/wps/wps.c   \
    $(WIFI_HOSTAP_SRC)/wps/wps_attr_build.c   \
    $(WIFI_HOSTAP_SRC)/wps/wps_attr_parse.c   \
    $(WIFI_HOSTAP_SRC)/wps/wps_attr_process.c   \
    $(WIFI_HOSTAP_SRC)/wps/wps_dev_attr.c   \
    $(WIFI_HOSTAP_SRC)/wps/wps_common.c   \
    $(WIFI_HOSTAP_SRC)/wps/wps_registrar.c   \
    $(WIFI_HOSTAP_SRC)/wps/wps_enrollee.c   \
    $(WIFI_HOSTAP_SRC)/radius/radius.c   \
    $(WIFI_HOSTAP_SRC)/radius/radius_client.c   \
    $(WIFI_HOSTAP_SRC)/radius/radius_das.c   \
    $(WIFI_HOSTAP_SRC)/utils/wpabuf.c    \
    $(WIFI_HOSTAP_SRC)/utils/wpa_debug.c    \
    $(WIFI_HOSTAP_SRC)/utils/os_unix.c    \
    $(WIFI_HOSTAP_SRC)/utils/eloop.c    \
    $(WIFI_HOSTAP_SRC)/utils/common.c    \
    $(WIFI_HOSTAP_SRC)/utils/ip_addr.c    \
    $(WIFI_HOSTAP_SRC)/utils/uuid.c    \
    $(WIFI_HOSTAP_SRC)/utils/radiotap.c    \
    $(WIFI_HOSTAP_SRC)/utils/crc32.c    \
    $(WIFI_HOSTAP_SRC)/common/wpa_common.c    \
    $(WIFI_HOSTAP_SRC)/common/hw_features_common.c    \
    $(WIFI_HOSTAP_SRC)/common/ieee802_11_common.c    \
    $(WIFI_HOSTAP_SRC)/common/ctrl_iface_common.c    \
    $(WIFI_HOSTAP_SRC)/common/dragonfly.c    \
    $(WIFI_HOSTAP_SRC)/crypto/crypto_openssl.c    \
    $(WIFI_HOSTAP_SRC)/crypto/ms_funcs.c    \
    $(WIFI_HOSTAP_SRC)/crypto/sha1-prf.c    \
    $(WIFI_HOSTAP_SRC)/crypto/sha1-pbkdf2.c    \
    $(WIFI_HOSTAP_SRC)/crypto/random.c    \
    $(WIFI_HOSTAP_SRC)/crypto/tls_internal.c    \
    $(WIFI_HOSTAP_SRC)/crypto/dh_groups.c    \
    $(WIFI_HOSTAP_SRC)/crypto/sha1.c    \
    $(WIFI_HOSTAP_SRC)/crypto/sha1-internal.c    \
    $(WIFI_HOSTAP_SRC)/crypto/sha256-internal.c    \
    $(WIFI_HOSTAP_SRC)/crypto/md5-internal.c    \
    $(WIFI_HOSTAP_SRC)/crypto/sha256.c    \
    $(WIFI_HOSTAP_SRC)/crypto/sha256-prf.c    \
    $(WIFI_HOSTAP_SRC)/crypto/aes-cbc.c    \
    $(WIFI_HOSTAP_SRC)/crypto/aes-internal.c    \
    $(WIFI_HOSTAP_SRC)/l2_packet/l2_packet_linux.c    \
    $(WIFI_HOSTAP_SRC)/rsn_supp/wpa.c    \
    $(WIFI_HOSTAP_SRC)/rsn_supp/wpa_ie.c    \
    $(WIFI_HOSTAP_SRC)/rsn_supp/wpa_ft.c    \
    $(WIFI_HOSTAP_SRC)/rsn_supp/pmksa_cache.c    \
    $(WIFI_HOSTAP_SRC)/rsn_supp/preauth.c    \
    $(WIFI_HOSTAP_SRC)/eapol_supp/eapol_supp_sm.c    \
    $(WIFI_HOSTAP_BASE)/hostapd/ctrl_iface.c    \
    $(WIFI_HOSTAP_BASE)/hostapd/config_file.c    \
    $(WIFI_HOSTAP_BASE)/hostapd/eap_register.c    \
    $(WIFI_HOSTAP_SRC)/drivers/drivers.c    \
    $(WIFI_HOSTAP_SRC)/drivers/driver_common.c    \
    $(WIFI_HOSTAP_SRC)/drivers/driver_nl80211.c    \
    $(WIFI_HOSTAP_SRC)/drivers/driver_nl80211_event.c    \
    $(WIFI_HOSTAP_SRC)/drivers/driver_nl80211_monitor.c    \
    $(WIFI_HOSTAP_SRC)/drivers/driver_nl80211_scan.c    \
    $(WIFI_HOSTAP_SRC)/drivers/driver_nl80211_capa.c    \
    $(WIFI_HOSTAP_SRC)/drivers/linux_ioctl.c    \
    $(WIFI_HOSTAP_SRC)/drivers/netlink.c    \
    $(WIFI_HOSTAP_SRC)/drivers/rfkill.c    \

HAL_LIB_OBJECTS = $(HAL_LIB_SOURCES:.c=.o)  # expands to list of object files
ALL_HAL_LIB_OBJECTS = $(HAL_LIB_OBJECTS)
HAL_LIB_FLAGS = -g -fPIC $(INCLUDE_HAL_LIB_DIRS) -DENABLE_FEATURE_MESHWIFI -DRASPBERRY_PI_PORT -D_PLATFORM_RASPBERRYPI_ -DCONFIG_HW_CAPABALITIES
HOSTAP_LIB_FLAGS = -g -fPIC $(INCLUDE_HOSTAP_LIB_DIRS) -DHOSTAPD -DCONFIG_CRYPTO_INTERNAL -DCONFIG_DRIVER_NL80211 -DNEED_AP_MLME -DCONFIG_IEEE80211AC -DCONFIG_IEEE80211AX -DCONFIG_IEEE80211N -DCONFIG_WPS -DIEEE8021X_EAPOL -DEAP_SERVER_IDENTITY -DEAP_SERVER_MD5 -DEAP_SERVER_TLS -DEAP_SERVER_MSCHAPV2 -DEAP_SERVER_PEAP -DEAP_SERVER_TTLS -DCONFIG_ECC -DRDK_ONEWIFI -DCONFIG_IEEE80211W -DCONFIG_OPENSSL_CMAC -DCONFIG_LIBNL20
HOSTAP_LIB_FLAGS +=  -DHOSTAPD_2_10 -DCONFIG_WEP -DFEATURE_SUPPORT_RADIUSGREYLIST -DCONFIG_DRIVER_BRCM -DCONFIG_DRIVER_BRCM_MAP

# wifi agent rules

LDFLAGS = $(LIBDIRS) $(LIBS)

PROGRAM = $(INSTALLDIR)/bin/OneWifi

INCLUDEDIRS = \
    -I$(WIFI_CCSP_COMMON_LIB)/source/cosa/include \
    -I$(WIFI_CCSP_COMMON_LIB)/source/cosa/include/linux \
    -I$(WIFI_CCSP_COMMON_LIB)/source/cosa/package/slap/include \
    -I$(WIFI_CCSP_COMMON_LIB)/source/ccsp/components/include \
    -I$(WIFI_CCSP_COMMON_LIB)/source/ccsp/components/common/MessageBusHelper/include \
    -I$(WIFI_CCSP_COMMON_LIB)/source/ccsp/components/common/PoamIrepFolder \
    -I$(WIFI_CCSP_COMMON_LIB)/source/ccsp/custom \
    -I$(WIFI_CCSP_COMMON_LIB)/source/ccsp/include \
    -I$(WIFI_CCSP_COMMON_LIB)/source/debug_api/include \
    -I$(WIFI_CCSP_COMMON_LIB)/source/dm_pack \
    -I$(WIFI_CCSP_COMMON_LIB)/source/util_api/http/include \
    -I$(WIFI_CCSP_COMMON_LIB)/source/util_api/ansc/include \
    -I$(WIFI_CCSP_COMMON_LIB)/WebConfig_Framework \
    -I$(WIFI_MSGPACK)/include \
    -I$(WIFI_UTOPIA)/source/include \
    -I$(WIFI_UTOPIA)/source/util/print_uptime \
    -I$(WIFI_DBUS)/ \
    -I$(BASE_DIR) \
    -I$(ONE_WIFI_HOME)/source/dml/tr_181/sbapi \
    -I$(ONE_WIFI_HOME)/source/sampleapps \
    -I$(ONE_WIFI_HOME)/source/dml/tr_181/ml \
    -I$(ONE_WIFI_HOME)/source/dml/wifi_ssp \
    -I$(ONE_WIFI_HOME)/source/ccsp \
    -I$(ONE_WIFI_HOME)/source/utils \
    -I$(ONE_WIFI_HOME)/source/stats \
    -I$(ONE_WIFI_HOME)/source/stubs \
    -I$(ONE_WIFI_HOME)/source/dml/linux \
    -I$(ONE_WIFI_HOME)/source/platform/linux \
    -I$(ONE_WIFI_HOME)/source/platform/common \
    -I$(ONE_WIFI_HOME)/lib/pktgen/ \
    -I$(ONE_WIFI_HOME)/source/core \
    -I$(ONE_WIFI_HOME)/source/apps \
    -I$(ONE_WIFI_HOME)/source/apps/analytics \
    -I$(ONE_WIFI_HOME)/source/apps/blaster \
    -I$(ONE_WIFI_HOME)/source/apps/cac \
    -I$(ONE_WIFI_HOME)/source/apps/csi \
    -I$(ONE_WIFI_HOME)/source/apps/harvester \
    -I$(ONE_WIFI_HOME)/source/apps/levl \
    -I$(ONE_WIFI_HOME)/source/apps/motion \
    -I$(ONE_WIFI_HOME)/source/apps/ocs \
    -I$(ONE_WIFI_HOME)/source/apps/sm \
    -I$(ONE_WIFI_HOME)/source/apps/whix \
    -I$(ONE_WIFI_HOME)/source/core/services \
    -I$(ONE_WIFI_HOME)/include/tr_181/ml \
    -I$(ONE_WIFI_HOME)/include \
    -I$(ONE_WIFI_HOME)/source/db \
    -I$(ONE_WIFI_HOME)/lib/common \
    -I$(ONE_WIFI_HOME)/lib/log \
    -I$(ONE_WIFI_HOME)/lib/ds \
    -I$(ONE_WIFI_HOME)/lib/ovsdb \
    -I$(ONE_WIFI_HOME)/lib/pjs \
    -I$(ONE_WIFI_HOME)/lib/json_util \
    -I$(ONE_WIFI_HOME)/lib/inc \
    -I$(ONE_WIFI_HOME)/lib/osa \
    -I$(ONE_WIFI_HOME)/lib/const \
    -I$(ONE_WIFI_HOME)/lib/schema \
    -I$(WIFI_HAL_INTERFACE) \
    -I/usr/local/ssl/include/ \
    -I/usr/include/libnl3 \
    -I$(WIFI_HOSTAP_BASE) \
    -I$(WIFI_HOSTAP_SRC) \
    -I$(WIFI_HOSTAP_SRC)/ap \
    -I$(WIFI_NETLINK)/include \

LIBDIRS = \
    -L$(INSTALLDIR)/lib \
    -L/usr/local/lib    \
    -L/usr/local/ssl/lib/ \

ifneq ($(OS), Darwin)
LIBDIRS += -L$(INSTALLDIR)/lib/platform/x86-64
else
LIBDIRS += -L$(INSTALLDIR)/lib/platform/darwin
endif

LIBS = -lm -luuid -lwifihal  -lpthread -ldl -ljansson -lev -lssl -lcrypto -lnl-3 -lnl-genl-3 -lnl-route-3 -lavro -lcjson

#
# The CXXSOURCES macro contains a list of source files.
#
# The CXXOBJECTS macro converts the CXXSOURCES macro into a list
# of object files.
#
# The CFLAGS macro contains a list of options to be passed to
# the compiler.  Adding "-g" to this line will cause the compiler
# to add debugging information to the executable.
#
# The CXX macro defines the C++ compiler.
#
# The LDFLAGS macro contains all of the library and library
# directory information to be passed to the linker.
#

CSOURCES = $(wildcard $(ONE_WIFI_HOME)/source/db/wifi_db.c) \
    $(filter-out $(ONE_WIFI_HOME)/source/core/services/vap_svc_mesh_pod.c,$(wildcard $(ONE_WIFI_HOME)/source/core/services/*.c)) \
    $(wildcard $(ONE_WIFI_HOME)/source/apps/*.c) \
    $(wildcard $(ONE_WIFI_HOME)/source/stubs/*.c) \
    $(wildcard $(ONE_WIFI_HOME)/source/stats/*.c)	\
    $(ONE_WIFI_HOME)/lib/common/util.c		\
    $(ONE_WIFI_HOME)/source/core/wifi_8021x.c	\
    $(ONE_WIFI_HOME)/source/core/wifi_ctrl_wifiapi_handlers.c	\
    $(ONE_WIFI_HOME)/source/core/wifi_ctrl.c	\
    $(ONE_WIFI_HOME)/source/core/wifi_ctrl_rbus_handlers.c	\
    $(ONE_WIFI_HOME)/source/core/wifi_ctrl_queue_handlers.c	\
    $(ONE_WIFI_HOME)/source/core/wifi_ctrl_webconfig.c	\
    $(ONE_WIFI_HOME)/source/core/wifi_multidoc_webconfig.c	\
    $(ONE_WIFI_HOME)/source/core/wifi_mgr.c	\
    $(ONE_WIFI_HOME)/source/core/wifi_events.c	\
    $(ONE_WIFI_HOME)/source/ccsp/ccsp.c \
    $(ONE_WIFI_HOME)/source/utils/collection.c	\
    $(ONE_WIFI_HOME)/source/utils/scheduler.c	\
    $(ONE_WIFI_HOME)/source/dml/linux/wifi_dml.c \
    $(ONE_WIFI_HOME)/source/platform/linux/misc.c 	\
    $(ONE_WIFI_HOME)/source/platform/linux/bus.c	\
    $(ONE_WIFI_HOME)/source/platform/common/common.c   \

WEBCONFIG_SOURCES = $(ONE_WIFI_HOME)/source/webconfig/wifi_decoder.c	\
        $(ONE_WIFI_HOME)/source/webconfig/wifi_encoder.c	\
        $(ONE_WIFI_HOME)/source/webconfig/wifi_webconfig_associated_client.c	\
        $(ONE_WIFI_HOME)/source/webconfig/wifi_webconfig.c	\
        $(ONE_WIFI_HOME)/source/webconfig/wifi_webconfig_dml.c	\
        $(ONE_WIFI_HOME)/source/webconfig/wifi_webconfig_home.c	\
        $(ONE_WIFI_HOME)/source/webconfig/wifi_webconfig_lnf.c	\
        $(ONE_WIFI_HOME)/source/webconfig/wifi_webconfig_macfilter.c	\
        $(ONE_WIFI_HOME)/source/webconfig/wifi_webconfig_mesh_backhaul.c	\
        $(ONE_WIFI_HOME)/source/webconfig/wifi_webconfig_mesh_backhaul_sta.c	\
        $(ONE_WIFI_HOME)/source/webconfig/wifi_webconfig_mesh.c	\
        $(ONE_WIFI_HOME)/source/webconfig/wifi_webconfig_mesh_sta.c	\
        $(ONE_WIFI_HOME)/source/webconfig/wifi_webconfig_null.c	\
        $(ONE_WIFI_HOME)/source/webconfig/wifi_webconfig_private.c	\
        $(ONE_WIFI_HOME)/source/webconfig/wifi_webconfig_radio.c	\
        $(ONE_WIFI_HOME)/source/webconfig/wifi_webconfig_stats_config.c		\
        $(ONE_WIFI_HOME)/source/webconfig/wifi_webconfig_steering_clients.c	\
        $(ONE_WIFI_HOME)/source/webconfig/wifi_webconfig_steering_config.c	\
        $(ONE_WIFI_HOME)/source/webconfig/wifi_webconfig_vif_neighbors.c	\
        $(ONE_WIFI_HOME)/source/webconfig/wifi_webconfig_wifiapi_radio.c	\
        $(ONE_WIFI_HOME)/source/webconfig/wifi_webconfig_wifiapi_vap.c		\
        $(ONE_WIFI_HOME)/source/webconfig/wifi_webconfig_wifi_config.c		\
        $(ONE_WIFI_HOME)/source/webconfig/wifi_webconfig_xfinity.c		\
        $(ONE_WIFI_HOME)/source/webconfig/wifi_webconfig_radio_stats.c		\
        $(ONE_WIFI_HOME)/source/webconfig/wifi_webconfig_neighbor_stats.c	\
        $(ONE_WIFI_HOME)/source/webconfig/wifi_webconfig_assocdevice_stats.c	\
        $(ONE_WIFI_HOME)/source/webconfig/wifi_webconfig_radio_temperature.c    \
        $(ONE_WIFI_HOME)/source/webconfig/wifi_webconfig_radiodiag_stats.c    \
        $(ONE_WIFI_HOME)/source/webconfig/wifi_webconfig_multivap.c    \
        $(ONE_WIFI_HOME)/source/utils/wifi_util.c	\

HEBUS_SOURCES = $(wildcard $(ONE_WIFI_HOME)/source/platform/linux/he_bus/src/*.c)  \

INCLUDE_HE_LIB_DIRS = \
    -I$(ONE_WIFI_HOME)/source/platform/linux/he_bus/inc \

ifdef EASY_MESH_NODE
    INCLUDEDIRS +=  -I$(ONE_WIFI_EM_HOME)/inc
    WEBCONFIG_SOURCES += $(ONE_WIFI_HOME)/source/webconfig/wifi_easymesh_translator.c 
endif

ifdef ONEWIFI_CSI_APP_SUPPORT
	CSOURCES += $(wildcard $(ONE_WIFI_HOME)/source/apps/csi/*.c)	\
	WEBCONFIG_SOURCES += $(ONE_WIFI_HOME)/source/webconfig/wifi_webconfig_csi.c
endif


ifdef ONEWIFI_CAC_APP_SUPPORT
	CSOURCES += $(wildcard $(ONE_WIFI_HOME)/source/apps/cac/*.c) 	\
	WEBCONFIG_SOURCES += $(ONE_WIFI_HOME)/source/webconfig/wifi_webconfig_cac.c
endif


ifdef ONEWIFI_MOTION_APP_SUPPORT
	CSOURCES += $(wildcard $(ONE_WIFI_HOME)/source/apps/motion/*.c)
endif

ifdef ONEWIFI_HARVESTER_APP_SUPPORT
	CSOURCES += $(wildcard $(ONE_WIFI_HOME)/source/apps/harvester/*.c) 	\
	WEBCONFIG_SOURCES += $(ONE_WIFI_HOME)/source/webconfig/wifi_webconfig_harvester.c
endif

ifdef ONEWIFI_LEVL_APP_SUPPORT
	CSOURCES += $(wildcard $(ONE_WIFI_HOME)/source/apps/levl/*.c) 	\
	WEBCONFIG_SOURCES += $(ONE_WIFI_HOME)/source/webconfig/wifi_webconfig_levl.c
endif

ifdef ONEWIFI_WHIX_APP_SUPPORT
	CSOURCES += $(wildcard $(ONE_WIFI_HOME)/source/apps/whix/*.c)
endif

ifdef ONEWIFI_BLASTER_APP_SUPPORT 
	CSOURCES += $(wildcard $(ONE_WIFI_HOME)/source/apps/blaster/*.c) \
	WEBCONFIG_SOURCES += $(ONE_WIFI_HOME)/source/webconfig/wifi_webconfig_blaster.c
endif


COBJECTS = $(CSOURCES:.c=.o)  # expands to list of object files

WEBCONFIG_OBJECTS = $(WEBCONFIG_SOURCES:.c=.o)  # expands to list of object files
ALL_WEBCFG_LIB_OBJECTS = $(WEBCONFIG_OBJECTS)

HEBUS_OBJECTS = $(HEBUS_SOURCES:.c=.o)  # expands to list of object files
ALL_HEBUS_LIB_OBJECTS = $(HEBUS_OBJECTS)

ALLOBJECTS = $(CXXOBJECTS) $(COBJECTS) $(WEBCONFIG_OBJECTS) $(HEBUS_OBJECTS)

CFLAGS = $(INCLUDEDIRS) $(INCLUDE_HE_LIB_DIRS) -g -fPIC -D_ANSC_LINUX -D_COSA_INTEL_USG_ATOM_ -DUSE_NOTIFY_COMPONENT -DCISCO_XB3_PLATFORM_CHANGES -DDUAL_CORE_XB3 -DFEATURE_ONE_WIFI -DWIFI_HAL_VERSION_3 -DFEATURE_SUPPORT_PASSPOINT -DFEATURE_SUPPORT_WEBCONFIG -DRASPBERRY_PI_PORT  -DNL80211_ACL -D_PLATFORM_RASPBERRYPI_ -DEASY_MESH_NODE  

ifneq ($(OS), Darwin)
CFLAGS += -DPLATFORM_LINUX
else
CFLAGS += -DPLATFORM_OSX
endif

LDFLAGS = $(LIBDIRS) $(LIBS)

$(BUILD_DIR):
	@mkdir -p $(INSTALLDIR)/lib
	@mkdir -p $(INSTALLDIR)/bin
#
# Default target: the first target is the default target.
# Just type "make -f Makefile.Linux" to build it.
#


all:  $(BUILD_DIR) $(CMN_LIBRARY) $(HAL_LIBRARY) $(WEBCONFIG_LIBRARY) $(HE_BUS_LIBRARY) $(PROGRAM)

$(CMN_LIBRARY): $(ALL_CMN_LIB_OBJECTS)
	$(AR)  $@  $^

$(HAL_LIBRARY): $(ALL_HAL_LIB_OBJECTS)
	$(AR)  $@  $^

$(WEBCONFIG_LIBRARY): $(ALL_WEBCFG_LIB_OBJECTS)
	$(AR)  $@  $^

$(HE_BUS_LIBRARY): $(ALL_HEBUS_LIB_OBJECTS)
	$(AR)  $@  $^
#
# Link target: automatically builds its object dependencies before
# executing its link command.
#

$(PROGRAM): $(ALLOBJECTS)
	$(CXX) -o $@ $(ALLOBJECTS) $(LDFLAGS)

#
# Object targets: rules that define objects, their dependencies, and
# a list of commands for compilation.
#

%.o: %.c
	$(CC) $(CMN_LIB_FLAGS) $(CFLAGS) $(HAL_LIB_FLAGS) $(HOSTAP_LIB_FLAGS) -o $@ -c $<

%.o: %.cpp
	$(CXX) $(CFLAGS) -o $@ -c $<

#
# Clean target: "make -f Makefile.Linux clean" to remove unwanted objects and executables.
#

clean:
	$(RM) $(ALLOBJECTS) $(ALL_CMN_LIB_OBJECTS) $(ALL_HAL_LIB_OBJECTS) $(CMN_LIBRARY) $(HE_BUS_LIBRARY) $(WEBCONFIG_LIBRARY) $(HAL_LIBRARY) $(HOSTAP_LIBRARY) $(PROGRAM)

#
# Run target: "make -f Makefile.Linux run" to execute the application
#             You will need to add $(VARIABLE_NAME) for any command line parameters 
#             that you defined earlier in this file.
# 

run:
	./$(PROGRAM)

setup:
	./build/linux/setup.sh

