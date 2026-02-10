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

# ============================================================
# Program
# ============================================================
bin_PROGRAMS = wifi_motion_app

# ============================================================
# Include paths
# ============================================================
wifi_motion_app_CPPFLAGS = $(CPPFLAGS) \
    -I$(top_srcdir)/./include \
    -I$(top_srcdir)/source/sampleapps/wifi_motion/src \
    -I$(top_srcdir)/source/sampleapps/wifi_motion/src/math \
    -I$(top_srcdir)/source/sampleapps/wifi_motion/src/utils \
    -I$(top_srcdir)/source/sampleapps/wifi_motion/src/web \
    -I${PKG_CONFIG_SYSROOT_DIR}$(includedir)/rbus \
    -I$(top_srcdir)/source/sampleapps/wifi_motion/halinterface/include/

# ============================================================
# Sources
# ============================================================
wifi_motion_app_SOURCES = \
    src/main.cpp \
    src/csimgr.cpp \
    src/sounder.cpp \
    src/web/web.cpp \
    src/utils/utils.cpp \
    src/utils/base64.c \
    src/utils/cJSON.cpp \
    src/utils/cJSON_Utils.cpp \
    src/utils/collection.cpp \
    src/math/equation.cpp \
    src/math/matrix.cpp \
    src/math/mvnpdf.cpp \
    src/math/npdf.cpp \
    src/math/number.cpp \
    src/math/polynomial.cpp \
    src/math/sequence.cpp \
    src/math/vector.cpp

# ============================================================
# Linker flags / libraries
# ============================================================
wifi_motion_app_LDFLAGS = -lrbus
#wifi_motion_app_LDFLAGS += -L$(top_builddir)/source/utils
#wifi_motion_app_LDFLAGS += -lwifi_utils

if WITH_LIBWEBCONFIG
#wifi_motion_app_LDFLAGS += -L$(top_builddir)/source/webconfig
#wifi_motion_app_LDFLAGS += -lwifi_webconfig
endif

# ============================================================
# Optional feature flags
# ============================================================
#wifi_motion_app_CFLAGS = $(DML_ENABLE_FLAG)
wifi_motion_app_CFLAGS = $(JOURNALCTL_ENABLE_FLAG)

