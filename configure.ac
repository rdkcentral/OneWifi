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
#                                              -*- Autoconf -*-
# Process this file with autoconf to produce configure script.
#

AC_PREREQ([2.65])
AC_INIT([wifi], [1.0], [BUG-REPORT-ADDRESS])
AM_INIT_AUTOMAKE([subdir-objects])
LT_INIT
GTEST_ENABLE_FLAG = ""

AC_ARG_ENABLE([gtestapp],
             AS_HELP_STRING([--enable-gtestapp],[enable Gtest support (default is no)]),
             [
              case "${enableval}" in
               yes) GTEST_SUPPORT_ENABLED=true
                    GTEST_ENABLE_FLAG="-DGTEST_ENABLE"
                    m4_if(m4_sysval,[0],[AC_CONFIG_FILES([source/test/Makefile])]);;
               no) GTEST_SUPPORT_ENABLED=false AC_MSG_ERROR([Gtest support is disabled]);;
               *) AC_MSG_ERROR([bad value ${enableval} for --enable-gtestapp ]);;
              esac
             ],
             [echo "Gtestapp is disabled"])
AM_CONDITIONAL([WITH_GTEST_SUPPORT], [test x$GTEST_SUPPORT_ENABLED = xtrue])

AC_ARG_ENABLE([libwebconfig],
             AS_HELP_STRING([--enable-libwebconfig],[enable libwebconfig (default is no)]),
             [
              case "${enableval}" in
               yes) LIBWEBCONFIG_ENABLED=true
                    m4_if(m4_sysval,[0],[AC_CONFIG_FILES([source/webconfig/Makefile])]);;
               no) LIBWEBCONFIG_ENABLED=false;;
               *) AC_MSG_ERROR([bad value ${enableval} for --enable-gtestapp ]);;
              esac
              # LIBWEBCONFIG_ENABLED=true
              # m4_if(m4_sysval,[0],[AC_CONFIG_FILES([source/webconfig/Makefile])])
             ],
             [echo "libwebconfig is disabled"])
AM_CONDITIONAL([WITH_LIBWEBCONFIG], [test x$LIBWEBCONFIG_ENABLED = xtrue])

AC_ARG_ENABLE([easymesh],
             AS_HELP_STRING([--enable-easymesh],[enable easymesh (default is no)]),
             [
              case "${enableval}" in
               yes) EASYMESH_ENABLED=true;;
               no) EASYMESH_ENABLED=false;;
               *) AC_MSG_ERROR([bad value ${enableval} for --enable-easymesh ]);;
              esac
             ],
             [echo "easymesh is disabled"])
AM_CONDITIONAL([WITH_EASYMESH], [test x$EASYMESH_ENABLED = xtrue])

AC_PREFIX_DEFAULT(`pwd`)
AC_ENABLE_SHARED
AC_DISABLE_STATIC

SM_APP_FLAG = " "
AC_ARG_ENABLE([sm_app],
             AS_HELP_STRING([--enable-sm-app],[enable sm app (default is no)]),
             [
              case "${enableval}" in
               yes) SM_APP_ENABLE=true
                    SM_APP_FLAG="-DSM_APP"
                    ;;
               no)  SM_APP_ENABLE=false AC_MSG_ERROR([sm app is disabled]);;
               *)   AC_MSG_ERROR([bad value ${enableval} for --enable-sm-app ]);;
              esac
             ],
             [echo "sm app is disabled"])
AM_CONDITIONAL([SM_APP_SUPPORT], [test x$SM_APP_ENABLE = xtrue])
AC_SUBST(SM_APP_FLAG)

EM_APP_FLAG = " "
AC_ARG_ENABLE([em_app],
             AS_HELP_STRING([--enable-em-app],[enable em app (default is no)]),
             [
              case "${enableval}" in
               yes) EM_APP_ENABLE=true
                    EM_APP_FLAG="-DEM_APP"
                    ;;
               no)  EM_APP_ENABLE=false AC_MSG_ERROR([em app is disabled]);;
               *)   AC_MSG_ERROR([bad value ${enableval} for --enable-em-app ]);;
              esac
             ],
             [echo "em app is disabled"])
AM_CONDITIONAL([EM_APP_SUPPORT], [test x$EM_APP_ENABLE = xtrue])
AC_SUBST(EM_APP_FLAG)

JOURNALCTL_ENABLE_FLAG = " "
AC_ARG_ENABLE([journalctl],
             AS_HELP_STRING([--enable-journalctl],[enable journalctl logging support (default is no)]),
             [
              case "${enableval}" in
               yes) JOURNALCTL_SUPPORT_ENABLE=true
                    JOURNALCTL_ENABLE_FLAG="-DJOURNALCTL_SUPPORT";;
               no)  JOURNALCTL_SUPPORT_ENABLE=false AC_MSG_ERROR([journalctl logging support is disabled]);;
               *)   AC_MSG_ERROR([bad value ${enableval} for --enable-journalctl ]);;
              esac
             ],
             [echo "journalctl logging is disabled"])
AM_CONDITIONAL([JOURNALCTL_SUPPORT], [test x$JOURNALCTL_SUPPORT_ENABLE = xtrue])
AC_SUBST(JOURNALCTL_ENABLE_FLAG)

AC_ARG_ENABLE([easyconnect],
             AS_HELP_STRING([--enable-easyconnect],[enable EasyConnect support (default is no)]),
             [
              case "${enableval}" in
               yes) EASYCONNECT_SUPPORT_ENABLE=true
                    EASYCONNECT_SUPPORT_FLAG="-DEASYCONNECT_SUPPORT";;
               no)  EASYCONNECT_SUPPORT_ENABLE=false AC_MSG_ERROR([EasyConnect support is disabled]);;
               *)   AC_MSG_ERROR([bad value ${enableval} for --enable-easyconnect ]);;
              esac
             ],
             [echo "EasyConnect is disabled"])
AM_CONDITIONAL([EASYCONNECT_SUPPORT], [test x$EASYCONNECT_SUPPORT_ENABLE = xtrue])

AM_CONDITIONAL([HAL_IPC], [test x$HAL_IPC = xtrue])
AM_CONDITIONAL([ONEWIFI_CAC_APP_SUPPORT], [test x$ONEWIFI_CAC_APP_SUPPORT = xtrue])
AM_CONDITIONAL([ONEWIFI_STA_MGR_APP_SUPPORT], [test x$ONEWIFI_STA_MGR_APP_SUPPORT  = xtrue])
AM_CONDITIONAL([ONEWIFI_DML_SUPPORT], [test x$ONEWIFI_DML_SUPPORT_MAKEFILE = xtrue])
AM_CONDITIONAL([ONEWIFI_DBUS_SUPPORT], [test x$ONEWIFI_DBUS_SUPPORT = xtrue])
AM_CONDITIONAL([ONEWIFI_ANALYTICS_APP_SUPPORT], [test x$ONEWIFI_ANALYTICS_APP_SUPPORT = xtrue])
AM_CONDITIONAL([ONEWIFI_LEVL_APP_SUPPORT], [test x$ONEWIFI_LEVL_APP_SUPPORT = xtrue])
AM_CONDITIONAL([ONEWIFI_CSI_APP_SUPPORT], [test x$ONEWIFI_CSI_APP_SUPPORT = xtrue])
AM_CONDITIONAL([ONEWIFI_MOTION_APP_SUPPORT], [test x$ONEWIFI_MOTION_APP_SUPPORT = xtrue])
AM_CONDITIONAL([ONEWIFI_WHIX_APP_SUPPORT], [test x$ONEWIFI_WHIX_APP_SUPPORT = xtrue])
AM_CONDITIONAL([ONEWIFI_HARVESTER_APP_SUPPORT], [test x$ONEWIFI_HARVESTER_APP_SUPPORT = xtrue])
AM_CONDITIONAL([ONEWIFI_BLASTER_APP_SUPPORT], [test x$ONEWIFI_BLASTER_APP_SUPPORT = xtrue])
AM_CONDITIONAL([ONEWIFI_MEMWRAPTOOL_APP_SUPPORT], [test x$ONEWIFI_MEMWRAPTOOL_APP_SUPPORT = xtrue])
AM_CONDITIONAL([FEATURE_OFF_CHANNEL_SCAN_5G], [test x$FEATURE_OFF_CHANNEL_SCAN_5G = xtrue])
AM_CONDITIONAL([USE_DML_SOURCES], [test x$DEVICE_EXTENDER != xtrue])
AM_CONDITIONAL([USE_EXTENDER_MISC], [test x$DEVICE_EXTENDER = xtrue])
AM_CONDITIONAL([ONEWIFI_AVRO_SUPPORT], [test "x$ONEWIFI_BLASTER_APP_SUPPORT" = "xtrue" || "x$ONEWIFI_HARVESTER_APP_SUPPORT" = "xtrue"])

# Specify ccsp cpu arch

AC_ARG_WITH([ccsp-arch],
[AC_HELP_STRING([--with-ccsp-arch={arm,atom,pc,mips}],
                [specify the ccsp board CPU platform])],
[case x"$withval" in
   xarm)
     CCSP_ARCH=arm
     ;;
   xatom)
     CCSP_ARCH=atom
     ;;
   xpc)
     CCSP_ARCH=pc
     ;;
   xmips)
     CCSP_ARCH=mips
     ;;
   *)
     AC_MSG_ERROR([$withval is an invalid option to --with-ccsp-arch])
     ;;
 esac],
[CCSP_ARCH=''])
if test x"${CCSP_ARCH}" != x; then
  AC_DEFINE_UNQUOTED(CCSP_ARCH, "$CCSP_ARCH",
                     [The board CPU architecture])
fi

AM_CONDITIONAL(CCSP_ARCH_ARM, test "x$CCSP_ARCH" = xarm)
AM_CONDITIONAL(CCSP_ARCH_ATOM, test "x$CCSP_ARCH" = xatom)
AM_CONDITIONAL(CCSP_ARCH_PC, test "x$CCSP_ARCH" = xpc)
AM_CONDITIONAL(CCSP_ARCH_MIPS, test "x$CCSP_ARCH" = xmips)

AC_ARG_ENABLE([libwebconfig],
             [  --enable-libwebconfig    Turn on building libwebconfig, otherwise link against sysroot],
             [case "${enableval}" in
                yes) libwebconfig=true ;;
                 no) libwebconfig=false ;;
                  *) AC_MSG_ERROR([bad value ${enableval} for --enable-libwebconfig]) ;;
            esac],[libwebconfig=true])
AM_CONDITIONAL([LIBWEBCONFIG], [test x$libwebconfig = xtrue])

AC_ARG_ENABLE([rdk-wifi-libhostap],
    [AS_HELP_STRING([--enable-rdk-wifi-libhostap],[enable])],
    [
        case x"${enableval}" in
        xyes) CCSP_HOSTAP_AUTH=yes ;;
        xno) AC_MSG_ERROR([hostap authenticator is disabled]) ;;
        *) AC_MSG_ERROR([bad value ${enableval} for --enable-hostap-auth ]) ;;
        esac
    ],
[CCSP_HOSTAP_AUTH=''])
if test x"${CCSP_HOSTAP_AUTH}" != x; then
  AC_DEFINE_UNQUOTED(CCSP_HOSTAP_AUTH, "$CCSP_HOSTAP_AUTH",
                     [The CCSP platform device])
fi
# Specify ccsp platform (device)

AC_ARG_WITH([ccsp-platform],
[AC_HELP_STRING([--with-ccsp-platform={intel_usg,pc,bcm}],
                [specify the ccsp platform])],
[case x"$withval" in
   xintel_usg)
     CCSP_PLATFORM=intel_usg
     ;;
   xpc)
     CCSP_PLATFORM=pc
     ;;
   xbcm)
     CCSP_PLATFORM=bcm
     ;;
   *)
     AC_MSG_ERROR([$withval is an invalid option to --with-ccsp-platform])
     ;;
 esac],
[CCSP_PLATFORM=''])
if test x"${CCSP_PLATFORM}" != x; then
  AC_DEFINE_UNQUOTED(CCSP_PLATFORM, "$CCSP_PLATFORM",
                     [The CCSP platform device])
fi

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])

# Checks for programs.
AC_PROG_CC
AC_PROG_CXX
AC_PROG_INSTALL
AM_PROG_CC_C_O
AM_PROG_LIBTOOL(libtool)

SYSTEMD_CFLAGS=" "
SYSTEMD_LDFLAGS=" "

AC_ARG_ENABLE([notify],
        AS_HELP_STRING([--enable-notify],[enable systemd notify]),
        [
          case "${enableval}" in
           yes) SYSTEMD_CFLAGS="-DENABLE_SD_NOTIFY"
                SYSTEMD_LDFLAGS="-lsystemd" ;;
           no) AC_MSG_ERROR([systemd notify is disabled]) ;;
          *) AC_MSG_ERROR([bad value ${enableval} for --enable-notify ]) ;;
           esac
           ],
         [echo "systemd notify is disabled."])

AC_SUBST(SYSTEMD_CFLAGS)
AC_SUBST(SYSTEMD_LDFLAGS)

# Checks for header files.
AC_CHECK_HEADERS([stdlib.h string.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_C_INLINE

# Checks for library functions.
AC_FUNC_MALLOC

AC_CONFIG_FILES(
    source/platform/Makefile
    source/dml/tr_181/sbapi/Makefile
    source/dml/tr_181/ml/Makefile
    source/dml/tr_181/Makefile
    source/dml/Makefile
    source/dml/dml_webconfig/Makefile
    source/core/Makefile
    source/Makefile
    source/sampleapps/Makefile
    source/utils/Makefile
    Makefile
)

AC_SUBST(GTEST_ENABLE_FLAG)
AC_OUTPUT

