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
#######################################################################
#   Copyright [2014] [Cisco Systems, Inc.]
# 
#   Licensed under the Apache License, Version 2.0 (the \"License\");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
# 
#       http://www.apache.org/licenses/LICENSE-2.0
# 
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an \"AS IS\" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
#######################################################################

#
#   for Intel USG, Pumba 6, all ARM boards
#   P&M custom makefile, included pre main makefile
#

#
#   component list
#
WIFI_BUILD_TR_181=1
WIFI_BUILD_WIFI=0

#
#   platform specific customization
#
ifneq ($(wildcard $(SDK_PATH)/ti/include), )
INCPATH += $(SDK_PATH)/ti/netdk/src/ti_udhcp
INCPATH += $(SDK_PATH)/ti/docsis/src/common/docsis_mac/docsis_db/include
INCPATH += $(SDK_PATH)/ti/docsis/src/common/management/sys_cfg_db/include
INCPATH += $(SDK_PATH)/ti/docsis/src/pform/hal_vendor/hal_tuners/hal_tuner_manager_api/include
INCPATH += $(SDK_PATH)/ti/pacm/src/common/src/common_util/include
endif
INCPATH += $(CCSP_ROOT_DIR)/CcspPandM/custom/comcast/source/TR-181/custom_include
CFLAGS += $(TI_ARM_INC_DIR)
LDFLAGS += $(ldflags-y) -lpompt -lpthread -lswctl -llmapi -lmoca_mgnt

ifeq ($(CONFIG_CISCO_HOTSPOT), y)
    CFLAGS += -DCONFIG_CISCO_HOTSPOT
endif

ifeq ($(CONFIG_TI_BBU), y)
  LDFLAGS += -lbbu
endif

LDFLAGS += -lcurl -lcrypto

LDFLAGS += $(CM_LDFLAGS) $(MOCA_LDFLAGS) -lutapi -lutctx -lsyscfg -lsysevent -lulog -lnvramstorage -lticc -lutils_docsis -ldocsis_shared_dbs -lqos_internal_db -lfccfg -lti_sme -lsme

