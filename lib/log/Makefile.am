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

AM_LDFLAGS += -lev

CcspWifiSsp_CFLAGS += $(JOURNALCTL_ENABLE_FLAG)

CcspWifiSsp_SOURCES += log.c log_syslog.c log_stdout.c log_traceback.c

if JOURNALCTL_SUPPORT
CcspWifiSsp_SOURCES += log_journal.c
endif

CcspWifiSsp_LDFLAGS_LDFLAGS += -lev

