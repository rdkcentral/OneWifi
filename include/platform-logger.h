/************************************************************************************
  If not stated otherwise in this file or this component's LICENSE file the
  following copyright and licenses apply:
  
  Copyright 2018 RDK Management
  
  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at
  
  http://www.apache.org/licenses/LICENSE-2.0
  
  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
 **************************************************************************/

#if CCSP_COMMON
#include <ccsp_trace.h>
#else
#include "wifi_util.h"
#endif //CCSP_COMMON

#if CCSP_COMMON
#define platform_trace_error(module, format, ...)    CcspTraceError((format, ##__VA_ARGS__))
#define platform_trace_warning(module, format, ...)  CcspTraceWarning((format, ##__VA_ARGS__))
#else
#define platform_trace_error(module, format, ...)    wifi_util_dbg_print(module, format, ##__VA_ARGS__)
#define platform_trace_warning(module, format, ...)  wifi_util_dbg_print(module, format, ##__VA_ARGS__)
#endif //CCSP_COMMON
