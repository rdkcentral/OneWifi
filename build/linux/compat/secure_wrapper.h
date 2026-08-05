/************************************************************************************
  If not stated otherwise in this file or this component's LICENSE file the
  following copyright and licenses apply:

  Copyright 2026 RDK Management

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
/*
 * CI coverage-build compatibility header.
 *
 * secure_wrapper.h (RDK libsecure_wrapper: v_secure_system / v_secure_popen ...)
 * is provided by utopia on full RDK builds. The linux mock/coverage build does
 * not link libsecure_wrapper; source/stubs/wifi_stubs.c already supplies a
 * v_secure_system stub symbol. Apps such as whix include this header but reach
 * the API only through function pointers, so these prototypes just satisfy the
 * include.
 *
 * This file is NOT upstream and must never be pushed; it lives under
 * build/linux/compat and is only on the include path for the coverage builds.
 */

#ifndef SECURE_WRAPPER_FAKE_H
#define SECURE_WRAPPER_FAKE_H

#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

int   v_secure_system(const char *command);
FILE *v_secure_popen(const char *direction, const char *fmt, ...);
int   v_secure_pclose(FILE *stream);

#ifdef __cplusplus
}
#endif

#endif /* SECURE_WRAPPER_FAKE_H */
