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
 * <rbus/rbus.h> is provided by the rbus package on real RDK builds. The linux
 * mock/coverage build uses the he_bus abstraction instead, but source/apps/cac
 * carries an unconditional `#include <rbus/rbus.h>` while referencing no rbus
 * symbols. This empty stub satisfies that include without pulling rbus in.
 * If a coverage tier ever needs real rbus types, expand this stub.
 * Or remove reference to it from source/apps/cac.
 *
 * This file is NOT upstream and must never be pushed; it lives under
 * build/linux/compat and is only on the include path for the coverage builds.
 */

#ifndef RBUS_RBUS_FAKE_H
#define RBUS_RBUS_FAKE_H
#endif /* RBUS_RBUS_FAKE_H */
