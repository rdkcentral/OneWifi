/*
 * If not stated otherwise in this file or this component's LICENSE file the
 * following copyright and licenses apply:
 *
 * Copyright 2016 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/
/*
 * Mock header for unit test simulation of telemetry_busmessage_sender.h
 */
#ifndef TELEMETRY_BUSMESSAGE_SENDER_H
#define TELEMETRY_BUSMESSAGE_SENDER_H

// Minimal type definitions for unit test
#include <stddef.h>
#include <stdbool.h>

typedef enum {
    T2ERROR_SUCCESS = 0,
    T2ERROR_FAILURE = 1
} T2ERROR;

static inline void t2_init(char* name) {
    (void)name;  // stub: parameter intentionally unused
}

static inline T2ERROR t2_event_s(const char* marker, char* value) {
    (void)marker; (void)value;  // stub: parameters intentionally unused
    return T2ERROR_SUCCESS;
}

static inline T2ERROR t2_event_d(const char* marker, int value) {
    (void)marker; (void)value;
    return T2ERROR_SUCCESS;
}

static inline T2ERROR t2_event_f(const char* marker, double value) {
    (void)marker; (void)value;
    return T2ERROR_SUCCESS;
}

#endif // TELEMETRY_BUSMESSAGE_SENDER_H
