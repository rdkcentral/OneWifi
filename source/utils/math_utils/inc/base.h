/**
 * Copyright 2023 Comcast Cable Communications Management, LLC
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
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef BASE_H
#define BASE_H

#include "wifi_util.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_LEN 128
#define MAX_MTRX_LEN MAX_LEN / 4
#define PI 3.14159

typedef char expr_t[32];
typedef char large_expr_t[2048];

typedef struct {
    unsigned int num;
    expr_t val[MAX_LEN];
} vector_s_t;

typedef struct {
    unsigned int rows;
    unsigned int cols;
    expr_t val[MAX_MTRX_LEN][MAX_MTRX_LEN];
} matrix_s_t;

typedef struct {
    double upper_limit;
    double lower_limit;
    double increments;
} bounds_t;

#ifdef __cplusplus
}
#endif

#endif
