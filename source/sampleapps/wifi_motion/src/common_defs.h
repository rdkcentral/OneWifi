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

#ifndef COMMON_DEFS_H
#define COMMON_DEFS_H

#include <sys/socket.h>
#include <unistd.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>

#define PORT 8081
#define MAX_HTTP_HDR_SZ     64
#define PATH_NAME_SZ     1024
#define RESP_BUFF_SZ     1024
#define MAX_LINE_SIZE   PATH_NAME_SZ
#define MAX_BUFF_SIZE   MAX_LINE_SIZE*1000*40
#define MAX_SMALL_BUFF_SIZE   MAX_LINE_SIZE*40

typedef struct {
    unsigned int algorithm_window;
    unsigned int variance_threshold;
    unsigned int consecutive_samples;
    unsigned int antenna_considerations;
} motion_algorithm_params_t;


typedef struct {
    unsigned int reporting;
    unsigned int start_frame;
    unsigned int end_frame;
    motion_algorithm_params_t   algo_params;
} motion_test_params_t;

#endif
