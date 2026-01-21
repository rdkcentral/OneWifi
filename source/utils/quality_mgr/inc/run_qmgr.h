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

#ifndef RUN_H
#define RUN_H
#ifdef __cplusplus
extern "C" {
#endif
#define MAX_LINE_SIZE   1024
//#define MAX_BUFF_SIZE   MAX_LINE_SIZE*1000
 #define MAX_FILE_NAME_SZ 1024

#define MAX_LINKQ_PARAMS    3
#define THRESHOLD 0.4
#define SAMPLING_INTERVAL 5
#define REPORTING_INTERVAL 10
#include "wifi_base.h"
typedef struct {
    int socket;
    char path[MAX_FILE_NAME_SZ];
    char output_file[MAX_FILE_NAME_SZ];
    double threshold;
    unsigned int sampling;
    unsigned int reporting;
} server_arg_t;

typedef struct {
    mac_addr_str_t mac_str;
    unsigned int vap_index;
    double per;
    unsigned int snr;
    unsigned int phy;
    unsigned int max_phy;
  } stats_arg_t;

typedef void (*qmgr_report_cb_t)(const report_batch_t *report);

int run_web_server();
int stop_web_server(const char *path);
/* Registration function (called from C main) */
void qmgr_register_callback(qmgr_report_cb_t cb);
void qmgr_invoke_callback(const report_batch_t *batch);

int add_stats_metrics(stats_arg_t *stats);
int remove_link_stats(stats_arg_t *stats);
int start_link_metrics();
int reinit_link_metrics(server_arg_t *arg);
#ifdef __cplusplus
}
#endif
#endif
