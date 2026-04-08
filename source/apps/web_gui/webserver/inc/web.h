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

#ifndef WEB_H
#define WEB_H

#include "common_defs.h"
#include <sys/un.h>

#define MOTION_WEB_SOCK "/tmp/motion_web.sock"

#define WEB_ASSOCIATED_CLIENTS_NAME "motion/associated_clients"

#define WEB_ANALYZE_CSI "/motion/analyze-csi"
#define WEB_SAVE_CSI "/motion/save-csi"
#define WEB_ABORT_CSI "/motion/abort-csi"
#define WEB_CAPTURE_CSI "/motion/capture-csi"
#define WEB_MOTION_INFO_CSI "/motion/motion-info-csi"

typedef enum {
    web_data_extn_type_js,
    web_data_extn_type_ico,
    web_data_extn_type_jpg,
    web_data_extn_type_png,
    web_data_extn_type_php,
    web_data_extn_type_html,
    web_data_extn_type_json,
    web_data_extn_type_css,
    web_data_extn_type_plain,
    web_data_extn_type_none
} web_data_extn_type_t;

typedef enum {
    web_event_type_csi_analyze,
    web_event_type_csi_abort,
    web_event_type_csi_save,
    web_event_type_csi_capture,
    web_event_type_csi_motion_info,
    web_event_type_max
} web_event_type_t;

typedef struct web_event {
    web_event_type_t type;
    char *buff;
} web_event_t;

class web_t {
    bool m_exit;
    char m_http_header[MAX_HTTP_HDR_SZ];
    char m_head[PATH_NAME_SZ];
    struct sockaddr_in m_address;
    int m_server_fd;
    
public:
    int init();
    void deinit();
    
    int start();
    void stop();
    
    int run();
    int server();
    int server(int sock);
    
    void handle_get(int sock, const char *action_string);
    void handle_post(int sock, const char *action_string, char *buff);
    
    char* parse(char line[], const char symbol[]);
    char* parse_method(char line[], const char symbol[]);
    char* find_value(char *buff, const char *name, char *value);
    int send_message(int fd, web_data_extn_type_t data_type, bool file, const char *data);
    
    web_data_extn_type_t get_file_extension(const char *file_name);
    web_event_type_t get_event_type(const char *action);
    
    static void *server(void *arg);
    static void *run(void *arg);
    
public:
    web_t(const char *path);
	~web_t();
};

extern void push_web_event(web_event_t *evt);

#endif
