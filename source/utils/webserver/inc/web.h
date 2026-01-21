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

#define PORT 8082
#define MAX_HTTP_HDR_SZ     64
#define PATH_NAME_SZ     1024

class web_t {
    bool m_exit;
    char m_http_header[MAX_HTTP_HDR_SZ];
    char m_head[PATH_NAME_SZ];
    struct sockaddr_in m_address;
    int m_server_fd;
    pthread_t m_run_tid;
    static web_t *instance;
    web_t(const char *path);

public:
    int init();
    void deinit();

    int start();
    void stop();
    int run();
    int server();
    int server(int sock);
 
    char* parse(char line[], const char symbol[]);
    char* parse_method(char line[], const char symbol[]);
    char* find_token(char line[], const char symbol[], const char match[]);
    int send_message(int fd, char image_path[], char head[]);
    
    static void *server(void *arg);
    static void *run(void *arg);
    static web_t* get_instance(const char *path);
    
public:
    ~web_t();
};

#endif
