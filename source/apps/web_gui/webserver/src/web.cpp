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

#include <stdio.h>
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
#include <sys/time.h>
#include "utils.h"
#include <sys/sendfile.h>
#include <errno.h>
#include <pthread.h>

#include "web.h"
#include <sys/un.h>
#include "common_web_gui.h"
#include "wifi_util.h"

typedef struct {
    web_t *web;
    int sock;
} web_args_t;

char* web_t::parse(char line[], const char symbol[])
{
    char *copy = (char *)malloc(strlen(line) + 1);
    strcpy(copy, line);

    char *message;
    char * token = strtok(copy, symbol);
    int current = 0;

    while (token != NULL) {

        token = strtok(NULL, " ");
        if (current == 0) {
            message = token;
            return message;
        }
        current = current + 1;
    }
   
    free(token);
    free(copy);
   
    return NULL;
}

char* web_t::parse_method(char line[], const char symbol[])
{
    char *copy = (char *)malloc(strlen(line) + 1);
    strcpy(copy, line);

    char *message = NULL;
    char * token = strtok(copy, symbol);
    int current = 0;

    while (token != NULL) {

      //token = strtok(NULL, " ");
        if (current == 0) {
            message = token;
            return message;
        }
        current = current + 1;
    }
    free(copy);
    free(token);
    return NULL;
}

char* web_t::find_value(char *buff, const char *name, char *value)
{
    char *tmp, *start, *end;
    const char *delim = "\r\n";
    
    if ((tmp = strstr(buff, name)) == NULL) {
        return NULL;
    }
    start = tmp + strlen(name) + 1;
    if ((end = strstr(start, delim)) == NULL) {
        return NULL;
    }
    
    strncpy(value, start, (end - start));
    
    return value;
}

web_data_extn_type_t web_t::get_file_extension(const char *file_name)
{
    char *delim, *tmp;
    
    if ((delim = strchr((char *)file_name, '.')) == NULL) {
        return web_data_extn_type_none;
    }
    
    tmp = (char *)file_name;
    
    while ((delim = strchr(tmp, '.')) != NULL) {
        tmp = delim; tmp++;
    }
    
    // tmp points to the last '.'
    delim = tmp;
    
    if (strncmp(delim, "js", strlen("js")) == 0) {
        return web_data_extn_type_js;
    } else if (strncmp(delim, "json", strlen("json")) == 0) {
        return web_data_extn_type_json;
    } else if (strncmp(delim, "html", strlen("html")) == 0) {
        return web_data_extn_type_html;
    } else if (strncmp(delim, "css", strlen("css")) == 0) {
        return web_data_extn_type_css;
    } else if (strncmp(delim, "ico", strlen("ico")) == 0) {
        return web_data_extn_type_ico;
    } else if (strncmp(delim, "php", strlen("php")) == 0) {
        return web_data_extn_type_php;
    } else if (strncmp(delim, "jpg", strlen("jpg")) == 0) {
        return web_data_extn_type_jpg;
    } else if (strncmp(delim, "png", strlen("png")) == 0) {
        return web_data_extn_type_png;
    }
    
    return web_data_extn_type_none;
}

web_event_type_t web_t::get_event_type(const char *action)
{
    web_event_type_t type = web_event_type_max;
    
    if (strncmp(action, "/analyze-csi", strlen("/analyze-csi")) == 0) {
        type = web_event_type_csi_analyze;
    } else if (strncmp(action, "/abort-csi", strlen("/abort-csi")) == 0) {
        type = web_event_type_csi_abort;
    } else if (strncmp(action, "/save-csi", strlen("/save-csi")) == 0) {
        type = web_event_type_csi_save;
    } else if (strncmp(action, "/capture-csi", strlen("/capture-csi")) == 0) {
        type = web_event_type_csi_capture;
    } else if (strncmp(action, "/motion-info-csi", strlen("/motion-info-csi")) == 0) {
        type = web_event_type_csi_motion_info;
    }
    
    return type;
}

int web_t::send_message(int fd, web_data_extn_type_t data_type, bool file, const char *data)
{
    int fdfile;
    struct stat stat_buf;  /* hold information about input file */
    off_t total_size, offset = 0;
    off_t len = 0;
    char value[RESP_BUFF_SZ];
    char head[PATH_NAME_SZ] = {0};
    
    strncpy(head, m_http_header, strlen(m_http_header) + 1);
    
    switch (data_type) {
        case web_data_extn_type_plain:
            strcat(head, "Content-Type: text/plain\r\n");
            break;
        
        case web_data_extn_type_html:
            strcat(head, "Content-Type: text/html\r\n");
            break;
            
        case web_data_extn_type_js:
            strcat(head, "Content-Type: text/javascript\r\n");
            break;
            
        case web_data_extn_type_css:
            strcat(head, "Content-Type: text/css\r\n");
            break;
       
        case web_data_extn_type_json:
            strcat(head, "Content-Type: application/json\r\n");
            break;
            
        case web_data_extn_type_ico:
            strcat(head, "Content-Type: image/vnd.microsoft.icon\r\n");
            break;
            
        case web_data_extn_type_jpg:
            strcat(head, "Content-Type: image/jpeg\r\n");
            break;
            
        case web_data_extn_type_png:
            strcat(head, "Content-Type: image/png\r\n");
            break;
            
        case web_data_extn_type_php:
            strcat(head, "Content-Type: text/plain\r\n");
            break;
            
        default:
            strcat(head, "Content-Type: text/plain\r\n");
    }
   
    if (file == false) {
        snprintf(value, sizeof(value), "Content-Length: %zu\r\n\r\n", strlen(data));
        strcat(head, value);
        write(fd, head, strlen(head));
        write(fd, data, strlen(data));
        return 0;
    }

    if((fdfile = open(data, O_RDONLY)) < 0){
        wifi_util_error_print(WIFI_WEB_GUI,"%s:%d: Cannot Open file path :%s with error %d\n", __func__, __LINE__, data, fdfile);
        snprintf(value, sizeof(value), "Content-Length: 0");
        strcat(head, value);
        write(fd, head, strlen(head));
        return -1;
    }

    fstat(fdfile, &stat_buf);
    total_size = stat_buf.st_size;
    wifi_util_dbg_print(WIFI_WEB_GUI,"total_size:%lld\r\n", (long long)total_size);
    snprintf(value, sizeof(value), "Content-Length: %lld\r\n\r\n", (long long)total_size);
    strcat(head, value);
    wifi_util_dbg_print(WIFI_WEB_GUI,"write message:%s\r\n", head);
    write(fd, head, strlen(head));

    wifi_util_dbg_print(WIFI_WEB_GUI,"total_size:%lld, offset:%lld\r\n",
        (long long)total_size, (long long)offset);
    while (offset < total_size) {
        len = total_size - offset;
        ssize_t sent = sendfile(fd, fdfile, &offset, len);
        if (sent <= 0) {
            wifi_util_error_print(WIFI_WEB_GUI,"send file is failed:%d\r\n", sent);
            close(fdfile);
            return -1;
        }
        wifi_util_dbg_print(WIFI_WEB_GUI,"sent:%lld, offset:%lld\r\n",
            (long long)sent, (long long)offset);
        offset += len;
    }
    
    close(fdfile);
    
    return 0;
}
    
void web_t::handle_get(int sock, const char *action_string)
{
    web_data_extn_type_t extn_type;
    char file_name[PATH_NAME_SZ] = {0};
    char *tmp;
    
    strncpy(file_name, m_head, strlen(m_head) + 1);
    wifi_util_dbg_print(WIFI_WEB_GUI,"%s:%d action_string:%s\r\n", __func__, __LINE__, action_string);

    if (strlen(action_string) <= 1) {
        strcat(file_name, "/index.html");
        wifi_util_dbg_print(WIFI_WEB_GUI,"%s:%d: file_name:%s\n", __func__, __LINE__, file_name);
        send_message(sock, web_data_extn_type_html, true, file_name);
    } else if ((tmp = strchr((char *)action_string, '/')) != NULL) {
        tmp++;
        extn_type = get_file_extension(tmp);
        if (extn_type == web_data_extn_type_none) {

            wifi_util_dbg_print(WIFI_WEB_GUI,"%s:%d: file_name:%s tmp message:%s\n", __func__,
                __LINE__, file_name, tmp);
            if (strncmp(tmp, "associated_clients", strlen("associated_clients")) == 0) {
                strcat(file_name, "/associated_clients.json");
                // send associated clients list
                
                send_message(sock, web_data_extn_type_json, true, file_name);
            }
            
        } else {
            //send real file
            strcat(file_name, action_string);
            send_message(sock, extn_type, true, file_name);
        }
    }
}
    
void web_t::handle_post(int sock, const char *action_string, char *buffer)
{
    char value[RESP_BUFF_SZ], *tmp;
    web_event_t *evt;
    ssize_t len, total_len = 0, expected_len;
    char resp_data[RESP_BUFF_SZ] = {0};
    
    
    if ((strncmp(action_string, "/analyze-csi", strlen("/analyze-csi")) == 0) || (strncmp(action_string, "/save-csi", strlen("/save-csi")) == 0)) {
        
        if ((tmp = find_value(buffer, "Content-Length", value)) != NULL) {
            evt = (web_event_t *)malloc(sizeof(web_event_t));
            evt->type = get_event_type(action_string);
            
            total_len = 0;
            expected_len = atoi(value);
            
            evt->buff = (char *)malloc(MAX_BUFF_SIZE);
            while ((total_len < expected_len) && (len = read(sock, &evt->buff[total_len], MAX_BUFF_SIZE - total_len)) > 0) {
                total_len += len;
            }
            
            if (total_len > 0) {
                //utils_t::print_hex_dump((unsigned int)total_len, (unsigned char *)evt->buff);
                push_web_event(evt);
                snprintf(resp_data, sizeof(resp_data), "{\"Status\": \"Event Pushed\"}");
                
            } else {
                free(evt->buff);
                free(evt);
                snprintf(resp_data, sizeof(resp_data), "{\"Status\": \"Event Not Pushed\"}");
                
            }

            send_message(sock, web_data_extn_type_json, false, resp_data);
        }
    } else if (strncmp(action_string, "/abort-csi", strlen("/abort-csi")) == 0) {
        evt = (web_event_t *)malloc(sizeof(web_event_t));
        evt->type = get_event_type(action_string);
        evt->buff = NULL;
        push_web_event(evt);
        snprintf(resp_data, sizeof(resp_data), "{\"Status\": \"Event Pushed\"}");
        send_message(sock, web_data_extn_type_json, false, resp_data);
    } else if (strncmp(action_string, "/capture-csi", strlen("/capture-csi")) == 0) {
        if ((tmp = find_value(buffer, "Content-Length", value)) != NULL) {
            evt = (web_event_t *)malloc(sizeof(web_event_t));
            evt->type = get_event_type(action_string);
            
            total_len = 0;
            expected_len = atoi(value);
            
            evt->buff = (char *)malloc(MAX_SMALL_BUFF_SIZE);
            while ((total_len < expected_len) && (len = read(sock, &evt->buff[total_len], MAX_BUFF_SIZE - total_len)) > 0) {
                total_len += len;
            }
            
            if (total_len > 0) {
                //utils_t::print_hex_dump((unsigned int)total_len, (unsigned char *)evt->buff);
                push_web_event(evt);
                snprintf(resp_data, sizeof(resp_data), "{\"Status\": \"Event Pushed\", \"FileName\": \"csi_samples_Static.json\"}");
                
            } else {
                free(evt->buff);
                free(evt);
                snprintf(resp_data, sizeof(resp_data), "{\"Status\": \"Event Not Pushed\"}");
                
            }

            send_message(sock, web_data_extn_type_json, false, resp_data);
        }
    } else if (strncmp(action_string, "/motion-info-csi", strlen("/motion-info-csi")) == 0) {
        if ((tmp = find_value(buffer, "Content-Length", value)) != NULL) {
            evt = (web_event_t *)malloc(sizeof(web_event_t));
            evt->type = get_event_type(action_string);
            
            total_len = 0;
            expected_len = atoi(value);
            
            evt->buff = (char *)malloc(MAX_SMALL_BUFF_SIZE);
            while ((total_len < expected_len) && (len = read(sock, &evt->buff[total_len], MAX_BUFF_SIZE - total_len)) > 0) {
                total_len += len;
            }
            
            if (total_len > 0) {
                //utils_t::print_hex_dump((unsigned int)total_len, (unsigned char *)evt->buff);
                push_web_event(evt);
                snprintf(resp_data, sizeof(resp_data), "{\"Status\": \"Event Pushed\"}");
                
            } else {
                free(evt->buff);
                free(evt);
                snprintf(resp_data, sizeof(resp_data), "{\"Status\": \"Event Not Pushed\"}");
                
            }

            send_message(sock, web_data_extn_type_json, false, resp_data);
        }
    }
    
}

int web_t::server(int sock)
{
    char buffer[30000] = {0};
    long valread;
    char *method, *action;

    wifi_util_dbg_print(WIFI_WEB_GUI,"%s:%d:waiting for child data\n", __func__, __LINE__);

    valread = read(sock, buffer, sizeof(buffer));
    if (valread <= 0) {
        wifi_util_error_print(WIFI_WEB_GUI,"%s:%d client stop:%ld\r\n", __func__, __LINE__, valread);
        close(sock);
        return -1;
    }

    wifi_util_dbg_print(WIFI_WEB_GUI,"%s:%d buffer:%s\r\n", __func__, __LINE__, buffer);
    if ((method = parse_method(buffer, " ")) == NULL) {  //Try to get the path which the client ask for
        wifi_util_error_print(WIFI_WEB_GUI,"%s:%d buffer:%s\r\n", __func__, __LINE__, buffer);
        return -1;
    }

    if ((action = parse(buffer, " ")) == NULL) {
        wifi_util_error_print(WIFI_WEB_GUI,"%s:%d buffer:%s\r\n", __func__, __LINE__, buffer);
        return -1;
    }

    wifi_util_dbg_print(WIFI_WEB_GUI,"%s:%d: Method: %s\tString:%s\n", __func__, __LINE__, method, action);

    if (strncmp(method, "GET", strlen("GET")) == 0) {
        handle_get(sock, action);
    } else if (strncmp(method, "POST", strlen("POST")) == 0) {
        handle_post(sock, action, buffer);
    }

    free(method);
    free(action);
    close(sock);

    return 0;
}

void *web_t::server(void *arg)
{
    web_args_t *args = (web_args_t *)arg;
    web_t *web = args->web;
    
    web->server(args->sock);

    free(args);

    return NULL;
}



int web_t::run()
{
    pthread_t stid;
    pthread_attr_t attr;
    size_t stack_size = 1024 * 1024; // Example: 1 MB stack size
    int new_sock;
    int addrlen = sizeof(m_address);
    
    while (m_exit == false) {
        if ((new_sock = accept(m_server_fd, (struct sockaddr *)&m_address, (socklen_t*)&addrlen))<0) {
            wifi_util_error_print(WIFI_WEB_GUI,"%s:%d: Error in accept: %d\n", __func__, __LINE__, errno);
            return -1;
        }

        web_args_t *args = (web_args_t *)malloc(sizeof(web_args_t));
        args->web = this;
        args->sock = new_sock;

        pthread_attr_init(&attr);
        pthread_attr_setstacksize(&attr, stack_size);
        if (pthread_create(&stid, &attr, server, args) != 0) {
            wifi_util_error_print(WIFI_WEB_GUI,"%s:%d: Failed to start child thread\n", __func__, __LINE__);
            return -1;
        } else {
            pthread_detach(stid);
            wifi_util_info_print(WIFI_WEB_GUI,"%s:%d:started child thread\n", __func__, __LINE__);
        }
    }
    
    return 0;
}

void *web_t::run(void *arg)
{
    
    web_t *web = (web_t *)arg;
    
    web->run();
    
    return NULL;
}

void web_t::stop()
{
    m_exit = true;
    close(m_server_fd);
}

int web_t::start()
{
    
    pthread_t tid;
    pthread_attr_t attr;
    size_t stack_size = 1024 * 1024; // Example: 1 MB stack size

    wifi_util_info_print(WIFI_WEB_GUI,"%s:%d web server start\r\n", __func__, __LINE__);

    if (init() != 0) {
        wifi_util_error_print(WIFI_WEB_GUI,"%s:%d: Error in initializing server\n", __func__, __LINE__);
        return -1;
    }
    
    // Creating socket file descriptor
    if ((m_server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        wifi_util_error_print(WIFI_WEB_GUI,"%s:%d: Error in cfreating socket: %d\n", __func__, __LINE__, errno);
        return -1;
    } else {
        wifi_util_info_print(WIFI_WEB_GUI,"%s:%d web server socket created:%d\r\n",
            __func__, __LINE__, m_server_fd);
    }

    if (bind(m_server_fd, (struct sockaddr *)&m_address, sizeof(m_address))<0) {
        wifi_util_error_print(WIFI_WEB_GUI,"%s:%d: Error in binding: %d\n", __func__, __LINE__, errno);
        close(m_server_fd);
        return -1;
    }
    
    if (listen(m_server_fd, 10) < 0) {
        wifi_util_error_print(WIFI_WEB_GUI,"%s:%d: Error in listen: %d\n", __func__, __LINE__, errno);
        return -1;
    }
    
    pthread_attr_init(&attr);
    pthread_attr_setstacksize(&attr, stack_size);
    
    if (pthread_create(&tid, &attr, run, this) != 0) {
        wifi_util_error_print(WIFI_WEB_GUI,"%s:%d: Failed to start child thread\n", __func__, __LINE__);
        return -1;
    } else {
        pthread_detach(tid);
        wifi_util_info_print(WIFI_WEB_GUI,"%s:%d web server run pthread create\r\n", __func__, __LINE__);
     }
    
    return 0;
}

void web_t::deinit()
{
    
}

int web_t::init()
{
    
    snprintf(m_http_header, sizeof(m_http_header), "HTTP/1.1 200 Ok\r\n");
    m_exit = false;
    
    m_address.sin_family = AF_INET;
    m_address.sin_addr.s_addr = INADDR_ANY;
    m_address.sin_port = htons(PORT);

    memset(m_address.sin_zero, '\0', sizeof m_address.sin_zero);
    
    return 0;
}

web_t::web_t(const char *path)
{
    strncpy(m_head, path, strlen(path) + 1);
}

web_t::~web_t()
{
    
}

extern "C" int init_web_server_param(web_gui_obj_t *p_web_mgr)
{
    p_web_mgr->web_server = new web_t(WEB_SERVER_PATH);
    wifi_util_info_print(WIFI_WEB_GUI,"%s:%d init web server param\r\n", __func__, __LINE__);
    p_web_mgr->web_server->start();

    return 0;
}
