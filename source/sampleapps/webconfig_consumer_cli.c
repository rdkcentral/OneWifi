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

#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include "wifi_hal.h"
#include "webconfig_consumer_cli.h"

sample_app_cli_task_t cli_task_obj;

void print_help_msg(void)
{
    printf("\r\n|**************************************************************|\r\n");
    printf("Please use below command to start test\r\n");
    printf("-w radio [parameters JSON blob file path]    { Test radio subdocument }\r\n");
    printf("-w private [parameters JSON blob file path]  { Test private subdocument }\r\n");
    printf("-w mesh [parameters JSON blob file path]     { Test mesh subdocument }\r\n");
    printf("-w xfinity [parameters JSON blob file path]  { Test xfinity subdocument }\r\n");
    printf("-w home [parameters JSON blob file path]     { Test home subdocument }\r\n");
    printf("-w lnf [parameters JSON blob file path]      { Test lnf subdocument }\r\n");
    printf("-w macfilter [parameters JSON blob file path]{ Test macfilter subdocument }\r\n");
    printf("-w all [parameters JSON blob file path]      { Tests all existing WebConfig Subdocuments one after other }\r\n");
    printf("-w sync                                      { Test dml sync subdocument }\r\n");
    printf("-w meshsta                                   { Test meshsta subdocument }\r\n");
    printf("-c 0                                         { WAN Manager External gateway absent }\r\n");
    printf("-c 1                                         { WAN Manager External gateway present }\r\n");
    printf("-o sync                                      { Test dml subdocument for ovsdb destination, execute this before any -o test cases}\r\n");
    printf("-o radio                                     { Test radio subdocument for ovsdb }\r\n");
    printf("-o mesh                                      { Test mesh subdocument for ovsdb}\r\n");
    printf("-o macfilter                                 { Test macfilter subdocument for ovsdb}\r\n");
    printf("-o null                                      { Test null subdocument for ovsdb}\r\n");
    printf("-o meshsta                                   { Test meshsta subdocument for ovsdb}\r\n");
    printf("-o lnf                                       { Test lnf subdocument for ovsdb}\r\n");
    printf("-o home                                      { Test home subdocument for ovsdb}\r\n");
    printf("-o private                                   { Test private subdocument for ovsdb}\r\n");
    printf("-o getsubdoc                                 { Test to get subdoctype from input ifname}\r\n");
    printf("-d <1>/<0>                                   { 1 for enable log and 0 for disable the /tmp/log_<subdoc> file creation}\r\n");
    printf("-t 1                                         { Tunnel Up event }\r\n");
    printf("-t 0                                         { Tunnel Down event }\r\n");
    printf("-a DeviceNetworkMode <1>/<0>                 { 0 for device gateway mode and 1 for device station mode }\r\n");
    printf("-kickmac <ap_index-maclist-timeout>          { kick associated devices , to kick all <ap_index-ff:ff:ff:ff:ff:ff-timeout>}\r\n");
    printf("wps <vap_index>                              { Trigger wps test case }\r\n");
    printf("rbusGet <properties> [properties1]           { Trigger rbus get command }\r\n");
    printf("mgmtFrameSend <ap_index> <packet_input.txt>  { Trigger this command to injecting 802.11 frames }\r\n");
    printf("mpcap <ap_index> <pcap file>                 { Trigger this command to injecting 802.11 frames from pcap files}\r\n");
    printf("help\r\n");
    printf("exit                                         { exit wifi webconfig consumer sample app}\r\n");
    printf("|**************************************************************|\r\n");
}

/* The function returns a pointer to allocated memory or NULL in case of error */
char *read_subdoc_input_param_from_file(char *file_path)
{
    FILE *file_ptr = NULL;
    char *read_data = NULL;
    unsigned int data_len = 0;
    // Opening file in reading mode
    file_ptr = fopen(file_path, "r");
    if (file_ptr == NULL) {
        printf("%s:%d file can't be opened:%s \r\n", __func__, __LINE__, file_path);
        return NULL;
    } else {
        fseek(file_ptr, 0, SEEK_END);
        data_len = ftell(file_ptr);
        fseek(file_ptr, 0, SEEK_SET);
        if (data_len != 0) {
            read_data = (char *)calloc(data_len, sizeof(char));
            if (read_data == NULL) {
                printf("%s:%d Failed to allocate memory.\r\n", __func__, __LINE__);
                fclose(file_ptr);
                return NULL;
            }
            if (fread(read_data, data_len, 1, file_ptr) != 0) {
                printf("%s:%d file read success:%s data len:%d\r\n", __func__, __LINE__, file_path, data_len);
            } else {
                printf("%s:%d file read failure:%s data len:%d\r\n", __func__, __LINE__, file_path, data_len);
                fclose(file_ptr);
                free(read_data);
                return NULL;
            }
        } else {
            printf("%s:%d Empty file:%s\r\n", __func__, __LINE__, file_path);
            fclose(file_ptr);
            return NULL;
        }
    }
    fclose(file_ptr);
    return read_data;
}

int get_next_word(char **word)
{
    *word = strtok(NULL, " ");
    if (*word == NULL) {
        printf("%s:%d wrong user input:\r\n", __func__, __LINE__);
        print_help_msg();
        return RETURN_ERR;
    }

    return RETURN_OK;
}

int parse_cli_input_msg(char *msg)
{
    char *first_arg, *second_arg, *third_arg;
    int ret = RETURN_OK;
    if (!strncmp(msg, "help", strlen("help"))) {
        print_help_msg();
    } else if (!strncmp(msg, "exit", strlen("exit"))) {
        de_init_rbus_object();
        cli_task_obj.exit_cli = true;
        exit_consumer_queue_loop();
    } else {
        first_arg = strtok(msg, " ");
        second_arg = strtok(NULL, " ");
        if ((first_arg == NULL) || (second_arg == NULL)) {
            printf("%s:%d wrong user input:\r\n", __func__, __LINE__);
            print_help_msg();
            return RETURN_ERR;
        } else {
            third_arg = strtok(NULL, " ");
            ret = parse_input_parameters(first_arg, second_arg, third_arg);
        }
    }

    return ret;
}

void delete_cli_thread(void)
{
    printf("%s:%d: delete cli task:\r\n", __func__, __LINE__);
    pthread_detach(pthread_self());
    pthread_exit(0);
}

void *cli_input_func(void *arg)
{
    char input_char;
    unsigned char char_index = 0;
    bool space_detection = 0, allow_special_char = 0;
    char input_buff[128] = { 0 };

    prctl(PR_SET_NAME,  __func__, 0, 0, 0);

    print_help_msg();
    printf("%s:%d: start cli task, Enter Input:\r\n$", __func__, __LINE__);
    while (cli_task_obj.exit_cli == false) {
        input_char = getchar();
        if ((char_index == 2) && (input_char == ' ')) {
            input_buff[char_index] = input_char;
            char_index++;
            space_detection = 0;
        } else if ((input_char == ' ') && (space_detection == 1)) {
            input_buff[char_index] = input_char;
            char_index++;
            space_detection = 0;
            allow_special_char = 1;
        } else if ((char_index == 0) && (input_char == '-')) {
            input_buff[char_index] = input_char;
            char_index++;
            continue;
        } else if (input_char == ' ') {
            continue;
        } else if ((char_index == 0) && (input_char == '\n')) {
            printf("$");
            continue;
        }

        if (input_char >= 'a' && input_char <= 'z') {
            input_buff[char_index] = input_char;
            char_index++;
            space_detection = 1;
	} else if (input_char >= 'A' && input_char <= 'Z') {
            input_buff[char_index] = input_char;
            char_index++;
            space_detection = 1;
        } else if (input_char >= '0' && input_char <= '9') {
            input_buff[char_index] = input_char;
            char_index++;
            space_detection = 1;

        } else if (input_char == '*') {
            input_buff[char_index] = input_char;
            char_index++;
            space_detection = 1;

        } else if ((input_char == '/' || input_char == '.' || input_char == '_' || input_char == '-' || input_char == ':' || input_char == ',')
                     &&  (allow_special_char == 1)) {
            input_buff[char_index] = input_char;
            char_index++;
        } else if ((input_char == '\n') && (char_index <= sizeof(input_buff))) {
            printf("%s\r\n$", input_buff);
            parse_cli_input_msg(input_buff);
            memset(input_buff, 0 ,sizeof(input_buff));
            char_index = 0;
            space_detection = 1;
            allow_special_char = 0;
        } else if (char_index > sizeof(input_buff)) {
            printf("wrong input can you please try again\r\n");
            memset(input_buff, 0 ,sizeof(input_buff));
            char_index = 0;
            space_detection = 1;
            allow_special_char = 0;
            print_help_msg();
        }
    }

    delete_cli_thread();
    return NULL;
}

int create_cli_task(void)
{
    cli_task_obj.exit_cli = false;
    if (pthread_create(&cli_task_obj.task_tid, NULL, cli_input_func, &cli_task_obj) != 0) {
        printf("%s:%d:cli task create failed\n", __func__, __LINE__);
        return RETURN_ERR;
    } else {
        printf("%s:%d:cli task create success\r\n", __func__, __LINE__);
    }

    return RETURN_OK;
}
