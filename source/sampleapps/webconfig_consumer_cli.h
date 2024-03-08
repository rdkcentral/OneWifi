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

#ifndef WEBCONFIG_CONSUMER_CLI_H
#define WEBCONFIG_CONSUMER_CLI_H

#include <stdio.h>
#include <string.h>
#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif


typedef struct {
    pthread_t    task_tid;
    int          argc;
    char         **argv;
    bool         exit_cli;
} sample_app_cli_task_t;

char *read_subdoc_input_param_from_file(char *file_path);

#ifdef __cplusplus
}
#endif

#endif // WEBCONFIG_CONSUMER_CLI_H
