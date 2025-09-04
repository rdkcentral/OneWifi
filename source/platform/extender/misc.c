/************************************************************************************
  If not stated otherwise in this file or this component's LICENSE file the
  following copyright and licenses apply:

  Copyright 2025 RDK Management

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

#include "misc.h"
#include <semaphore.h>
#include <fcntl.h>
#include "wifi_util.h"
#include <errno.h>
#include <unistd.h>

void wifi_misc_init();
sem_t *sem;

int ext_sysevent_open(char *ip, unsigned short port, int version, char *id, unsigned int *token)
{
    //ToDo
    return 0;
}

int ext_sysevent_close(const int fd, const unsigned int  token)
{
    //ToDo
    return 0;
}

int ext_wifi_enableCSIEngine(int apIndex, mac_address_t sta, bool enable)
{
    return 0;
}

int ext_initparodusTask()
{
    return 0;
}

int ext_wifi_getRadioTrafficStats2(int radioIndex, wifi_radioTrafficStats2_t *output_struct)
{
    return 0;
}

int ext_WiFi_InitGasConfig()
{
    return 0;
}

void ext_daemonize()
{
    int fd; 

    /* initialize semaphores for shared processes */
    sem = sem_open ("pSemCcspWifi", O_CREAT | O_EXCL, 0644, 0); 
    if (SEM_FAILED == sem) {
        wifi_util_error_print(WIFI_MGR,"Failed to create semaphore %d - %s\n", errno, strerror(errno));
        _exit(1);
    }
    /* name of semaphore is "pSemCcspWifi", semaphore is reached using this name */
    sem_unlink ("pSemCcspWifi");
    /* unlink prevents the semaphore existing forever */
    /* if a crash occurs during the execution         */
    wifi_util_info_print(WIFI_MGR,"Semaphore initialization Done!!:%p\n", sem);

    switch (fork()) {
        case 0:
            break;
        case -1:
            // Error
            wifi_util_error_print(WIFI_MGR,"Error daemonizing (fork)! %d - %s\n", errno, strerror(errno));
            exit(0);
            break;
        default:
            sem_wait (sem);
            sem_close (sem);
            _exit(0);
    }

    if (setsid() < 0) {
        wifi_util_error_print(WIFI_MGR,"Error demonizing (setsid)! %d - %s\n", errno, strerror(errno));
        exit(0);
    }
    fd = open("/dev/null", O_RDONLY);
    if (fd != 0) {
        dup2(fd, 0);
        close(fd);
    }
    fd = open("/dev/null", O_WRONLY);
    if (fd != 1) {
        dup2(fd, 1);
        close(fd);
    }
    fd = open("/dev/null", O_WRONLY);
    if (fd != 2) {
        dup2(fd, 2);
        close(fd);
    }
}

void ext_sendWebpaMsg(char *serviceName, char *dest, char *trans_id, char *traceParent, char *traceState, char *contentType, char *payload, unsigned int payload_len)
{
     return;
}

void wifi_misc_init(wifi_misc_t *misc)
{
   misc->desc.sysevent_open_fn = ext_sysevent_open;
   misc->desc.sysevent_close_fn = ext_sysevent_close;
   misc->desc.wifi_enableCSIEngine_fn = ext_wifi_enableCSIEngine;
   misc->desc.initparodusTask_fn = ext_initparodusTask;
   misc->desc.wifi_getRadioTrafficStats2_fn = ext_wifi_getRadioTrafficStats2;
   misc->desc.WiFi_InitGasConfig_fn = ext_WiFi_InitGasConfig;
   misc->desc.daemonize_fn = ext_daemonize;
   misc->desc.sendWebpaMsg_fn = ext_sendWebpaMsg;
}
