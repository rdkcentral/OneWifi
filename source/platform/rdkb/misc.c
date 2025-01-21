#include <sysevent/sysevent.h>
#include "wifi_util.h"
#include "misc.h"
#include <semaphore.h>
#include <fcntl.h>
#include "wifi_util.h"
#include <errno.h>
#include <unistd.h>

void wifi_misc_init();
sem_t *sem;

int rdkb_sysevent_open(char *ip, unsigned short port, int version, char *id, unsigned int *token)
{
    int fd;
    wifi_util_error_print(WIFI_MGR,"%s:%d calling sysevent_open!\n", __func__, __LINE__);
    fd = sysevent_open(ip, SE_SERVER_WELL_KNOWN_PORT, SE_VERSION, id, token);
    return fd;
}

int rdkb_sysevent_close(const int fd, const unsigned int  token)
{
    sysevent_close(fd, token);
    return 0;
}

int rdkb_wifi_enableCSIEngine(int apIndex, mac_address_t sta, bool enable)
{
    wifi_enableCSIEngine(apIndex, sta, enable);
    return 0;
}

int rdkb_initparodusTask()
{
    initparodusTask();
    return 0;
}

int rdkb_wifi_getRadioTrafficStats2(int radioIndex, wifi_radioTrafficStats2_t *output_struct)
{
    return (wifi_getRadioTrafficStats2(radioIndex, output_struct));
}

int rdkb_WiFi_InitGasConfig()
{
    return (WiFi_InitGasConfig());
}

void rdkb_daemonize()
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

void rdkb_sendWebpaMsg(char *serviceName, char *dest, char *trans_id, char *traceParent, char *traceState, char *contentType, char *payload, unsigned int payload_len)
{
    sendWebpaMsg(serviceName, dest, trans_id, traceParent, traceState, contentType, payload, payload_len);
}

void wifi_misc_init(wifi_misc_t *misc)
{
   misc->desc.sysevent_open_fn = rdkb_sysevent_open;
   misc->desc.sysevent_open_fn = rdkb_sysevent_open;
   misc->desc.sysevent_close_fn = rdkb_sysevent_close;
   misc->desc.wifi_enableCSIEngine_fn = rdkb_wifi_enableCSIEngine;
   misc->desc.initparodusTask_fn = rdkb_initparodusTask;
   misc->desc.wifi_getRadioTrafficStats2_fn = rdkb_wifi_getRadioTrafficStats2;
   misc->desc.WiFi_InitGasConfig_fn = rdkb_WiFi_InitGasConfig;
   misc->desc.daemonize_fn = rdkb_daemonize;
   misc->desc.sendWebpaMsg_fn = rdkb_sendWebpaMsg;
}
