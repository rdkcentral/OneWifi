#include "wifi_util.h"
#include "misc.h"

void wifi_misc_init();

int linux_sysevent_open(char *ip, unsigned short port, int version, char *id, unsigned int  *token)
{
    return 0;
}

int linux_sysevent_close(const int fd, const unsigned int  token)
{
    return 0;
}

int linux_wifi_enableCSIEngine(int apIndex, mac_address_t sta, bool enable)
{
    return 0;
}

int linux_initparodusTask()
{
    return 0;
}

int linux_wifi_getRadioTrafficStats2(int radioIndex, wifi_radioTrafficStats2_t *output_struct)
{
    return 0;
}

int linux_WiFi_InitGasConfig()
{
    return 0;
}

void linux_daemonize()
{
    return 0;
}

void linux_sendWebpaMsg(char *serviceName, char *dest, char *trans_id, char *traceParent, char *traceState, char *contentType, char *payload, unsigned int payload_len)
{
    return;
}

void wifi_misc_init(wifi_misc_t *misc)
{
   misc->desc.sysevent_open_fn = linux_sysevent_open;
   misc->desc.sysevent_open_fn = linux_sysevent_open;
   misc->desc.sysevent_close_fn = linux_sysevent_close;
   misc->desc.wifi_enableCSIEngine_fn = linux_wifi_enableCSIEngine;
   misc->desc.initparodusTask_fn = linux_initparodusTask;
   misc->desc.wifi_getRadioTrafficStats2_fn = linux_wifi_getRadioTrafficStats2;
   misc->desc.WiFi_InitGasConfig_fn = linux_WiFi_InitGasConfig;
   misc->desc.daemonize_fn = linux_daemonize;
   misc->desc.sendWebpaMsg_fn = linux_sendWebpaMsg;
}
