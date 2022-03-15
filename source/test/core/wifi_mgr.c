#include <stdio.h>
#include <stdbool.h>
#include <pthread.h>
#include <ev.h>
#include <sys/time.h>
#include "wifi_hal.h"
#include "wifi_ovsdb.h"
#include "wifi_ctrl.h"
//#include "ssp_main.h"

void my_print_hex_dump(unsigned int length, unsigned char *buffer)
{
    unsigned int i;
    unsigned char buff[512] = {};
    const unsigned char * pc = (const unsigned char *)buffer;

    if ((pc == NULL) || (length <= 0)) {
        printf ("buffer NULL or BAD LENGTH = %d :\n", length);
        return;
    }

    for (i = 0; i < length; i++) {
        if ((i % 16) == 0) {
            if (i != 0)
                printf ("  %s\n", buff);
            printf ("  %04x ", i);
        }

        printf (" %02x", pc[i]);

        if (!isprint(pc[i]))
            buff[i % 16] = '.';
        else
            buff[i % 16] = pc[i];
        buff[(i % 16) + 1] = '\0';
    }

    while ((i % 16) != 0) {
        printf ("   ");
        i++;
    }

    printf ("  %s\n", buff);

}

typedef struct {
	wifi_ovsdb_t 	ovsdb;
	//wifi_ssp_t	ssp;
	wifi_ctrl_t	ctrl;
} wifi_mgr_t;

wifi_mgr_t g_wifi_mgr;

int main(int argc, char *argv[])
{
    //start_ovsdb(&g_wifi_mgr.ovsdb);
    //init_ovsdb_tables(&g_wifi_mgr.ovsdb);

    //start_ssp_main(&g_wifi_mgr.ssp);
    if (start_wifi_ctrl(&g_wifi_mgr.ctrl, argc, argv) != 0) {
        return -1;
    }

    return 0;
}
