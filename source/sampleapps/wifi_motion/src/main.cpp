//
//  main.cpp
//  wifi_motion
//
//  Created by Munshi, Soumya on 12/2/25.
//

#include <stdio.h>
#include "web.h"
#include "csimgr.h"

#define WEB_SERVER_PATH "/www/data"
csimgr_t *g_mgr = NULL;

void push_web_event(web_event_t *evt)
{
    if (g_mgr) {
        g_mgr->push(evt);
    }
}

int main(int argc, const char * argv[])
{
    web_t *web;

    web = new web_t(WEB_SERVER_PATH);
    web->start();

    g_mgr = new csimgr_t(WEB_SERVER_PATH);
    g_mgr->run();

    return 0;
}

