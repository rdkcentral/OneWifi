#include "uahf.h"
#include "uahf_server.h"
#include "stdlib.h"
#include "wifi_ctrl.h"
#include "wifi_hal.h"
#include "wifi_mgr.h"
#include "wifi_util.h"
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/time.h>

void* uahf_worker_task(void* arg) {
    wifi_app_t* app = (wifi_app_t*)arg;
    uahf_data_t* d = GET_UAHF(app);

    wifi_util_error_print(WIFI_APPS, "UAHF: starting server in detached thread\n");

    // 1. Run the server directly (BLOCKING)
    // This will sit here until the user submits the form and the loop breaks
    uahf_start_server(app);
    wifi_util_error_print(WIFI_APPS, "UAHF: server exited from detached thread\n");

    // 2. Update State (Critical Section)
    pthread_mutex_lock(&d->app_lock);

    d->worker_running = false;
    d->worker_done = true; // Signal main thread that data is in d->username/password
    pthread_mutex_unlock(&d->app_lock);

    wifi_util_error_print(WIFI_CTRL, "UAHF Result: User=%s, Pass=%s\n", 
                                 d->username, d->password);

  // Pass to AppMgr or other logic
  // process_login(d->username, d->password);
#define BUFFER_SIZE 4096
    /*char command_buffer[BUFFER_SIZE];
    int len = snprintf( command_buffer, BUFFER_SIZE, "dmcli eRT setv Device.WiFi.SSID.15.SSID string %s", d->username);
    if (len == 0) printf("have to use this somewhere to disable -Wall error");
    wifi_util_error_print(WIFI_APPS, "%s:%d: uahf : about to call set ssid for vap 15\n", __func__, __LINE__);

    system(command_buffer);
wifi_util_error_print(WIFI_APPS, "%s:%d: uahf :  called set ssid for vap 15\n", __func__, __LINE__);

    len = snprintf( command_buffer, BUFFER_SIZE, "dmcli eRT setv Device.WiFi.SSID.16.SSID string %s", d->username);
wifi_util_error_print(WIFI_APPS, "%s:%d: uahf : about to call set ssid for vap 16\n", __func__, __LINE__);

    system(command_buffer);
wifi_util_error_print(WIFI_APPS, "%s:%d: uahf : called set ssid for vap 16\n", __func__, __LINE__);
wifi_util_error_print(WIFI_APPS, "%s:%d: uahf : about to call set ssid for vap 24\n", __func__, __LINE__);

    len = snprintf( command_buffer, BUFFER_SIZE, "dmcli eRT setv Device.WiFi.SSID.24.SSID string %s", d->username);
    system(command_buffer);
wifi_util_error_print(WIFI_APPS, "%s:%d: uahf :  called set ssid for vap 24\n", __func__, __LINE__);

    len = snprintf( command_buffer, BUFFER_SIZE,
            "dmcli eRT setv Device.WiFi.AccessPoint.15.Security.KeyPassphrase string %s", d->password);
wifi_util_error_print(WIFI_APPS, "%s:%d: uahf : about to call set psk for vap 15\n", __func__, __LINE__);

    system(command_buffer);
wifi_util_error_print(WIFI_APPS, "%s:%d: uahf : called set psk  for vap 15\n", __func__, __LINE__);

    len = snprintf( command_buffer, BUFFER_SIZE,
            "dmcli eRT setv Device.WiFi.AccessPoint.16.Security.KeyPassphrase string %s", d->password);

wifi_util_error_print(WIFI_APPS, "%s:%d: uahf : will call set psk for vap 16, with %s \n", __func__, __LINE__, d->password);

    system(command_buffer);
wifi_util_error_print(WIFI_APPS, "%s:%d: uahf : called set psk for vap 16\n", __func__, __LINE__);
wifi_util_error_print(WIFI_APPS, "%s:%d: cmd: %s\n", __func__, __LINE__, command_buffer);

    len = snprintf( command_buffer, BUFFER_SIZE,
            "dmcli eRT setv Device.WiFi.AccessPoint.24.Security.KeyPassphrase string %s", d->password);
wifi_util_error_print(WIFI_APPS, "%s:%d: uahf : about to call set psk for vap 24\n", __func__, __LINE__);

    system(command_buffer);
wifi_util_error_print(WIFI_APPS, "%s:%d: uahf : called set psk for vap 24, call start ext vaps\n", __func__, __LINE__);

    system("dmcli eRT setv Device.WiFi.ApplyAccessPointSettings bool true"); */
//wifi_util_error_print(WIFI_APPS, "%s:%d: uahf : will call start extender vaps\n", __func__, __LINE__);

   // start_extender_vaps();
wifi_util_error_print(WIFI_APPS, "%s:%d: uahf : called start extender vaps\n", __func__, __LINE__);

wifi_util_error_print(WIFI_APPS, "%s:%d: will called start uahf vaps\n", __func__, __LINE__);

start_uahf_vaps(TRUE, d->username, d->password);
wifi_util_error_print(WIFI_APPS, "%s:%d: called start uahf vaps\n", __func__, __LINE__);

    return NULL;
}

int uahf_update(wifi_app_t *app) {
    uahf_data_t* d = GET_UAHF(app);
    wifi_util_error_print(WIFI_APPS, "%s:%d: Init uahf-update\n", __func__, __LINE__);

    // --- Trigger Server ---
    if (!d->worker_running && !d->worker_done) {
        wifi_util_error_print(WIFI_APPS, "%s:%d: wILL try to create thread\n", __func__, __LINE__);

        pthread_mutex_lock(&d->app_lock);
        
        // Clear old data just in case
        memset(d->username, 0, sizeof(d->username));
        memset(d->password, 0, sizeof(d->password));
        
        if (!d->worker_running) {
            d->worker_running = true;

            // --- SPAWN THREAD (NON-BLOCKING) ---
            // We create a separate thread to handle the blocking server.
            // pthread_create returns immediately.
            
            pthread_attr_t attr;
            pthread_attr_init(&attr);
            pthread_attr_setstacksize(&attr, 128 * 1024); 
            wifi_util_error_print(WIFI_APPS, "%s:%d: uahf:about to spawn a thread with server\n", __func__, __LINE__);

            if (pthread_create(&d->worker_tid, &attr, uahf_worker_task, app) == 0) {
                pthread_detach(d->worker_tid); // Fire and forget
        wifi_util_error_print(WIFI_APPS, "%s:%d: uahf: started thread with server\n", __func__, __LINE__);

            } else {
                d->worker_running = false;
            }
            pthread_attr_destroy(&attr);
        }
        pthread_mutex_unlock(&d->app_lock);

    }
//    wifi_util_error_print(WIFI_APPS, "%s:%d: uahf after  spawning a thread block\n", __func__, __LINE__);

    // --- Process Results --
    // dead cpde for now
    if (d->worker_done) {
        pthread_mutex_lock(&d->app_lock);
        if (d->worker_done) {
            
            // SUCCESS: Data is now available directly in the struct
            wifi_util_error_print(WIFI_APPS, "UAHF Result: User=%s, Pass=%s\n", 
                                 d->username, d->password);


            d->worker_done = true; //for now we leave it here,so that it isn't restarted several times. 
        }
        pthread_mutex_unlock(&d->app_lock);
    }
//wifi_util_error_print(WIFI_APPS, "%s:%d: uahf: exit\n", __func__, __LINE__);

    return RETURN_OK;
}

int uahf_init(wifi_app_t *app, unsigned int create_flag)
{

    memset(&app->data.u.uahf_data, 0, sizeof(uahf_data_t));
    pthread_mutex_init(&app->data.u.uahf_data.app_lock, NULL);

    if (app_init(app, create_flag) != 0) {
        return RETURN_ERR;
    }
    wifi_util_error_print(WIFI_APPS, "%s:%d: Init uahf\n", __func__, __LINE__);

    return RETURN_OK;
}

int uahf_deinit(wifi_app_t *app)
{
    return RETURN_OK;
}

/*
int my_app_deinit(wifi_app_t* app) {
    MyHttpState* state = GET_STATE(app);
    if (state->worker_running) {
        // In a real app, you'd kill the thread or wait.
        // For a demo, a small sleep or warning is sufficient.
        printf("Warning: App closing while worker is active.\n");
    }
    return 0;
    */
