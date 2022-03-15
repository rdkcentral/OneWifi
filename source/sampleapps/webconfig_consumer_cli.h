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
}__attribute__((__packed__)) sample_app_cli_task_t;


#ifdef __cplusplus
}
#endif

#endif // WEBCONFIG_CONSUMER_CLI_H
