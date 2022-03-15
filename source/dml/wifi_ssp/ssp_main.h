#ifndef WIFI_SSP_MAIN_H
#define WIFI_SSP_MAIN_H

#ifdef __cplusplus
extern "C"
{
#endif

typedef struct {
	pthread_t	tid;
        int             argc;
        char            **argv;
} wifi_ssp_t;

#ifdef __cplusplus
}
#endif

#endif //WIFI_SSP_MAIN_H
