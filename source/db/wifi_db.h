#ifndef WIFI_DB_H
#define WIFI_DB_H

#ifdef __cplusplus
extern "C"
{
#endif

typedef struct {
	mac_addr_str_t	mac;
	char	vap_name[32];
	struct timeval tm;
	char	dev_name[32];
} mac_filter_data_t;

typedef struct {
    struct      ev_loop	*wifidb_ev_loop;
    struct      ev_io wifidb_ev_io;
    int         wifidb_fd;
    int         wifidb_wfd;
    char        wifidb_sock_path[256];
    char        wifidb_run_dir[256];
    char        wifidb_bin_dir[256];
    char        wifidb_schema_dir[256];
    pthread_t	wifidb_thr_id;
    pthread_t   evloop_thr_id;
    bool	debug;
} wifi_db_t;

#define WIFIDB_SCHEMA_DIR "/usr/ccsp/wifi"
#define WIFIDB_DIR "/nvram/wifi"
#define WIFIDB_RUN_DIR "/var/tmp"

#define BUFFER_LENGTH_WIFIDB 32

int start_wifidb();
int init_wifidb_tables();

#ifdef __cplusplus
}
#endif

#endif //WIFI_DB_H
