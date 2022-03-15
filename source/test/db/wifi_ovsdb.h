#ifndef WIFI_OVSDB_H
#define WIFI_OVSDB_H

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
	struct ev_loop	*ovs_ev_loop;
	struct ev_io wovsdb;
	int ovsdb_fd;
	char ovsdb_sock_path[256];
    char    ovsdb_run_dir[256];
    char    ovsdb_bin_dir[256];
    char    ovsdb_schema_dir[256];
	pthread_t	ovsdb_thr_id;
	pthread_t   evloop_thr_id;
	bool	debug;
} wifi_ovsdb_t;

#ifdef __cplusplus
}
#endif

#endif //WIFI_OVSDB_H
