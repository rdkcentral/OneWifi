#ifndef VAP_SVC_H
#define VAP_SVC_H

#ifdef __cplusplus
extern "C" {
#endif

#include "wifi_hal.h"

typedef struct wifi_ctrl wifi_ctrl_t;

typedef enum {
    vap_svc_type_private,
    vap_svc_type_public,
    vap_svc_type_mesh_gw,
    vap_svc_type_mesh_ext,
    vap_svc_type_max
} vap_svc_type_t;

struct vap_svc *svc;

typedef struct vap_svc vap_svc_t;

typedef int (* vap_svc_start_fn_t)(vap_svc_t *svc, unsigned int radio_index, wifi_vap_info_map_t *map);
typedef int (* vap_svc_stop_fn_t)(vap_svc_t *svc, unsigned int radio_index, wifi_vap_info_map_t *map);
typedef int (* vap_svc_update_fn_t)(vap_svc_t *svc, unsigned int radio_index, wifi_vap_info_map_t *map);
typedef bool (* vap_svc_is_my_fn_t)(unsigned int vap_index);

typedef struct vap_svc {
    bool                created;
    vap_svc_type_t      type;
    vap_svc_start_fn_t  start_fn;
    vap_svc_stop_fn_t   stop_fn;
    vap_svc_update_fn_t update_fn;
    vap_svc_is_my_fn_t  is_my_fn;
} vap_svc_t;

int svc_init(vap_svc_t *svc, vap_svc_type_t type);

// private
extern int vap_svc_private_start(vap_svc_t *svc, unsigned int radio_index, wifi_vap_info_map_t *map);
extern int vap_svc_private_stop(vap_svc_t *svc, unsigned int radio_index, wifi_vap_info_map_t *map);
extern int vap_svc_private_update(vap_svc_t *svc, unsigned int radio_index, wifi_vap_info_map_t *map);
extern bool vap_svc_is_private(unsigned int vap_index);

// public
extern int vap_svc_public_start(vap_svc_t *svc, unsigned int radio_index, wifi_vap_info_map_t *map);
extern int vap_svc_public_stop(vap_svc_t *svc, unsigned int radio_index, wifi_vap_info_map_t *map);
extern int vap_svc_public_update(vap_svc_t *svc, unsigned int radio_index, wifi_vap_info_map_t *map);
extern bool vap_svc_is_public(unsigned int vap_index);

// mesh_gateway
extern int vap_svc_mesh_gw_start(vap_svc_t *svc, unsigned int radio_index, wifi_vap_info_map_t *map);
extern int vap_svc_mesh_gw_stop(vap_svc_t *svc, unsigned int radio_index, wifi_vap_info_map_t *map);
extern int vap_svc_mesh_gw_update(vap_svc_t *svc, unsigned int radio_index, wifi_vap_info_map_t *map);
extern bool vap_svc_is_mesh_gw(unsigned int vap_index);

// mesh_extender
extern int vap_svc_mesh_ext_start(vap_svc_t *svc, unsigned int radio_index, wifi_vap_info_map_t *map);
extern int vap_svc_mesh_ext_stop(vap_svc_t *svc, unsigned int radio_index, wifi_vap_info_map_t *map);
extern int vap_svc_mesh_ext_update(vap_svc_t *svc, unsigned int radio_index, wifi_vap_info_map_t *map);
extern bool vap_svc_is_mesh_ext(unsigned int vap_index);

vap_svc_t *get_svc_by_type(wifi_ctrl_t *ctrl, vap_svc_type_t type);
vap_svc_t *get_svc_by_vap_index(wifi_ctrl_t *ctrl, unsigned int vap_index);
vap_svc_t *get_svc_by_name(wifi_ctrl_t *ct, char *vap_name);

#ifdef __cplusplus
}
#endif

#endif // VAP_SVC_H
