/************************************************************************************
  If not stated otherwise in this file or this component's LICENSE file the
  following copyright and licenses apply:
  
  Copyright 2018 RDK Management
  
  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at
  
  http://www.apache.org/licenses/LICENSE-2.0
  
  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
 **************************************************************************/

#ifndef EXTERNAL_PROTO_H
#define EXTERNAL_PROTO_H
#include <webconfig_external_proto_ovsdb.h>
#include <webconfig_external_proto_tr181.h>
#if defined EASY_MESH_NODE || defined EASY_MESH_COLOCATED_NODE
#include <webconfig_external_proto_easymesh.h>
#endif

typedef struct {
    union {
        webconfig_external_ovsdb_t ovsdb;
        webconfig_external_tr181_t tr181;
#if defined EASY_MESH_NODE || defined EASY_MESH_COLOCATED_NODE
        webconfig_external_easymesh_t easymesh;
#endif
    }u;

} webconfig_external_proto_t;

// external api sets for ovsdbmgr, encode takes webconfig object, external schema array structure
// and subdocument type as input, encoded string (4th argument) is output
webconfig_error_t webconfig_ovsdb_encode(webconfig_t *config,
                const webconfig_external_ovsdb_t *ext,
                webconfig_subdoc_type_t type,
                char **str);

// external api sets for ovsdbmgr, decode takes webconfig object, encoded string as imput
// and gives back external schema array structure (3rd argument) and subdocument type (4th argument)
// as output
webconfig_error_t webconfig_ovsdb_decode(webconfig_t *config,
                const char *str,
                webconfig_external_ovsdb_t *out,
                webconfig_subdoc_type_t *type);

webconfig_error_t webconfig_convert_ifname_to_subdoc_type(const char *ifname, webconfig_subdoc_type_t *type);

#if defined EASY_MESH_NODE || defined EASY_MESH_COLOCATED_NODE
// external api sets for easymesh agent, encode takes webconfig object, easymesh structure
// and subdocument type as input, encoded string (4th argument) is output
webconfig_error_t webconfig_easymesh_encode(webconfig_t *config,
                const webconfig_external_easymesh_t *ext,
                webconfig_subdoc_type_t type,
                char **str);

// external api sets for easymesh agent, decode takes webconfig object, encoded string as imput
// and gives back easymesh agent structure (3rd argument) and subdocument type (4th argument)
// as output
webconfig_error_t webconfig_easymesh_decode(webconfig_t *config,
                const char *str,
                webconfig_external_easymesh_t *out,
                webconfig_subdoc_type_t *type);

#endif
#endif //EXTERNAL_PROTO_H
