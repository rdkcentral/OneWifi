#ifndef EXTERNAL_PROTO_H
#define EXTERNAL_PROTO_H
#include <webconfig_external_proto_ovsdb.h>
#include <webconfig_external_proto_tr181.h>

typedef struct {
    union {
        webconfig_external_ovsdb_t ovsdb;
        webconfig_external_tr181_t tr181;
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

#endif //EXTERNAL_PROTO_H
