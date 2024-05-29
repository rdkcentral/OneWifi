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

#ifndef _COLLECTION_H_
#define	_COLLECTION_H_

#include <stdint.h>
#include <stdbool.h>

#define HASH_MAP_MAX_KEY_SIZE   100

typedef struct element_t {
    void     *data;
    struct element_t *next;    
} element_t;

typedef struct {
    void    *data;
    char    *key;
} hash_element_t;

typedef struct {
    element_t    *head;
    uint32_t count;
} queue_t;

typedef struct {
    queue_t *queue;
    element_t    *itr;
} hash_map_t;

// queue operations
queue_t     *queue_create    (void);
void        queue_destroy    (queue_t *q);
int8_t        queue_push        (queue_t *q, void *data);
void        *queue_pop        (queue_t *q);
void        *queue_remove      (queue_t *q, uint32_t n);
void        *queue_peek     (queue_t *q, uint32_t n);
uint32_t     queue_count        (queue_t *q);
// hash map operations, currently hash map is flat there are no buckets
hash_map_t     *hash_map_create    (void);
void         hash_map_destroy    (hash_map_t *map);
void         hash_map_cleanup    (hash_map_t *map);
int8_t         hash_map_put    (hash_map_t *map, char *key, void *data);
void         *hash_map_get    (hash_map_t *map, const char *key);
void        *hash_map_remove (hash_map_t *map, const char *key);
uint32_t     hash_map_count    (hash_map_t *map);

void     *hash_map_get_first    (hash_map_t *map);
void     *hash_map_get_next    (hash_map_t *map, void *data);
hash_map_t *hash_map_clone (hash_map_t *src_map, size_t data_size);

#endif // _COLLECTION_H_
