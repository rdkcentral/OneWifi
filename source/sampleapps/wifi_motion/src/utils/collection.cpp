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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "collection.h"


queue_t *queue_create   (void)
{
    queue_t *q;
    
    q = (queue_t *)malloc(sizeof(queue_t));
    if (q == NULL) {
        return NULL;
    }
    memset(q, 0, sizeof(queue_t));
    return q;
}

int8_t     queue_push      (queue_t *q, void *data)
{
    element_t *e, *tmp;
    e = (element_t *)malloc(sizeof(element_t));
    if (e == NULL) {
        return -1;
    }
    memset(e, 0, sizeof(element_t));
    e->data = data;
    if (q->head == NULL) {
        q->head = e;
    } else {
        tmp = q->head;
        q->head = e;
        e->next = tmp;    
    }
    q->count++;
    return 0;    
}

void    *queue_pop      (queue_t *q)
{
    element_t *e, *tmp = NULL;
    void *data;
    e = q->head;
    if (e == NULL) {
        return NULL;
    }
    while (e->next != NULL) {
        tmp = e;
        e = e->next;
    }
        
    data = e->data;
    if (tmp != NULL) {
        tmp->next = NULL;
    } else {
        q->head = NULL;
    }
    free(e);
    q->count--;
    return data;
}

void     *queue_remove    (queue_t *q, uint32_t index)
{
    element_t    *e, *tmp = NULL;
    void *data;
    uint32_t i = 0;
    
    if (index >= queue_count(q)) {
        return NULL;
    }
    e = q->head;
    if (e == NULL) {
        return NULL;
    }
    while (i < index) {
        tmp = e;
        e = e->next;    
        i++;    
    }
    if (tmp == NULL) {
        q->head = e->next;
    } else {
        tmp->next = e->next;
    }
    data = e->data;
    free(e);
    q->count--;
    return data;
}

void    *queue_peek  (queue_t *q, uint32_t index)
{
    element_t    *e;
    uint32_t i = 0;
    
    if (index >= queue_count(q)) {
        return NULL;
    }
    e = q->head;
    if (e == NULL) {
        return NULL;
    }
    while ((i < index) && (e != NULL)) {
        e = e->next;    
        i++;    
    }
    if (e) {
        return e->data;
    }
    return NULL;
}

uint32_t queue_count    (queue_t *q)
{
    if (q == NULL) {
        return 0;
    } else {
        return q->count;
    }
}

void    queue_destroy   (queue_t *q)
{
    element_t    *e, *tmp;
    e = q->head;
    while (e != NULL) {
        tmp = e->next;
        if (e->data != NULL) {
            free(e->data);
        }
        free(e);
        e = tmp;
    }
    free(q);
}

int8_t hash_map_put    (hash_map_t *map, char *key, void *data)
{
    hash_element_t *e;
    
    if (map == NULL) {
        return -1;
    }
    map->itr = NULL;
    e = (hash_element_t *)malloc(sizeof(hash_element_t));
    if (e == NULL) {
        return -1;
    }
    memset(e, 0, sizeof(hash_element_t));
    e->key = key;
    e->data = data;
    
    if (queue_push(map->queue, e) < 0) {
        free(key);
        if ( e->data != NULL) {
            free(e->data);
            e->data = NULL;
        }
        free(e);
        return -1;
    }
    return 0;    
}

void *hash_map_get   (hash_map_t *map, const char *key)
{
    uint32_t i = 0;
    hash_element_t *he;
    element_t    *e;

    if (map == NULL || map->queue == NULL) {
        return NULL;
    }
    e = map->queue->head;
    if (e == NULL) {
        return NULL;
    }
    while (e != NULL) {
        if (e->data != NULL) {
            he = (hash_element_t *) e->data;
            if (he != NULL && (strncmp(he->key, key, HASH_MAP_MAX_KEY_SIZE) == 0)) {
                return he->data;
            }
        }
        e = e->next;
        i++;
    }
    
    return NULL;
}

void *hash_map_remove   (hash_map_t *map, const char *key)
{
    uint32_t i = 0;
    hash_element_t *he;
    element_t    *e, *prev = NULL;
    bool found = false;
    void *data;

    if (map == NULL || map->queue == NULL) {
        return NULL;
    }
    prev = NULL;
    e = map->queue->head;
    if (e == NULL) {
        return NULL;
    }
    while (e != NULL) {
        if (e->data != NULL) {
            he = (hash_element_t *) e->data;
            if (he != NULL && (strncmp(he->key, key, HASH_MAP_MAX_KEY_SIZE) == 0)) {
                found = true;
                break;
            }
        }
        prev = e;
        e = e->next;
        i++;
    }
    
    if (found == false) {
        return NULL;
    }
    
    if (prev == NULL) {
        map->queue->head = e->next;
    } else {
        prev->next = e->next;
    }
    free(e);
    map->queue->count--;

    data = he->data;
    free(he->key);
    free(he);
    
    return data;
}

void     *hash_map_get_first    (hash_map_t *map)
{
    hash_element_t *he;
    element_t    *e;
    if (map == NULL) {
        return NULL;
    }
    map->itr = NULL;

    e = map->queue->head;
    if (e == NULL) {
        return NULL;
    }
    map->itr = e;
    he = (hash_element_t *) e->data;
    if(he == NULL) {
        return NULL;
    }
    return he->data;
}

void     *hash_map_get_next    (hash_map_t *map, void *data)
{
    hash_element_t *he;
    element_t *e;

    if (map == NULL) {
        return NULL;
    }
    if (map->itr != NULL) {
        if (map->itr->data != NULL) {
            he = (hash_element_t *) map->itr->data;
            if (he->data == data) {
                map->itr = map->itr->next;
                if (map->itr == NULL) {
                    return NULL;
                } else {
                    he = (hash_element_t *) map->itr->data;
                    if (he == NULL) {
                        return NULL;
                    }
                    return he->data;
                }
            }
        }
    }
    //full search
    e = map->queue->head;
    if (e == NULL) {
        return NULL;
    }
    while (e != NULL) {
        if (e->data != NULL) {
            he = (hash_element_t *) e->data;
            if (he->data == data) {
                map->itr = e->next;
                if (map->itr == NULL) {
                    return NULL;
                } else {
                    he = (hash_element_t *) map->itr->data;
                    if (he == NULL) {
                        return NULL;
                    }
                    return he->data;
                }
            }
        }
        e = e->next;
    }
    return NULL;
}

uint32_t hash_map_count  (hash_map_t *map)
{
    return queue_count(map->queue);
}

hash_map_t  *hash_map_create    ()
{
    hash_map_t    *map;
    map = (hash_map_t *)malloc(sizeof(hash_map_t));
    if (map == NULL) {
        return NULL;
    }
    
    memset(map, 0, sizeof(hash_map_t));
    map->queue = queue_create();
    if (map->queue == NULL) {
        free(map);
        return NULL;
    }
    return map;
}


void  hash_map_cleanup(hash_map_t *map)
{
    hash_element_t *he;
    element_t    *e, *tmp;
    
    if (map == NULL || map->queue == NULL || map->queue->head == NULL) {
        return;
    }
    e = map->queue->head;
    while (e != NULL) {
        tmp = e->next;
        he = (hash_element_t *) e->data;
        if(he != NULL) {
            if (he->data != NULL) {
                free(he->data);
            }
            if (he->key != NULL) {
                free(he->key);
            }
            free(he);
        }
        free(e);
        e = tmp;
    }
    map->queue->head = NULL;
    map->queue->count = 0;
    return;
}

void  hash_map_destroy    (hash_map_t *map)
{
    if (map != NULL) {
        hash_map_cleanup(map);
        queue_destroy(map->queue);
        free(map);
    }
}
