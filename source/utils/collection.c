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
    e = NULL;

	return data;
}

void 	*queue_remove	(queue_t *q, uint32_t index)
{
	element_t	*e, *tmp = NULL;
	void *data;
	uint32_t i = 0;
    
    if (index > (queue_count(q) - 1)) {
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
    e = NULL;

	return data;
}

void    *queue_peek  (queue_t *q, uint32_t index)
{
	element_t	*e;
	uint32_t i = 0;
    
    if (index > (queue_count(q) - 1)) {
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
        /*CID: 58822 Dereference after null check*/
        if (e)
    	  return e->data;

    return NULL;

}

uint32_t queue_count    (queue_t *q)
{
	uint32_t i = 0;
	element_t *e = NULL;

	if (q == NULL) {
	    return 0;
	}

	e = q->head;

	while (e != NULL) {
		i++;
		e = e->next;
	}

	return i;
}

void    queue_destroy   (queue_t *q)
{
	element_t	*e, *tmp;

	e = q->head;

	while (e != NULL) {
		tmp = e->next;
		free(e->data);
        e->data = NULL;
		free(e);
        e = NULL;
		e = tmp;
	}

	free(q);
    q = NULL;
}

int8_t hash_map_put    (hash_map_t *map, char *key, void *data)
{
	hash_element_t *e;

	e = (hash_element_t *)malloc(sizeof(hash_element_t));
	if (e == NULL) {
		return -1;
	}

	memset(e, 0, sizeof(hash_element_t));

	e->key = key;
	e->data = data;
	return queue_push(map->queue, e);	
}

void *hash_map_get   (hash_map_t *map, const char *key)
{
	uint32_t count, i;
	hash_element_t *e = NULL;
	bool found = false;

	count = queue_count(map->queue);
	if (count == 0) {
		return NULL;
	}

	for (i = 0; i < count; i++) {
		e = queue_peek(map->queue, i);
		if ((e != NULL) && (strncmp(e->key, key, strlen(key)) == 0)) {
			found = true;
			break;
		}
	}

	if (found == false) {
		return NULL;
	}


	return e->data;	
	
}

void *hash_map_remove   (hash_map_t *map, const char *key)
{
    uint32_t count, i;
    hash_element_t *e = NULL, *tmp = NULL;
    bool found = false;
    void *data;
    
    count = queue_count(map->queue);
    if (count == 0) {
        return NULL;
    }
    
    for (i = 0; i < count; i++) {
        e = queue_peek(map->queue, i);
        if ((e != NULL) && (strncmp(e->key, key, strlen(key)) == 0)) {
            found = true;
            break;
        }
    }
    
    if (found == false) {
        return NULL;
    }
    
    tmp = queue_remove(map->queue, i);
    assert(tmp == e);
    
    data = e->data;
   //Setting unused pointers to NULL is a defensive style, protecting against dangling pointer bugs
    free(e->key);
    e->key = NULL;
    free(e);
    e = NULL;
    
    return data;
    
}


void     *hash_map_get_first    (hash_map_t *map)
{
    hash_element_t *e;
    
    e = queue_peek(map->queue, 0);
    if (e == NULL) {
        return NULL;
    }
    
    return e->data;
}

void     *hash_map_get_next    (hash_map_t *map, void *data)
{
    uint32_t count, i;
    hash_element_t *e;
    bool found = false;
    
    count = hash_map_count(map);
    for (i = 0; i < count; i++) {
        e = queue_peek(map->queue, i);
        if ((e != NULL) && (e->data == data)) {
            found = true;
            break;
        }
    }
    
    if (found == false) {
        return NULL;
    }
    
    e = queue_peek(map->queue, i + 1);
    if (e == NULL) {
        return NULL;
    }
    
    return e->data;
}

uint32_t hash_map_count  (hash_map_t *map)
{
	return queue_count(map->queue);
}

hash_map_t  *hash_map_create    ()
{
	hash_map_t	*map;

	map = (hash_map_t *)malloc(sizeof(hash_map_t));
	if (map == NULL) {
		return NULL;
	}
	
	memset(map, 0, sizeof(hash_map_t));
	map->queue = queue_create();

	return map;
}

void  hash_map_destroy    (hash_map_t *map)
{
	queue_destroy(map->queue);
	free(map);
    map = NULL;
}
