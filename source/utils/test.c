#include "collection.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
int main() {
    hash_map_t *map = hash_map_create();
    char *key = strdup("test");
    char *data = strdup("value");
 
    // Insert
    if (hash_map_put(map, key, data) == 0) {
        printf("Inserted successfully\n");
    }
 
    // Retrieve
    char *val = (char *)hash_map_get(map, "test");
    printf("Retrieved: %s\n", val);

    queue_peek(map->queue, 0);
 
    // Remove
    char *removed = (char *)hash_map_remove(map, "test");
    printf("Removed: %s\n", removed);
    free(removed); // caller owns it now
 
    // Cleanup
    hash_map_destroy(map);


    //
    queue_destroy_with_data_free(queue_create(),free);
    printf("Queue destroyed with data free\n");
    return 0;
}
 