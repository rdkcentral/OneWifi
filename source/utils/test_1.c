
#include "collection.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

int main() {
    hash_map_t *map = hash_map_create();

    // Insert 4 hardcoded key-value pairs
    char *keys[] = {"test1", "test2", "test3", "test4"};
    char *values[] = {"value1", "value2", "value3", "value4"};

    for (int i = 0; i < 4; i++) {
        if (hash_map_put(map, strdup(keys[i]), strdup(values[i])) == 0) {
            printf("Inserted: %s -> %s\n", keys[i], values[i]);
        } else {
            printf("Failed to insert: %s\n", keys[i]);
        }
    }

    // Retrieve and print all 4 values
    for (int i = 0; i < 4; i++) {
        char *val = (char *)hash_map_get(map, keys[i]);
        printf("Retrieved: %s -> %s\n", keys[i], val);
    }

    // Peek into queue (assuming queue is part of map)
    queue_peek(map->queue, 0);

    // Remove one key and print
    char *removed = (char *)hash_map_remove(map, "test2");
    printf("Removed: %s\n", removed);
    free(removed);

    // Cleanup
   

    for (int i = 0; i < 4; i++) {
        char *val = (char *)hash_map_get(map, keys[i]);
        printf("Retrieved: %s -> %s\n", keys[i], val);
    }
 hash_map_destroy(map);
    // Test queue destroy with data free
    queue_destroy_with_data_free(queue_create(), free);
    printf("Queue destroyed with data free\n");

    return 0;
}
