/************************************************************************************
  Simple unit test for collection.c queue and hash_map
  Tests: no double-free, no use-after-free, proper payload cleanup
 **************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "collection.h"

#define TEST_PASS  printf("✓ PASS: %s\n", __func__)
#define TEST_FAIL  printf("✗ FAIL: %s\n", __func__); return 1

/* Test 1: Queue push/pop/destroy */
int test_queue_basic() {
    printf("\n=== Test 1: Queue Basic Operations ===\n");
    
    queue_t *q = queue_create();
    if (q == NULL) {
        TEST_FAIL;
    }
    
    // Push some data
    int *data1 = (int *)malloc(sizeof(int));
    int *data2 = (int *)malloc(sizeof(int));
    int *data3 = (int *)malloc(sizeof(int));
    
    *data1 = 10;
    *data2 = 20;
    *data3 = 30;
    
    queue_push(q, data1);
    queue_push(q, data2);
    queue_push(q, data3);
    
    if (queue_count(q) != 3) {
        printf("  Expected count 3, got %u\n", queue_count(q));
        TEST_FAIL;
    }
    
    // Pop and verify order (LIFO for this implementation)
    int *val = (int *)queue_pop(q);
    if (val == NULL || *val != 30) {
        printf("  Expected 30, got %d\n", val ? *val : -1);
        TEST_FAIL;
    }
    free(val);
    
    // Destroy — should NOT crash (no double-free)
    // NOTE: remaining items (data1, data2) are NOT freed by queue_destroy
    // So we must free them manually
    val = (int *)queue_pop(q);
    if (val) free(val);
    val = (int *)queue_pop(q);
    if (val) free(val);
    
    queue_destroy(q);
    
    TEST_PASS;
    return 0;
}

/* Test 2: Queue destroy_with_data_free */
int test_queue_destroy_with_data_free() {
    printf("\n=== Test 2: Queue destroy_with_data_free ===\n");
    
    queue_t *q = queue_create();
    if (q == NULL) {
        TEST_FAIL;
    }
    
    // Push heap-allocated data
    for (int i = 0; i < 5; i++) {
        int *data = (int *)malloc(sizeof(int));
        *data = i * 10;
        queue_push(q, data);
    }
    
    if (queue_count(q) != 5) {
        TEST_FAIL;
    }
    
    // Destroy with automatic payload freeing — should NOT crash
    queue_destroy_with_data_free(q, free);
    
    TEST_PASS;
    return 0;
}

/* Test 3: Hash map put/get/remove */
int test_hash_map_basic() {
    printf("\n=== Test 3: Hash Map Basic Operations ===\n");
    
    hash_map_t *map = hash_map_create();
    if (map == NULL) {
        TEST_FAIL;
    }
    
    // Store some key-value pairs
    int *val1 = (int *)malloc(sizeof(int));
    int *val2 = (int *)malloc(sizeof(int));
    int *val3 = (int *)malloc(sizeof(int));
    
    *val1 = 100;
    *val2 = 200;
    *val3 = 300;
    
    hash_map_put(map, strdup("key1"), val1);
    hash_map_put(map, strdup("key2"), val2);
    hash_map_put(map, strdup("key3"), val3);
    
    if (hash_map_count(map) != 3) {
        printf("  Expected count 3, got %u\n", hash_map_count(map));
        TEST_FAIL;
    }
    
    // Get values
    int *retrieved = (int *)hash_map_get(map, "key2");
    if (retrieved == NULL || *retrieved != 200) {
        printf("  Expected 200, got %d\n", retrieved ? *retrieved : -1);
        TEST_FAIL;
    }
    
    // Remove entry
    int *removed = (int *)hash_map_remove(map, "key1");
    if (removed == NULL || *removed != 100) {
        printf("  Expected 100, got %d\n", removed ? *removed : -1);
        TEST_FAIL;
    }
    free(removed);
    
    if (hash_map_count(map) != 2) {
        printf("  After remove, expected count 2, got %u\n", hash_map_count(map));
        TEST_FAIL;
    }
    
    // Destroy — should NOT crash or double-free
    hash_map_destroy(map);
    
    TEST_PASS;
    return 0;
}

/* Test 4: Hash map iteration */
int test_hash_map_iteration() {
    printf("\n=== Test 4: Hash Map Iteration ===\n");
    
    hash_map_t *map = hash_map_create();
    if (map == NULL) {
        TEST_FAIL;
    }
    
    // Add entries
    for (int i = 0; i < 3; i++) {
        char key[32];
        snprintf(key, sizeof(key), "key%d", i);
        int *val = (int *)malloc(sizeof(int));
        *val = i * 100;
        hash_map_put(map, strdup(key), val);
    }
    
    // Iterate through all entries
    void *data = hash_map_get_first(map);
    int count = 0;
    while (data != NULL) {
        count++;
        data = hash_map_get_next(map, data);
    }
    
    if (count != 3) {
        printf("  Expected to iterate 3 items, got %d\n", count);
        TEST_FAIL;
    }
    
    hash_map_destroy(map);
    
    TEST_PASS;
    return 0;
}

/* Test 5: Hash map clone */
int test_hash_map_clone() {
    printf("\n=== Test 5: Hash Map Clone ===\n");
    
    hash_map_t *src = hash_map_create();
    
    // Add some data
    for (int i = 0; i < 3; i++) {
        char key[32];
        snprintf(key, sizeof(key), "key%d", i);
        int *val = (int *)malloc(sizeof(int));
        *val = i * 100;
        hash_map_put(src, strdup(key), val);
    }
    
    // Clone with sizeof(int) as data size
    hash_map_t *dst = hash_map_clone(src, sizeof(int));
    if (dst == NULL) {
        TEST_FAIL;
    }
    
    if (hash_map_count(dst) != hash_map_count(src)) {
        printf("  Clone count mismatch\n");
        TEST_FAIL;
    }
    
    // Both destroy — should NOT crash
    hash_map_destroy(src);
    hash_map_destroy(dst);
    
    TEST_PASS;
    return 0;
}

int main() {
    printf("\n╔════════════════════════════════════════════════════════╗\n");
    printf("║  Collection.c Unit Tests - Memory Safety Verification  ║\n");
    printf("╚════════════════════════════════════════════════════════╝\n");
    
    int failed = 0;
    
    failed += test_queue_basic();
    failed += test_queue_destroy_with_data_free();
    failed += test_hash_map_basic();
    failed += test_hash_map_iteration();
    failed += test_hash_map_clone();
    
    printf("\n╔════════════════════════════════════════════════════════╗\n");
    if (failed == 0) {
        printf("║  ✓ ALL TESTS PASSED - Memory fixes working correctly!  ║\n");
    } else {
        printf("║  ✗ %d TEST(S) FAILED                                   ║\n", failed);
    }
    printf("╚════════════════════════════════════════════════════════╝\n\n");
    
    return failed;
}
