#ifndef WIFIEVENTS_CONSUMER_SAMPLE_H
#define WIFIEVENTS_CONSUMER_SAMPLE_H

#include <stdio.h>
#include <string.h>
#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif

// Enum for different gestures/motions
typedef enum {
    GESTURE_IDLE = 0,
    GESTURE_HAND_MOVEMENT = 0x0001,
    GESTURE_WALKING = 0x0002,
    GESTURE_RUNNING = 0x0004
} motion_gesture_t;

typedef struct {
    motion_gesture_t value;
    const char *name;
} motion_gesture_map_t;

void set_motion_gesture_obj(motion_gesture_t val);

int start_cli_thread(void);

#ifdef __cplusplus
}
#endif

#endif // WIFIEVENTS_CONSUMER_SAMPLE_H
