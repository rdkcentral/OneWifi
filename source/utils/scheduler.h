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

#ifndef SCHEDULER_H
#define SCHEDULER_H

#ifdef __cplusplus
extern "C" {
#endif

#include "collection.h"
#include <sys/time.h>
#include <pthread.h>

/*
    Return value of scheduled functions.
    The function will be continue to be executed
    while returning TIMER_TASK_CONTINUE.
*/
#define TIMER_TASK_COMPLETE     0
#define TIMER_TASK_CONTINUE     1
#define TIMER_TASK_ERROR        -1

struct scheduler {
    queue_t *high_priority_timer_list;      /* high priority queue */
    unsigned int num_hp_tasks;                       /* number of task in high priority queue */
    unsigned int hp_index;                           /* next task to be executed */

    queue_t *timer_list;                    /* low priority queue */
    unsigned int num_tasks;                          /* number of task in low priority queue */
    unsigned int index;                              /* next task to be executed */
    unsigned int timer_list_age;                     /* low priority queue age */

    pthread_mutex_t lock;
};

 /* Description:
  *      This api is used for the initialization of scheduler
  * Return Value:
  *      Returns pointer to the scheduler struct
  */
struct scheduler * scheduler_init(void);

/* Description:
  *      This API is used to terminate the scheduler
  * Arguments:
  *      sched - Pointer to the scheduler struct
  * Return Value:
  *      Returns 0 on Success, -1 on Failure
  */
int scheduler_deinit(struct scheduler **sched);


/* Description:
  *      This API is used to add the timer task to the scheduler
  * Arguments:
  *      sched - Pointer to the scheduler struct
  *      high_prio - if high_prio == TRUE, Its an high priority task
  *      id - unique identifier to denote the timer task
  *      cb - callback function
  *      arg - Argument to be passed to call back function
  *      interval_ms - time interval in milliseconds
  *      repetitions -  number of configured repetitions, if repetitions=0 then it will run forever
  * Returns:
  *     Returns 0 on Success, -1 on Failure
  */
int scheduler_add_timer_task(struct scheduler *sched, bool high_prio, int *id,
                                int (*cb)(void *arg), void *arg, unsigned int interval_ms, unsigned int repetitions, bool start_immediately);

/* Description:
  *      This API is used to cancel the timer task from the scheduler
  * Arguments:
  *      sched - Pointer to the scheduler struct
  *      id - unique identifier to denote the timer task
  * Returns:
  *       Returns 0 on Success, -1 on Failure
  */
int scheduler_cancel_timer_task(struct scheduler *sched, int id);


/* Description:
  *      This API is used to update the time interval for the task in milliseconds
  * Arguments:
  *      sched - Pointer to the scheduler struct
  *      id - unique identifier to denote the timer task
  *      interval_ms - new interval in milliseconds
  * Returns:
  *       Returns 0 on Success, -1 on Failure
  */
int scheduler_update_timer_task_interval(struct scheduler *sched, int id, unsigned int interval_ms);

/* Description:
  *      This API is used to check if the task is completed
  * Arguments:
  *      sched - Pointer to the scheduler struct
  *      id - unique identifier to denote the timer task
  * Returns:
  *       Returns true if it is the last repetition, or task is cancelled, false otherwise
  */
bool scheduler_timer_task_is_completed(struct scheduler *sched, int id);

/* Description:
  *      This API is used to update the repetitions for the task
  * Arguments:
  *      sched - Pointer to the scheduler struct
  *      id - unique identifier to denote the timer task
  *      repetitions - new repetitions number, if repetitions=0 then it will run forever
  * Returns:
  *       Returns 0 on Success, -1 on Failure
  */
int scheduler_update_timer_task_repetitions(struct scheduler *sched, int id, unsigned int repetitions);


/* Description:
  *      This API is used run the scheduler
  * Arguments:
  *      sched - Pointer to the scheduler struct
  *      t_start - start time
  *      timeout_ms - timeout in milliseconds
  * Returns:
  *       Returns 0 on Success, -1 on Failure
  */
int scheduler_execute(struct scheduler *sched, struct timespec t_start, unsigned int timeout_ms);

/* Description:
  *      This API is used to free task's arg if such was allocated
  * Arguments:
  *      sched - Pointer to the scheduler struct
  *      id - unique identifier to denote the timer task
  * Returns:
  *       Returns 0 on Success, -1 on Failure
  */
int scheduler_free_timer_task_arg(struct scheduler *sched, int id);

#ifdef __cplusplus
}
#endif
#endif /* SCHEDULER_H */


