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

#include <sys/time.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include "scheduler.h"
#include "timespec_macro.h"

struct timer_task {
    int id;                             /* identifier - used to delete */
    struct timespec timeout;            /* Next timeout */
    struct timespec interval;           /* Interval between execution */
    unsigned int repetitions;           /* number of configured repetitions */
    bool cancel;                        /* remove the task if true */

    bool execute;                       /* indication task should be executed */
    unsigned int execution_counter;     /* number of times the task was executed completely */

    int (*timer_call_back)(void *arg); /* Call back function */
    void *arg;                          /* Argument to be passed to call back function */
};

static int scheduler_calculate_timeout(struct scheduler *sched, struct timespec t_now);
static int scheduler_get_number_tasks_pending(struct scheduler *sched, bool high_prio);
static int scheduler_remove_complete_tasks(struct scheduler *sched);

struct scheduler * scheduler_init(void)
{
    struct scheduler *sched = (struct scheduler *) malloc(sizeof(struct scheduler));

    if (sched != NULL) {
        pthread_mutex_init(&sched->lock, NULL);

        sched->high_priority_timer_list = queue_create();
        if (sched->high_priority_timer_list == NULL) {
            free(sched);
            pthread_mutex_destroy(&sched->lock);
            return NULL;
        }
        sched->num_hp_tasks = 0;
        sched->hp_index = 0;

        sched->timer_list = queue_create();
        if (sched->timer_list == NULL) {
            queue_destroy(sched->timer_list);
            free(sched);
            pthread_mutex_destroy(&sched->lock);
            return NULL;
        }
        sched->num_tasks = 0;
        sched->index = 0;
        sched->timer_list_age = 0;
    }
    return sched;
}

int scheduler_deinit(struct scheduler **sched)
{
    if (sched == NULL && *sched == NULL) {
        return -1;
    }
    pthread_mutex_lock(&(*sched)->lock);
    if ((*sched)->high_priority_timer_list != NULL) {
        queue_destroy((*sched)->high_priority_timer_list);
    }
    if ((*sched)->timer_list != NULL) {
        queue_destroy((*sched)->timer_list);
    }
    pthread_mutex_unlock(&(*sched)->lock);
    pthread_mutex_destroy(&(*sched)->lock);
    free(*sched);
    *sched = NULL;
    return 0;
}

int scheduler_add_timer_task(struct scheduler *sched, bool high_prio, int *id,
                                int (*cb)(void *arg), void *arg, unsigned int interval_ms,
                                unsigned int repetitions, bool start_immediately)
{
    struct timer_task *tt;
    static int new_id = 0;
    struct
    {
        queue_t *timer_list;
        unsigned int *num_tasks;
        unsigned int *index;
    } sched_queue;

    if (sched == NULL || cb == NULL) {
        return -1;
    }
    tt = (struct timer_task *) malloc(sizeof(struct timer_task));
    if (tt == NULL)
    {
        return -1;
    }
    timespecclear(&(tt->timeout));
    tt->interval.tv_sec = (interval_ms / 1000);
    tt->interval.tv_nsec = ((interval_ms % 1000) * 1000 * 1000);
    tt->repetitions = repetitions;
    tt->cancel = false;
    tt->execute = false;
    tt->execution_counter = 0;
    tt->timer_call_back = cb;
    tt->arg = arg;

    if (start_immediately) {
        clock_gettime(CLOCK_MONOTONIC, &(tt->timeout));
    }
    if (high_prio) {
        sched_queue.timer_list = sched->high_priority_timer_list;
        sched_queue.num_tasks = &sched->num_hp_tasks;
        sched_queue.index = &sched->hp_index;
    } else {
        sched_queue.timer_list = sched->timer_list;
        sched_queue.num_tasks = &sched->num_tasks;
        sched_queue.index = &sched->index;
    }

    pthread_mutex_lock(&sched->lock);
    new_id++;
    tt->id = new_id;
    queue_push(sched_queue.timer_list, tt);
    (*sched_queue.num_tasks)++;
    (*sched_queue.index)++;
    if ((*sched_queue.index) >= (*sched_queue.num_tasks)) {
        (*sched_queue.index) = (*sched_queue.num_tasks) - 1;
    }
    pthread_mutex_unlock(&sched->lock);

    if (id != NULL) {
        *id = tt->id;
    }
    return 0;
}

static struct timer_task *scheduler_find_timer_task(struct scheduler *sched, int id)
{
    struct timer_task *tt;
    unsigned int i;

    if (sched == NULL) {
        return NULL;
    }
    for (i = 0; i < sched->num_hp_tasks; i++) {
        tt = queue_peek(sched->high_priority_timer_list, i);
        if (tt != NULL && tt->id == id) {
            return tt;
        }
    }
    for (i = 0; i < sched->num_tasks; i++) {
        tt = queue_peek(sched->timer_list, i);
        if (tt != NULL && tt->id == id) {
            return tt;
        }
    }

    /* could not find the task */
    return NULL;
}

int scheduler_cancel_timer_task(struct scheduler *sched, int id)
{
    struct timer_task *tt;
    int ret = -1;

    if (sched == NULL) {
        return ret;
    }

    pthread_mutex_lock(&sched->lock);
    tt = scheduler_find_timer_task(sched, id);

    if (tt) {
        tt->cancel = true;
        ret = 0;
    }

    pthread_mutex_unlock(&sched->lock);

    return ret;
}

int scheduler_free_timer_task_arg(struct scheduler *sched, int id)
{
    struct timer_task *tt;
    int ret = -1;

    if (sched == NULL) {
        return ret;
    }

    pthread_mutex_lock(&sched->lock);
    tt = scheduler_find_timer_task(sched, id);

    if (tt) {
        free(tt->arg);
        tt->arg = NULL;
        ret = 0;
    }

    pthread_mutex_unlock(&sched->lock);

    return ret;
}

int scheduler_update_timer_task_interval(struct scheduler *sched, int id, unsigned int interval_ms)
{
    struct timer_task *tt;
    unsigned int i;
    struct timespec new_timer, res;

    if (sched == NULL) {
        return -1;
    }
    pthread_mutex_lock(&sched->lock);
    for (i = 0; i < sched->num_hp_tasks; i++) {
        tt = queue_peek(sched->high_priority_timer_list, i);
        if (tt != NULL && tt->id == id) {
            new_timer.tv_sec = (interval_ms / 1000);
            new_timer.tv_nsec = ((interval_ms % 1000) * 1000 * 1000);
            if(timespeccmp(&new_timer, &(tt->interval), >)) {
                if (timespecisset(&tt->timeout)) {
                    timespecsub(&new_timer, &(tt->interval), &res);
                    timespecadd(&(tt->timeout), &res, &(tt->timeout));
                }
                tt->interval.tv_sec = (interval_ms / 1000);
                tt->interval.tv_nsec = ((interval_ms % 1000) * 1000 * 100);
            } else if (timespeccmp(&new_timer, &(tt->interval), <)) {
                if (timespecisset(&tt->timeout)) {
                    timespecsub(&(tt->interval), &new_timer, &res);
                    timespecsub(&(tt->timeout), &res, &(tt->timeout));
                }
                tt->interval.tv_sec = (interval_ms / 1000);
                tt->interval.tv_nsec = ((interval_ms % 1000) * 1000 * 1000);
            }
            pthread_mutex_unlock(&sched->lock);
            return 0;
        }
    }
    for (i = 0; i < sched->num_tasks; i++) {
        tt = queue_peek(sched->timer_list, i);
        if (tt != NULL && tt->id == id) {
            new_timer.tv_sec = (interval_ms / 1000);
            new_timer.tv_nsec = ((interval_ms % 1000) * 1000 * 1000);
            if(timespeccmp(&new_timer, &(tt->interval), >)) {
                if (timespecisset(&tt->timeout)) {
                    timespecsub(&new_timer, &(tt->interval), &res);
                    timespecadd(&(tt->timeout), &res, &(tt->timeout));
                }
                tt->interval.tv_sec = (interval_ms / 1000);
                tt->interval.tv_nsec = ((interval_ms % 1000) * 1000 * 1000);
            } else if (timespeccmp(&new_timer, &(tt->interval), <)) {
                if (timespecisset(&tt->timeout)) {
                    timespecsub(&(tt->interval), &new_timer, &res);
                    timespecsub(&(tt->timeout), &res, &(tt->timeout));
                }
                tt->interval.tv_sec = (interval_ms / 1000);
                tt->interval.tv_nsec = ((interval_ms % 1000) * 1000 * 1000);
            }
            pthread_mutex_unlock(&sched->lock);
            return 0;
        }
    }
    pthread_mutex_unlock(&sched->lock);
    /* could not find the task */
    return -1;
}

int scheduler_update_timer_task_repetitions(struct scheduler *sched, int id, unsigned int repetitions)
{
    struct timer_task *tt;
    unsigned int i;

    if (sched == NULL) {
        return -1;
    }
    pthread_mutex_lock(&sched->lock);
    for (i = 0; i < sched->num_hp_tasks; i++) {
        tt = queue_peek(sched->high_priority_timer_list, i);
        if (tt != NULL && tt->id == id) {
            tt->repetitions = repetitions;
            pthread_mutex_unlock(&sched->lock);
            return 0;
        }
    }
    for (i = 0; i < sched->num_tasks; i++) {
        tt = queue_peek(sched->timer_list, i);
        if (tt != NULL && tt->id == id) {
            tt->repetitions = repetitions;
            pthread_mutex_unlock(&sched->lock);
            return 0;
        }
    }
    pthread_mutex_unlock(&sched->lock);
    /* could not find the task */
    return -1;
}

bool scheduler_timer_task_is_completed(struct scheduler *sched, int id)
{
    return (scheduler_find_timer_task(sched, id) ? false : true);
}

int scheduler_execute(struct scheduler *sched, struct timespec t_start, unsigned int timeout_ms)
{
    struct timespec t_now;
    struct timespec timeout;
    struct timespec interval;
    int timeout_ms_margin;
    struct timer_task *tt;
    int ret;
    int high_priority_pending_tasks;
    int low_priority_pending_tasks;

    if (sched == NULL ) {
        return -1;
    }

    t_now = t_start;
    /* return if reach 70% of the timeout */
    timeout_ms_margin = (timeout_ms*0.7);
    interval.tv_sec = (timeout_ms_margin / 1000);
    interval.tv_nsec = ((timeout_ms_margin % 1000) * 1000 * 1000);
    timespecadd(&t_start, &interval, &timeout);

    pthread_mutex_lock(&sched->lock);
    scheduler_remove_complete_tasks(sched);
    scheduler_calculate_timeout(sched, t_now);

    high_priority_pending_tasks = scheduler_get_number_tasks_pending(sched, true);
    low_priority_pending_tasks = scheduler_get_number_tasks_pending(sched, false);

    while (timespeccmp(&timeout, &t_now, >)) {

        if (high_priority_pending_tasks == 0 && low_priority_pending_tasks == 0)
        {
            break;
        }
        //dont starve low priority
        if (sched->timer_list_age < 5) {
            while (high_priority_pending_tasks > 0 && timespeccmp(&timeout, &t_now, >)) {
                if (sched->num_hp_tasks > 0) {
                    tt = queue_peek(sched->high_priority_timer_list, sched->hp_index);
                    if (tt != NULL && tt->execute == true && tt->cancel == false) {
                        pthread_mutex_unlock(&sched->lock);
                        ret = tt->timer_call_back(tt->arg);
                        pthread_mutex_lock(&sched->lock);
                        if (ret != TIMER_TASK_CONTINUE) {
                            tt->execute = false;
                            high_priority_pending_tasks = scheduler_get_number_tasks_pending(sched, true);
                            tt->execution_counter++;
                        }
                    }
                    if (tt != NULL && (tt->execute == false || tt->cancel == true)) {
                        sched->hp_index--;
                        if (sched->hp_index >= sched->num_hp_tasks) {
                            sched->hp_index = sched->num_hp_tasks - 1;
                        }
                    }
                }
                clock_gettime(CLOCK_MONOTONIC, &t_now);
            }
        }
        if (timespeccmp(&timeout, &t_now, <)) {
            if (low_priority_pending_tasks > 0) {
                //dont starve low priority
                sched->timer_list_age++;
            }
            break;
        } else {
            if (low_priority_pending_tasks > 0) {
                sched->timer_list_age = 0;
                if (sched->num_tasks > 0) {
                    tt = queue_peek(sched->timer_list, sched->index);
                    if (tt != NULL && tt->execute == true && tt->cancel == false) {
                        pthread_mutex_unlock(&sched->lock);
                        ret = tt->timer_call_back(tt->arg);
                        pthread_mutex_lock(&sched->lock);
                        if (ret != TIMER_TASK_CONTINUE) {
                            tt->execute = false;
                            tt->execution_counter++;
                            low_priority_pending_tasks = scheduler_get_number_tasks_pending(sched, false);
                        }
                    }
                    if (tt != NULL && (tt->execute == false || tt->cancel == true)) {
                        sched->index--;
                        if (sched->index >= sched->num_tasks) {
                            sched->index = sched->num_tasks - 1;
                        }
                    }
                }
                clock_gettime(CLOCK_MONOTONIC, &t_now);
            }
        }
    }
    pthread_mutex_unlock(&sched->lock);
    return 0;
}

static int scheduler_calculate_timeout(struct scheduler *sched, struct timespec t_now)
{
    unsigned int i;
    struct timer_task *tt;

    if (sched == NULL) {
        return -1;
    }
    for (i = 0; i < sched->num_tasks; i++) {
        tt = queue_peek(sched->timer_list, i);
        if (tt != NULL && timespeccmp(&t_now, &(tt->timeout), >)) {
            if(tt->execute == true) {
                printf("Error: **** Timer task expired again before previous execution to complete  !!!\n");
            }
            tt->execute = timespecisset(&tt->timeout);
            timespecadd(&t_now, &(tt->interval), &(tt->timeout));
        }
    }
    for (i = 0; i < sched->num_hp_tasks; i++) {
        tt = queue_peek(sched->high_priority_timer_list, i);
        if (tt != NULL && timespeccmp(&t_now, &(tt->timeout), >)) {
            if(tt->execute == true) {
                printf("Error: **** Timer task expired again before previous execution to complete (high priority) !!!\n");
            }
            tt->execute = timespecisset(&tt->timeout);
            timespecadd(&t_now, &(tt->interval), &(tt->timeout));
        }
    }
    return 0;
}

static int scheduler_get_number_tasks_pending(struct scheduler *sched, bool high_prio)
{
    unsigned int i;
    int pending = 0;
    struct timer_task *tt;

    if (sched == NULL ) {
        return -1;
    }
    if (high_prio == true) {
        for (i = 0; i < sched->num_hp_tasks; i++) {
            tt = queue_peek(sched->high_priority_timer_list, i);
            if (tt != NULL && tt->execute == true) {
                pending++;
            }
        }
    } else {
        for (i=0; i < sched->num_tasks; i++) {
            tt = queue_peek(sched->timer_list, i);
            if (tt != NULL && tt->execute == true) {
                pending++;
            }
        }
    }

    return pending;
}

static int scheduler_remove_complete_tasks(struct scheduler *sched)
{
    unsigned int i;
    int hp_id = 0, lp_id = 0;
    int hp_update_index = 0, lp_update_index = 0;
    struct timer_task *tt;

    if (sched == NULL) {
        return -1;
    }

    if (sched->num_tasks > 0) {
        tt = queue_peek(sched->timer_list, sched->index);
        if(tt != NULL) {
            lp_id = tt->id;
            lp_update_index = 1;
        }
    }
    if (sched->num_hp_tasks > 0) {
        tt = queue_peek(sched->high_priority_timer_list, sched->hp_index);
        if(tt != NULL) {
            hp_id = tt->id;
            hp_update_index = 1;
        }
    }
    for (i = 0; i < sched->num_tasks; i++) {
        tt = queue_peek(sched->timer_list, i);
        if (tt != NULL) {
            if((tt->repetitions != 0 && tt->execution_counter == tt->repetitions) || tt->cancel == true) {
                queue_remove(sched->timer_list, i);
                if (tt->id == lp_id) {
                    lp_update_index = 0;
                    sched->index = i-1;
                }
                free(tt);
                sched->num_tasks--;
                i--;
            }
        }
    }
    for (i = 0; i < sched->num_hp_tasks; i++) {
        tt = queue_peek(sched->high_priority_timer_list, i);
        if (tt != NULL) {
            if((tt->repetitions != 0 && tt->execution_counter == tt->repetitions) || tt->cancel == true) {
                queue_remove(sched->high_priority_timer_list, i);
                if (tt->id == hp_id) {
                    hp_update_index = 0;
                    sched->hp_index = i-1;
                }
                free(tt);
                sched->num_hp_tasks--;
                i--;
            }
        }
    }
    if (lp_update_index == 1) {
        for (i = 0; i < sched->num_tasks; i++) {
            tt = queue_peek(sched->timer_list, i);
            if (tt != NULL && tt->id == lp_id) {
                sched->index = i;
                break;
            }
        }
    }
    if (hp_update_index == 1) {
        for (i = 0; i < sched->num_hp_tasks; i++) {
            tt = queue_peek(sched->high_priority_timer_list, i);
            if (tt != NULL && tt->id == hp_id) {
                sched->hp_index = i;
                break;
            }
        }
    }
    //make sure index is valid
    if (sched->num_tasks > 0 && sched->index >= sched->num_tasks) {
        sched->index = sched->num_tasks -1;
    }
    if (sched->num_hp_tasks > 0 && sched->hp_index >= sched->num_hp_tasks) {
        sched->hp_index = sched->num_hp_tasks -1;
    }
    return 0;
}


