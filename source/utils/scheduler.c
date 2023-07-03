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

struct timer_task {
    int id;                             /* identifier - used to delete */
    struct timeval timeout;             /* Next timeout */
    struct timeval interval;            /* Interval between execution */
    unsigned int repetitions;           /* number of configured repetitions */
    bool cancel;                        /* remove the task if true */

    bool execute;                       /* indication task should be executed */
    unsigned int execution_counter;     /* number of times the task was executed completely */

    int (*timer_call_back)(void *arg); /* Call back function */
    void *arg;                          /* Argument to be passed to call back function */
};

static int scheduler_calculate_timeout(struct scheduler *sched, struct timeval *t_now);
static int scheduler_get_number_tasks_pending(struct scheduler *sched, bool high_prio);
static int scheduler_remove_complete_tasks(struct scheduler *sched);
static int scheduler_update_timeout(struct scheduler *sched, struct timeval *t_diff);

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
                                unsigned int repetitions)
{
    struct timer_task *tt;
    static int new_id = 0;

    if (sched == NULL || cb == NULL) {
        return -1;
    }
    pthread_mutex_lock(&sched->lock);
    tt = (struct timer_task *) malloc(sizeof(struct timer_task));
    if (tt == NULL)
    {
        pthread_mutex_unlock(&sched->lock);
        return -1;
    }
    new_id++;
    tt->id = new_id;
    timerclear(&(tt->timeout));
    tt->interval.tv_sec = (interval_ms / 1000);
    tt->interval.tv_usec = (interval_ms % 1000) * 1000;
    tt->repetitions = repetitions;
    tt->cancel = false;
    tt->execute = false;
    tt->execution_counter = 0;
    tt->timer_call_back = cb;
    tt->arg = arg;

    if (high_prio == true) {
        queue_push(sched->high_priority_timer_list, tt);
        sched->num_hp_tasks++;
    } else {
        queue_push(sched->timer_list, tt);
        sched->num_tasks++;
    }
    if (id != NULL) {
        *id = tt->id;
    }
    pthread_mutex_unlock(&sched->lock);
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
    struct timeval new_timer, res;

    if (sched == NULL) {
        return -1;
    }
    pthread_mutex_lock(&sched->lock);
    for (i = 0; i < sched->num_hp_tasks; i++) {
        tt = queue_peek(sched->high_priority_timer_list, i);
        if (tt != NULL && tt->id == id) {
            new_timer.tv_sec = (interval_ms / 1000);
            new_timer.tv_usec = (interval_ms % 1000) * 1000;
            if(timercmp(&new_timer, &(tt->interval), >)) {
                timersub(&new_timer, &(tt->interval), &res);
                timeradd(&(tt->timeout), &res, &(tt->timeout));
                tt->interval.tv_sec = (interval_ms / 1000);
                tt->interval.tv_usec = (interval_ms % 1000) * 1000;
            } else if (timercmp(&new_timer, &(tt->interval), <)) {
                timersub(&(tt->interval), &new_timer, &res);
                timersub(&(tt->timeout), &res, &(tt->timeout));
                tt->interval.tv_sec = (interval_ms / 1000);
                tt->interval.tv_usec = (interval_ms % 1000) * 1000;
            }
            pthread_mutex_unlock(&sched->lock);
            return 0;
        }
    }
    for (i = 0; i < sched->num_tasks; i++) {
        tt = queue_peek(sched->timer_list, i);
        if (tt != NULL && tt->id == id) {
            new_timer.tv_sec = (interval_ms / 1000);
            new_timer.tv_usec = (interval_ms % 1000) * 1000;
            if(timercmp(&new_timer, &(tt->interval), >)) {
                timersub(&new_timer, &(tt->interval), &res);
                timeradd(&(tt->timeout), &res, &(tt->timeout));
                tt->interval.tv_sec = (interval_ms / 1000);
                tt->interval.tv_usec = (interval_ms % 1000) * 1000;
            } else if (timercmp(&new_timer, &(tt->interval), <)) {
                timersub(&(tt->interval), &new_timer, &res);
                timersub(&(tt->timeout), &res, &(tt->timeout));
                tt->interval.tv_sec = (interval_ms / 1000);
                tt->interval.tv_usec = (interval_ms % 1000) * 1000;
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

int scheduler_execute(struct scheduler *sched, struct timeval t_start, unsigned int timeout_ms)
{
    struct timeval t_now;
    struct timeval timeout;
    struct timeval interval;
    int timeout_ms_margin;
    struct timer_task *tt;
    int ret;
    static struct timeval last_t_start = {0,0};
    struct timeval t_diff;
    int high_priority_pending_tasks;
    int low_priority_pending_tasks;

    if (sched == NULL ) {
        return -1;
    }


    //detect system time change and update the timers
    if (last_t_start.tv_sec != 0) {
        t_diff.tv_sec = t_start.tv_sec - last_t_start.tv_sec;
        t_diff.tv_usec = t_start.tv_usec - last_t_start.tv_usec;
        if(t_diff.tv_usec < 0) {
            t_diff.tv_usec = t_diff.tv_usec + 1000000;
            t_diff.tv_sec = t_diff.tv_sec - 1;
        }
        if ( (unsigned int)((t_diff.tv_sec*1000) + (t_diff.tv_usec/1000)) > (timeout_ms*1000)) {
            //system time changed
            scheduler_update_timeout(sched, &t_diff);
        }
    }
    last_t_start = t_start;

    sched->t_start = t_start;
    t_now = t_start;
    /* return if reach 70% of the timeout */
    timeout_ms_margin = (timeout_ms*0.7);
    interval.tv_sec = (timeout_ms_margin / 1000);
    interval.tv_usec = (timeout_ms_margin % 1000) * 1000;
    timeradd(&t_start, &interval, &timeout);
    scheduler_remove_complete_tasks(sched);
    scheduler_calculate_timeout(sched, &t_now);

    high_priority_pending_tasks = scheduler_get_number_tasks_pending(sched, true);
    low_priority_pending_tasks = scheduler_get_number_tasks_pending(sched, false);

    pthread_mutex_lock(&sched->lock);
    while (timercmp(&timeout, &t_now, >)) {

        if (high_priority_pending_tasks == 0 && low_priority_pending_tasks == 0)
        {
            break;
        }
        //dont starve low priority
        if (sched->timer_list_age < 5) {
            while (high_priority_pending_tasks > 0 && timercmp(&timeout, &t_now, >)) {
                if (sched->num_hp_tasks > 0) {
                    tt = queue_peek(sched->high_priority_timer_list, sched->hp_index);
                    if (tt != NULL && tt->execute == true) {
                        pthread_mutex_unlock(&sched->lock);
                        ret = tt->timer_call_back(tt->arg);
                        pthread_mutex_lock(&sched->lock);
                        if (ret != TIMER_TASK_CONTINUE) {
                            tt->execute = false;
                            high_priority_pending_tasks = scheduler_get_number_tasks_pending(sched, true);
                            tt->execution_counter++;
                        }
                    }
                    if (tt != NULL && tt->execute == false) {
                        sched->hp_index++;
                        if (sched->hp_index >= sched->num_hp_tasks) {
                            sched->hp_index = 0;
                        }
                    }
                }
                gettimeofday(&t_now, NULL);
            }
        }
        if (timercmp(&timeout, &t_now, <)) {
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
                    if (tt != NULL && tt->execute == true) {
                        pthread_mutex_unlock(&sched->lock);
                        ret = tt->timer_call_back(tt->arg);
                        pthread_mutex_lock(&sched->lock);
                        if (ret != TIMER_TASK_CONTINUE) {
                            tt->execute = false;
                            tt->execution_counter++;
                            low_priority_pending_tasks = scheduler_get_number_tasks_pending(sched, false);
                        }
                    }
                    if (tt != NULL && tt->execute == false) {
                        sched->index++;
                        if (sched->index >= sched->num_tasks) {
                            sched->index = 0;
                        }
                    }
                }
                gettimeofday(&t_now, NULL);
            }
        }
    }
    pthread_mutex_unlock(&sched->lock);
    return 0;
}

static int scheduler_update_timeout(struct scheduler *sched, struct timeval *t_diff)
{
    unsigned int i;
    struct timer_task *tt;
    struct timeval new_timeout;

    if (sched == NULL || t_diff == NULL) {
        return -1;
    }
    for (i = 0; i < sched->num_tasks; i++) {
        tt = queue_peek(sched->timer_list, i);
        if (tt != NULL) {
            timeradd(&(tt->timeout), t_diff, &new_timeout);
            tt->timeout = new_timeout;
        }
    }
    for (i = 0; i < sched->num_hp_tasks; i++) {
        tt = queue_peek(sched->high_priority_timer_list, i);
        if (tt != NULL) {
            timeradd(&(tt->timeout), t_diff, &new_timeout);
            tt->timeout = new_timeout;
        }
    }
    return 0;
}

static int scheduler_calculate_timeout(struct scheduler *sched, struct timeval *t_now)
{
    unsigned int i;
    struct timer_task *tt;

    if (sched == NULL || t_now == NULL) {
        return -1;
    }
    for (i = 0; i < sched->num_tasks; i++) {
        tt = queue_peek(sched->timer_list, i);
        if (tt != NULL && timercmp(t_now, &(tt->timeout), >)) {
            if(tt->execute == true) {
                printf("Error: **** Timer task expired again before previous execution to complete  !!!\n");
            }
            if (tt->timeout.tv_sec == 0 && tt->timeout.tv_usec == 0) {
                tt->execute = false;
            } else {
                tt->execute = true;
            }
            timeradd(t_now, &(tt->interval), &(tt->timeout));
        }
    }
    for (i = 0; i < sched->num_hp_tasks; i++) {
        tt = queue_peek(sched->high_priority_timer_list, i);
        if (tt != NULL && timercmp(t_now, &(tt->timeout), >)) {
            if(tt->execute == true) {
                printf("Error: **** Timer task expired again before previous execution to complete (high priority) !!!\n");
            }
            if (tt->timeout.tv_sec == 0 && tt->timeout.tv_usec == 0) {
                tt->execute = false;
            } else {
                tt->execute = true;
            }
            timeradd(t_now, &(tt->interval), &(tt->timeout));
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
    struct timer_task *tt;

    if (sched == NULL) {
        return -1;
    }
    for (i = 0; i < sched->num_tasks; i++) {
        tt = queue_peek(sched->timer_list, i);
        if (tt != NULL) {
            if((tt->repetitions != 0 && tt->execution_counter == tt->repetitions) || tt->cancel == true) {
                queue_remove(sched->timer_list, i);
                free(tt);
                sched->num_tasks--;
                if(sched->index >= sched->num_tasks)
                {
                    sched->index = 0;
                }
                i--;
            }
        }
    }
    for (i = 0; i < sched->num_hp_tasks; i++) {
        tt = queue_peek(sched->high_priority_timer_list, i);
        if (tt != NULL) {
            if((tt->repetitions != 0 && tt->execution_counter == tt->repetitions) || tt->cancel == true) {
                queue_remove(sched->high_priority_timer_list, i);
                free(tt);
                sched->num_hp_tasks--;
                if (sched->hp_index >= sched->num_hp_tasks) {
                    sched->hp_index = 0;
                }
                i--;
            }
        }
    }
    return 0;
}


