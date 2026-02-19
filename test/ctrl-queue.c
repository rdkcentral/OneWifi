#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <collection.h>
#include <wifi_ctrl.h>
#include <wifi_mgr.h>
#include <assert.h>
#include <sys/time.h>

#define called() \
	do { \
		struct timeval tv; \
		gettimeofday(&tv, NULL); \
		printf("%ld.%03ld:%s:%d: Called\n", tv.tv_sec, tv.tv_usec / 1000, __func__, __LINE__); \
	} while (0)

static wifi_ctrl_t *ldk_wifi_ctrl_g;
extern void ctrl_queue_loop(wifi_ctrl_t *);

extern void ldk (void) {
	assert(0);
}

static unsigned char scheduler_executed = false;

int scheduler_execute(struct scheduler *sched, struct timespec t_start, unsigned int timeout_ms)
{
	usleep(timeout_ms * 1000);
	scheduler_executed = true;
	return 0;
}

wifi_ctrl_t *get_wifictrl_obj(void) {
	return ldk_wifi_ctrl_g;
}

wifi_mgr_t *get_wifimgr_obj(void) {
	return NULL;
}

int get_number_of_radios(wifi_platform_property_t *wifi_prop) {
	return 1;
}

int apps_mgr_event(wifi_apps_mgr_t *apps_mgr, wifi_event_t *event) {
	// printf("%s:%d: Called\n", __func__, __LINE__);
	return -1;
}

void wifi_util_print(wifi_log_level_t level, wifi_dbg_type_t module, char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	vprintf(format, ap);
	va_end(ap);
}

struct ts {
	uint64_t ts;
};

void handle_hal_indication(wifi_ctrl_t *ctrl, void *data, unsigned int len,
		           wifi_event_subtype_t subtype) {
	struct ts *ts = data;
	struct timespec tv;
	clock_gettime(CLOCK_MONOTONIC, &tv);
	const uint64_t delay = (tv.tv_sec * 1000 + tv.tv_nsec /1000 /1000) - ts->ts;
	printf("%s:%d: Processing delay: %ld\n", __func__, __LINE__, delay);
	assert(delay < 200);

	// simulate short event
	usleep(10 * 1000);
}

void handle_webconfig_event(wifi_ctrl_t *ctrl, const char *raw, unsigned int len,
		            wifi_event_subtype_t subtype) {
	// simulate long event
	usleep(200 * 1000);
}

void * ctrl_queue_wrapper(void *arg) {
	wifi_ctrl_t *ctrl = arg;
	ctrl_queue_loop(ctrl);
	return NULL;
}

static void push_event(const wifi_event_type_t event) {
	struct ts ts;
	struct timespec tv;
	memset(&ts, 0x0, sizeof(ts));
	clock_gettime(CLOCK_MONOTONIC, &tv);
	ts.ts = tv.tv_sec * 1000 + tv.tv_nsec /1000 /1000;
	push_event_to_ctrl_queue(&ts, sizeof(ts), event, 0, NULL);
}

int main(int argc, char *argv[]) {
	wifi_ctrl_t ctrl;
	memset(&ctrl, 0x0, sizeof(ctrl));

	/* Init ctrl-queue */
    	clock_gettime(CLOCK_MONOTONIC, &ctrl.last_signalled_time);
    	clock_gettime(CLOCK_MONOTONIC, &ctrl.last_polled_time);

    	pthread_condattr_t cond_attr;
    	pthread_condattr_init(&cond_attr);
    	pthread_condattr_setclock(&cond_attr, CLOCK_MONOTONIC);
    	pthread_cond_init(&ctrl.cond, &cond_attr);
    	pthread_condattr_destroy(&cond_attr);

	pthread_mutexattr_init(&ctrl.attr);
	pthread_mutexattr_settype(&ctrl.attr, PTHREAD_MUTEX_RECURSIVE);
	pthread_mutex_init(&ctrl.queue_lock, &ctrl.attr);

	ctrl.queue = queue_create();
	ctrl.poll_period = QUEUE_WIFI_CTRL_TASK_TIMEOUT;
	ldk_wifi_ctrl_g = &ctrl;

	/* Event sequence */
	push_event(wifi_event_type_hal_ind);
	push_event(wifi_event_type_hal_ind);
	push_event(wifi_event_type_hal_ind);
	push_event(wifi_event_type_webconfig);
	push_event(wifi_event_type_hal_ind);
	push_event(wifi_event_type_hal_ind);

	/* Spin thread */
	pthread_t tid;
	pthread_create(&tid, NULL, ctrl_queue_wrapper, &ctrl);
	while (0x42) {
		pthread_mutex_lock(&ctrl.queue_lock);
		int len = queue_count(ctrl.queue);
		if ((len == 0) && (scheduler_executed == true)) {
			ctrl.exit_ctrl = true;
			pthread_cond_signal(&ctrl.cond);
			pthread_mutex_unlock(&ctrl.queue_lock);
			break;
		}
		pthread_mutex_unlock(&ctrl.queue_lock);
		usleep(100 * 1000);
	}
	pthread_join(tid, NULL);
	return 0;
}
