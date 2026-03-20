#include "tcp.h"
#include "tcp_timer.h"
#include "tcp_sock.h"

#include <stdio.h>
#include <unistd.h>
#include <pthread.h>
#include "log.h"

static struct list_head timer_list;
static pthread_mutex_t timer_list_lock = PTHREAD_MUTEX_INITIALIZER;

// scan the timer_list, find the tcp sock which stays for at 2*MSL, release it
void tcp_scan_timer_list()
{
	struct tcp_timer *timer, *tmp;
	struct tcp_sock *tsk;
	
	pthread_mutex_lock(&timer_list_lock);
	
	list_for_each_entry_safe(timer, tmp, &timer_list, list) {
		if (timer->enable && timer->type == 0) {
			timer->timeout -= TCP_TIMER_SCAN_INTERVAL;
			if (timer->timeout <= 0) {
				list_delete_entry(&timer->list);
				timer->enable = 0; 
				tsk = timewait_to_tcp_sock(timer);
				log(DEBUG, "TIME_WAIT timeout, closing connection");
				if (!tsk->parent) {
					tcp_bind_unhash(tsk);
				}
				tcp_set_state(tsk, TCP_CLOSED);
				tcp_unhash(tsk);  // 释放内存
			}
		}
	}
	
	pthread_mutex_unlock(&timer_list_lock);
}

// set the timewait timer of a tcp sock, by adding the timer into timer_list
void tcp_set_timewait_timer(struct tcp_sock *tsk)
{
	pthread_mutex_lock(&timer_list_lock);
	
	tsk->timewait.type = 0;  // TIME_WAIT timer
	tsk->timewait.timeout = TCP_TIMEWAIT_TIMEOUT;  // 2*MSL
	tsk->timewait.enable = 1;
	
	// 添加到定时器列表
	list_add_head(&tsk->timewait.list, &timer_list);
	tsk->ref_cnt += 1;

	pthread_mutex_unlock(&timer_list_lock);
	
	log(DEBUG, "TIME_WAIT timer set for 2*MSL (%d us)", TCP_TIMEWAIT_TIMEOUT);
}

// scan the timer_list periodically by calling tcp_scan_timer_list
void *tcp_timer_thread(void *arg)
{
	init_list_head(&timer_list);
	while (1) {
		usleep(TCP_TIMER_SCAN_INTERVAL);
		tcp_scan_timer_list();
	}

	return NULL;
}