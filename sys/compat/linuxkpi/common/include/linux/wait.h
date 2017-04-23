/*-
 * Copyright (c) 2010 Isilon Systems, Inc.
 * Copyright (c) 2010 iX Systems, Inc.
 * Copyright (c) 2010 Panasas, Inc.
 * Copyright (c) 2013, 2014 Mellanox Technologies, Ltd.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice unmodified, this list of conditions, and the following
 *    disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * $FreeBSD$
 */
#ifndef	_LINUX_WAIT_H_
#define	_LINUX_WAIT_H_

#include <linux/compiler.h>
#include <linux/list.h>
#include <linux/jiffies.h>

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/_mutex.h>
#include <sys/proc.h>
#include <sys/sleepqueue.h>

typedef struct {
} wait_queue_t;

typedef struct {
	unsigned int	wchan;
	struct mtx	mtx;
	struct list_head list;
} wait_queue_head_t;

/* XXX should be in .c? */
#define	init_waitqueue_head(wq) do {					\
	INIT_LIST_HEAD(&(wq)->list);					\
	mtx_init(&(wq)->mtx, "lnxwq", NULL, MTX_DEF);			\
} while (0)

extern void	linux_wake_up(wait_queue_head_t *q, bool all);

#define	wake_up(q)				linux_wake_up(q, false)
#define	wake_up_nr(q, nr)			linux_wake_up(q, true)
#define	wake_up_all(q)				linux_wake_up(q, true)
#define	wake_up_interruptible(q)		linux_wake_up(q, false)
#define	wake_up_interruptible_nr(q, nr)		linux_wake_up(q, true)
#define	wake_up_interruptible_all(q, nr)	linux_wake_up(q, true)

extern int	linux_wait_event_common(wait_queue_head_t *q, void *chan,
		    long timeout, bool intr);

#define	__wait_event_common(q, cond, timeout, intr) ({			\
	void *__c;							\
	int __error, __ret;						\
									\
	__c = &(q).wchan;						\
	__ret = 1;							\
	mtx_lock(&(q).mtx);						\
	if (!(cond)) {							\
		for (;;) {						\
			if (SCHEDULER_STOPPED())			\
				break;					\
			sleepq_lock(c);					\
			if (cond) {					\
				sleepq_release(c);			\
				__ret = 1;				\
				break;					\
			}						\
			__error = linux_wait_event_common(&(q), __c,	\
			    timeout, intr);				\
			if (__error != 0) {				\
				if (__error == EWOULDBLOCK)		\
					__ret = (cond);			\
				else					\
					__ret = -ERESTARTSYS;		\
				break;					\
			}						\
		}							\
	}								\
	mtx_unlock(&(q).mtx);						\
	__ret;								\
})

#define	wait_event(q, cond) do {					\
	(void)__wait_event_common(q, cond, 0, false);			\
} while (0)

#define	wait_event_timeout(q, cond, timeout)				\
	__wait_event_common(q, cond, timeout, false)

#define	wait_event_interruptible(q, cond)				\
	__wait_event_common(q, cond, 0, true)

#define	wait_event_interruptible_timeout(q, cond, timeout)		\
	__wait_event_common(q, cond, timeout, true)

static inline int
waitqueue_active(wait_queue_head_t *q)
{
	int ret;

	mtx_lock(&q->mtx);
	ret = !list_empty(&q->list);
	mtx_unlock(&q->mtx);
	return (ret);
}

#define DEFINE_WAIT(name)	\
	wait_queue_t name = {}

static inline void
prepare_to_wait(wait_queue_head_t *q, wait_queue_t *wait, int state)
{
}

static inline void
finish_wait(wait_queue_head_t *q, wait_queue_t *wait)
{
}

#endif	/* _LINUX_WAIT_H_ */
