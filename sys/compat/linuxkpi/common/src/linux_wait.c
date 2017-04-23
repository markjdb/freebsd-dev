/*-
 * Copyright (c) 2017 Mark Johnston <markj@FreeBSD.org>
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
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/file.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/sleepqueue.h>

#include <linux/file.h>
#include <linux/fs.h>
#include <linux/list.h>
#include <linux/jiffies.h>
#include <linux/poll.h>
#include <linux/wait.h>

struct wait_queue_entry {
	struct list_head next;
	struct linux_file *filp;
};

void
linux_poll_wait(struct linux_file *filp, wait_queue_head_t *q, poll_table *p)
{
	struct wait_queue_entry *entry;

	entry = malloc(sizeof(*entry), M_TEMP, M_WAITOK | M_ZERO);

	fhold(filp->_file);

	mtx_lock(&q->mtx);
	entry->filp = filp;
	selrecord(curthread, &filp->f_selinfo);
	list_add(&entry->next, &q->list);
	mtx_unlock(&q->mtx);
}

int
linux_wait_event_common(wait_queue_head_t *q, void *wchan, long timeout,
    bool intr)
{
	int error, flags;

	flags = SLEEPQ_SLEEP | (intr ? SLEEPQ_INTERRUPTIBLE : 0);

	if (timeout != 0)
		sleepq_set_timeout(wchan, linux_timer_jiffies_until(timeout));
	sleepq_add(wchan, &q->mtx.lock_object, "lnxev", flags, 0);
	if (intr) {
		if (timeout != 0)
			error = sleepq_timedwait_sig(wchan, 0);
		else
			error = sleepq_wait_sig(wchan, 0);
	} else {
		if (timeout != 0)
			error = sleepq_timedwait(wchan, 0);
		else {
			error = 0;
			sleepq_wait(wchan, 0);
		}
	}
	return (error);
}

void
linux_wake_up(wait_queue_head_t *q, bool all)
{
	struct linux_file *filp;
	struct list_head *entry, *tmp;
	struct thread *td;
	struct wait_queue_entry *wqe;
	void *wchan;
	int wakeup_swapper;

	td = curthread;

	mtx_lock(&q->mtx);
	wchan = &q->wchan;
	sleepq_lock(wchan);
	if (all)
		wakeup_swapper = sleepq_broadcast(wchan, SLEEPQ_SLEEP, 0, 0);
	else
		wakeup_swapper = sleepq_signal(wchan, SLEEPQ_SLEEP, 0, 0);
	sleepq_release(wchan);
	if (wakeup_swapper)
		kick_proc0();

	list_for_each_safe(entry, tmp, &q->list) {
		wqe = __containerof(entry, struct wait_queue_entry, next);
		filp = wqe->filp;
		if (filp != NULL) {
			selwakeup(&filp->f_selinfo);
			KNOTE(&filp->f_selinfo.si_note, 0, 0);
			fdrop(filp->_file, td);
		}
		list_del(entry);
		free(wqe, M_TEMP);
	}
	mtx_unlock(&q->mtx);
}
