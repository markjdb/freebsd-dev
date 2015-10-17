/*-
 * Copyright (c) 2014 Gleb Smirnoff <glebius@FreeBSD.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/lock.h>
#include <sys/lwref.h>
#include <sys/malloc.h>
#include <sys/pcpu.h>
#include <sys/proc.h>
#include <sys/sched.h>
#include <sys/smp.h>
#include <sys/sx.h>

#include <machine/frame.h>
#include <machine/pcb.h>

#ifdef __amd64__
CTASSERT(offsetof(struct lwref, lw_counters[0]) == 8);
CTASSERT(offsetof(struct lwref, lw_counters[1]) == 16);
#endif

#define	LWR_LOCK(lwr)	sx_xlock(&lwr->lw_lock)
#define	LWR_UNLOCK(lwr)	sx_xunlock(&lwr->lw_lock)

extern char lwref_acquire_ponr[];

static void	lwref_switch_cpu(void *);

int
lwref_init(lwref_t lwr, int flags)
{

	lwr->lw_counters[0] = counter_u64_alloc(flags);
	lwr->lw_counters[1] = counter_u64_alloc(flags);
	if (lwr->lw_counters[0] == NULL || lwr->lw_counters[1] == NULL) {
		counter_u64_free(lwr->lw_counters[0]);
		counter_u64_free(lwr->lw_counters[1]);
		return (1);
	}
	lwr->lw_idx = 0;
	sx_init(&lwr->lw_lock, "lwref");
	return (0);
}

static void
lwref_fixup_rip(register_t *rip, const char *p)
{

	if (*rip >= (register_t)lwref_acquire &&
	    *rip < (register_t)lwref_acquire_ponr) {
		if (p)
			printf("%s: %p\n", p, (void *)*rip);
		*rip = (register_t)lwref_acquire;
	}
}

static void
lwref_fixup_td(struct thread *td, void *arg __unused)
{

	if (td->td_intr_nesting_level == 0)
		/*
		 * The thread didn't switch in interrupt context, so it couldn't
		 * have been executing an lwref operation.
		 */
		return;

	if (td->td_intr_nesting_level == 1) {
		lwref_fixup_rip(&td->td_intr_frame->tf_rip, __func__);
		return;
	}

	/*
	 * XXX not sure what to do here yet.
	 */
	MPASS(0 == 1);
}

static void
lwref_switch_cpu(void *arg)
{
	struct thread *td;
	lwref_t lwr;

	lwr = arg;

	sched_foreach_on_runq(lwref_fixup_td, NULL);

	td = curthread;
	if (td->td_intr_nesting_level == 0)
		/* We requested the rendezvous, so there's nothing to do. */
		return;

	lwref_fixup_rip(&td->td_intr_frame->tf_rip, __func__);
}

int
lwref_switch(lwref_t lwr)
{
	long idx;

	LWR_LOCK(lwr);

	idx = lwr->lw_idx;
	KASSERT(idx == 0 || idx == 1, ("lwref %p invalid index", lwr));

	lwr->lw_idx = idx ^ 1;
	KASSERT(counter_u64_fetch(lwr->lw_counters[lwr->lw_idx]) == 0,
	    ("non-zero reference on alternate index"));

	smp_rendezvous(smp_no_rendevous_barrier, lwref_switch_cpu,
	    smp_no_rendevous_barrier, lwr);

	while (counter_u64_fetch(lwr->lw_counters[idx]) != 0)
		/* XXX */
		pause("lwref", 1);

	LWR_UNLOCK(lwr);

	return (0);
}
