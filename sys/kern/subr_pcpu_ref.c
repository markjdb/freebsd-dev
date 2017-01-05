/*-
 * Copyright (c) 2016 Mateusz Guzik <mjg@FreeBSD.org>
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
#include <sys/counter.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/sched.h>
#include <sys/smp.h>
#include <sys/sysctl.h>
#include <vm/uma.h>

#include <sys/pcpu_ref.h>

#define	_PCPU_REF_INITIALIZED	0x1
#define	_PCPU_REF_BLOCKED	0x2
#define	_PCPU_REF_DYING		0x4

/* XXXMJG pessimized crap */
#define	smp_mb()	mb()
static void
_pcpu_counter_s32_add(pcpu_ref_t *r, int n)
{

	critical_enter();
	counter_s32_add_protected(r->counter, n);
	critical_exit();
}

static void
_pcpu_counter_s32_dec(pcpu_ref_t *r, int n)
{

	critical_enter();
	counter_s32_dec_protected(r->counter, n);
	critical_exit();
}

static void
_pcpu_ref_consumer_sleep_locked(pcpu_ref_t *r, int priority, const char *wmesg)
{

	mtx_assert(r->lock, MA_OWNED);
	msleep(r->counter, r->lock, priority, wmesg, 0);
}

static void
_pcpu_ref_consumer_wakeup_locked(pcpu_ref_t *r)
{

	mtx_assert(r->lock, MA_OWNED);
	wakeup(r->counter);
}

static void
_pcpu_ref_sleep_locked(pcpu_ref_t *r, int priority, const char *wmesg)
{

	mtx_assert(r->lock, MA_OWNED);
	msleep(r, r->lock, priority, wmesg, 0);
}

static void
_pcpu_ref_wakeup_locked(pcpu_ref_t *r)
{

	mtx_assert(r->lock, MA_OWNED);
	wakeup(r);
}

static void
_pcpu_ref_wakeup(pcpu_ref_t *r)
{

	mtx_lock(r->lock);
	_pcpu_ref_wakeup_locked(r);
	mtx_unlock(r->lock);
}

bool
pcpu_ref_alloc(pcpu_ref_t *r, struct mtx *lock, int flags)
{

	r->flags = 0;
	r->lock = lock;
	r->counter = counter_s32_alloc(flags);
	return (r->counter != NULL);
}

void
pcpu_ref_init(pcpu_ref_t *r)
{

	r->flags = _PCPU_REF_INITIALIZED;
}

void
pcpu_ref_destroy(pcpu_ref_t *r)
{

	MPASS((r->flags & _PCPU_REF_INITIALIZED) != 0);
	MPASS((r->flags & _PCPU_REF_BLOCKED) != 0);
	MPASS((r->flags & _PCPU_REF_DYING) != 0);
	MPASS(counter_s32_fetch(r->counter) == 0);
	r->flags = 0;
	counter_s32_free(r->counter);
}

int32_t
pcpu_ref_fetch(pcpu_ref_t *r)
{

	MPASS((r->flags & _PCPU_REF_INITIALIZED) != 0);
	return (counter_s32_fetch(r->counter));
}

bool
pcpu_ref_block(pcpu_ref_t *r, int priority, const char *wmesg)
{
	int32_t count;
	bool slept = false;

	MPASS((r->flags & _PCPU_REF_INITIALIZED) != 0);
	mtx_assert(r->lock, MA_OWNED);

	atomic_set_int(&r->flags, _PCPU_REF_BLOCKED);

	for (;;) {
		count = counter_s32_fetch(r->counter);
		if (count == 0)
			break;
		if (count < 0)
			panic("%s: invalid count %d ref %p\n", __func__, count, r);
		printf("%s: sleeping due to %p count %d\n", __func__, r, count);
		_pcpu_ref_sleep_locked(r, priority, wmesg);
		slept = true;
	}

	_pcpu_ref_consumer_wakeup_locked(r);

	return (slept);
}

void
pcpu_ref_unblock(pcpu_ref_t *r)
{

	MPASS((r->flags & _PCPU_REF_INITIALIZED) != 0);
	mtx_assert(r->lock, MA_OWNED);
	MPASS((r->flags & _PCPU_REF_DYING) == 0);

	atomic_clear_int(&r->flags, _PCPU_REF_BLOCKED);
	_pcpu_ref_consumer_wakeup_locked(r);
}

bool
pcpu_ref_kill(pcpu_ref_t *r, int priority, const char *wmesg)
{
	int32_t count;
	bool slept = false;

	MPASS((r->flags & _PCPU_REF_INITIALIZED) != 0);
	mtx_assert(r->lock, MA_OWNED);

	atomic_set_int(&r->flags, _PCPU_REF_BLOCKED | _PCPU_REF_DYING);

	for (;;) {
		count = counter_s32_fetch(r->counter);
		if (count == 0)
			break;
		printf("%s: ref %p count %d sleeping\n", __func__, r, count);
		_pcpu_ref_sleep_locked(r, priority, wmesg);
		printf("%s: ref %p woken up\n", __func__, r);
		slept = true;
	}

	_pcpu_ref_consumer_wakeup_locked(r);

	return (slept);
}

int
pcpu_ref_acq_hard(pcpu_ref_t *r, int flags, int priority, const char *wmesg)
{
	int error;

	MPASS((r->flags & _PCPU_REF_INITIALIZED) != 0);
	mtx_assert(r->lock, MA_NOTOWNED);
	MPASS((priority & PDROP) == 0);

	if ((r->flags & _PCPU_REF_BLOCKED) == 0) {
		_pcpu_counter_s32_add(r, 1);
		smp_mb();
		if ((r->flags & _PCPU_REF_BLOCKED) == 0)
			return (0);
		_pcpu_counter_s32_dec(r, 1);
	}

	if ((flags & PCPU_REF_NOWAIT) != 0) {
		_pcpu_ref_wakeup(r);
		return (ENOENT);
	}

	mtx_lock(r->lock);
	_pcpu_ref_wakeup_locked(r);
	for (;;) {
		if ((r->flags & _PCPU_REF_BLOCKED) == 0)
			break;
		if ((r->flags & _PCPU_REF_DYING) != 0) {
			error = ENOENT;
			goto out;
		}
		_pcpu_ref_consumer_sleep_locked(r, priority, wmesg);
	}
	_pcpu_counter_s32_add(r, 1);
	error = 0;
out:
	mtx_unlock(r->lock);
	return (error);
}

bool
pcpu_ref_acq(pcpu_ref_t *r)
{

	MPASS((r->flags & _PCPU_REF_INITIALIZED) != 0);
	mtx_assert(r->lock, MA_NOTOWNED);

	if ((r->flags & _PCPU_REF_BLOCKED) != 0)
		return (false);

	MPASS(r->counter != NULL);
	_pcpu_counter_s32_add(r, 1);
	smp_mb();
	if ((r->flags & _PCPU_REF_BLOCKED) == 0)
		return (true);

	_pcpu_counter_s32_dec(r, 1);
	_pcpu_ref_wakeup(r);
	return (false);
}

void
pcpu_ref_acq_force(pcpu_ref_t *r)
{

	MPASS((r->flags & _PCPU_REF_INITIALIZED) != 0);
	MPASS(r->counter != NULL);
	_pcpu_counter_s32_add(r, 1);
}

void
pcpu_ref_acq_valid(pcpu_ref_t *r)
{

	MPASS((r->flags & _PCPU_REF_INITIALIZED) != 0);
	MPASS((r->flags & _PCPU_REF_BLOCKED) == 0);
	_pcpu_counter_s32_add(r, 1);
}

bool
pcpu_ref_rel(pcpu_ref_t *r)
{

	MPASS((r->flags & _PCPU_REF_INITIALIZED) != 0);
	mtx_assert(r->lock, MA_NOTOWNED);

	_pcpu_counter_s32_dec(r, 1);
	if ((r->flags & _PCPU_REF_BLOCKED) != 0) {
		_pcpu_ref_wakeup(r);
	}
	return (true);
}

bool
pcpu_ref_rel_locked(pcpu_ref_t *r)
{

	MPASS((r->flags & _PCPU_REF_INITIALIZED) != 0);
	mtx_assert(r->lock, MA_OWNED);

	_pcpu_counter_s32_dec(r, 1);
	if ((r->flags & _PCPU_REF_BLOCKED) != 0) {
		_pcpu_ref_wakeup_locked(r);
	}
	return (true);
}
