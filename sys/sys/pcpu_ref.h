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
 *
 * $FreeBSD$
 */

#ifndef __SYS_PCPU_REF_H__
#define __SYS_PCPU_REF_H__

#ifdef _KERNEL
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/counter.h>

#define	PCPU_REF_NOWAIT	0x1

struct pcpu_ref {
	volatile int flags;
	struct mtx *lock;
	counter_s32_t counter;
};
typedef	struct pcpu_ref pcpu_ref_t;

bool	pcpu_ref_alloc(pcpu_ref_t *, struct mtx *, int);
void	pcpu_ref_init(pcpu_ref_t *);
void	pcpu_ref_destroy(pcpu_ref_t *);

bool	pcpu_ref_block(pcpu_ref_t *, int, const char *);
void	pcpu_ref_unblock(pcpu_ref_t *);
bool	pcpu_ref_kill(pcpu_ref_t *r, int, const char *);

int32_t	pcpu_ref_fetch(pcpu_ref_t *);

bool	pcpu_ref_acq(pcpu_ref_t *);
int	pcpu_ref_acq_hard(pcpu_ref_t *, int, int, const char *);
void	pcpu_ref_acq_force(pcpu_ref_t *);
void	pcpu_ref_acq_valid(pcpu_ref_t *);
bool	pcpu_ref_rel(pcpu_ref_t *);
bool	pcpu_ref_rel_locked(pcpu_ref_t *);

#endif	/* _KERNEL */
#endif	/* ! __SYS_PCPU_REF_H__ */
