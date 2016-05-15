/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 *
 * Copyright 2016 Mark Johnston <markj@FreeBSD.org>
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/queue.h>
#include <sys/sdt.h>

#include <sys/dtrace.h>

#include <machine/frame.h>

#include "sdt.h"

#define	AMD64_BP	0xcc
#define	AMD64_NOP	0x90

int
sdt_invop(uintptr_t addr, struct trapframe *frame, uintptr_t rval)
{
	struct sdt_invoprec *rec;

	rec = sdt_lookup_site(addr);
	if (rec == NULL)
		return (0);

#ifdef __amd64__
	dtrace_probe(rec->sr_id, frame->tf_rdi, frame->tf_rsi, frame->tf_rdx,
	    frame->tf_rcx, frame->tf_r8);
#else
	dtrace_probe(rec->sr_id, stack[0], stack[1], stack[2], stack[3],
	    stack[4]);
#endif
	return (DTRACE_INVOP_NOP);
}

static void
sdt_probe_patch(struct sdt_probedesc *desc, uint8_t instr)
{
	struct sdt_probe *probe;
	uint8_t *callsite;

	if (desc->spd_offset == 0) {
		probe = desc->li.spd_probe;
		MPASS(strlen(probe->func) > 0);
		SLIST_FOREACH(desc, &probe->site_list, li.spd_entry) {
			callsite = (uint8_t *)desc->spd_offset;
			callsite[0] = instr;
		}
	} else {
		callsite = (uint8_t *)desc->spd_offset;
		callsite[0] = instr;
	}
}

void
sdt_probe_enable(struct sdt_probedesc *desc)
{

	sdt_probe_patch(desc, AMD64_BP);
}

void
sdt_probe_disable(struct sdt_probedesc *desc)
{

	sdt_probe_patch(desc, AMD64_NOP);
}
