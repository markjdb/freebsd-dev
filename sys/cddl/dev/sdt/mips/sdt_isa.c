/*-
 * Copyright (c) 2016 Ruslan Bukin <br@bsdpad.com>
 * All rights reserved.
 *
 * Portions of this software were developed by SRI International and the
 * University of Cambridge Computer Laboratory under DARPA/AFRL contract
 * FA8750-10-C-0237 ("CTSRD"), as part of the DARPA CRASH research programme.
 *
 * Portions of this software were developed by the University of Cambridge
 * Computer Laboratory as part of the CTSRD Project, with support from the
 * UK Higher Education Innovation Fund (HEIF).
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
#include <sys/queue.h>
#include <sys/sdt.h>

#include <sys/dtrace.h>

#include <machine/frame.h>
#include <machine/cpuregs.h>

#include "sdt.h"

#define	MIPS_NOP	0

int
sdt_invop(uintptr_t addr, struct trapframe *tf, uintptr_t rval)
{
	struct sdt_invoprec *rec;

	rec = sdt_lookup_site(addr);
	if (rec == NULL)
		return (0);

	dtrace_probe(rec->sr_id, tf->a0, tf->a1, tf->a2,
		tf->a3, tf->a4);

	return (DTRACE_INVOP_NOP);
}

static void
sdt_probe_patch(struct sdt_probedesc *desc, uint32_t instr)
{
	struct sdt_probe *probe;
	uint32_t *callsite;

	if (desc->spd_offset == 0) {
		probe = desc->li.spd_probe;
		MPASS(strlen(probe->func) > 0);
		SLIST_FOREACH(desc, &probe->site_list, li.spd_entry) {
			callsite = (uint32_t *)desc->spd_offset;
			callsite[0] = instr;
		}
	} else {
		callsite = (uint32_t *)desc->spd_offset;
		callsite[0] = instr;
	}
}

void
sdt_probe_enable(struct sdt_probedesc *desc __unused)
{

	sdt_probe_patch(desc, MIPS_BREAK_INSTR);
}

void
sdt_probe_disable(struct sdt_probedesc *desc)
{

	sdt_probe_patch(desc, MIPS_NOP);
}
