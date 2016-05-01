/*-
 * Copyright (c) 2016 Mark Johnston <markj@FreeBSD.org>
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
 * THIS SOFTWARE IS PROVIDED BY AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
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
#include <sys/queue.h>
#include <sys/sdt.h>

#include <machine/cpu.h>

#define	ARM_OPC_B	0xea
#define	ARM_OPC_BL	0xeb

#define	ARM_NOP		0xe1a00000 /* mov r0, r0 */
#define	ARM_MOV_PC_LR	0xe1a0f00e /* mov pc, lr */

/*
 * Defined by sdtstubs.sh at compile-time.
 */
void	_sdt_probe_stub(void);

uint64_t
sdt_md_patch_callsite(struct sdt_probe *probe, uint64_t offset, bool reloc)
{
	uint32_t *callinstr, newinstr;
	uint8_t opcode;

	callinstr = (uint32_t *)(uintptr_t)offset;
	opcode = (*callinstr & 0xff000000) >> 24;
	if (opcode != ARM_OPC_B && opcode != ARM_OPC_BL) {
		printf("sdt: opcode mismatch (0x%x) for %s:::%s@%p\n",
		    opcode, probe->prov->name, probe->name,
		    (void *)(uintptr_t)offset);
		return (0);
	}

	/* XXX check the branch target */
	switch (opcode) {
	case ARM_OPC_B:
		newinstr = ARM_MOV_PC_LR;
		break;
	case ARM_OPC_BL:
		newinstr = ARM_NOP;
		break;
	}

	*callinstr = newinstr;
	icache_sync((vm_offset_t)callinstr, sizeof(*callinstr));
	return (offset);
}
