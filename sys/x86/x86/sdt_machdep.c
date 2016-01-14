/*-
 * Copyright 2015 Mark Johnston <markj@FreeBSD.org>
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

#define	X86_OPC_CALL32	0xe8
#define	X86_OPC_JMP32	0xe9
#define	X86_OPC_NOP	0x90
#define	X86_OPC_RET	0xc3

/*
 * Defined by sdtstubs.sh at compile-time.
 */
void	_sdt_probe_stub(void);

uint64_t
sdt_md_patch_callsite(struct sdt_probe *probe, uint64_t offset, bool reloc)
{
	uintptr_t stubaddr;
	uint32_t target;
	uint8_t *callinstr, opcode;

	callinstr = (uint8_t *)(uintptr_t)(offset - 1);
	opcode = callinstr[0];
	if (opcode != X86_OPC_CALL32 && opcode != X86_OPC_JMP32) {
		printf("sdt: opcode mismatch (0x%x) for %s:::%s@%p\n",
		    callinstr[0], probe->prov->name, probe->name,
		    (void *)(uintptr_t)offset);
		return (0);
	}

	/*
	 * If we've been passed a probe descriptor, verify that the call/jmp
	 * target is in fact the SDT stub. If it's not, something's wrong and
	 * we shouldn't touch anything.
	 */
	stubaddr = (uintptr_t)_sdt_probe_stub;
	memcpy(&target, &callinstr[1], sizeof(target));
	if (!reloc && roundup2(target + (uintptr_t)callinstr, 16) != stubaddr) {
		printf("sdt: offset mismatch: %p vs. %p\n",
		    (void *)roundup2(target + (uintptr_t)callinstr, 16),
		    (void *)stubaddr);
		return (0);
	}

	switch (opcode) {
	case X86_OPC_CALL32:
		callinstr[0] = X86_OPC_NOP;
		/* four-byte NOP */
		callinstr[1] = 0x0f;
		callinstr[2] = 0x1f;
		callinstr[3] = 0x40;
		callinstr[4] = 0x00;
		break;
	case X86_OPC_JMP32:
		/*
		 * The probe site is a tail call, so we need a "ret"
		 * when the probe isn't enabled. We overwrite the second
		 * byte instead of the first: the first byte will be
		 * replaced with a breakpoint when the probe is enabled.
		 */
		callinstr[0] = X86_OPC_NOP;
		callinstr[1] = X86_OPC_RET;
		/* three-byte NOP */
		callinstr[2] = 0x0f;
		callinstr[3] = 0x1f;
		callinstr[4] = 0x00;
		break;
	}
	return ((uint64_t)(uintptr_t)callinstr);
}
