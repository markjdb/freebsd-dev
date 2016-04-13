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
 * Portions Copyright 2006-2008 John Birrell jb@freebsd.org
 * Portions Copyright 2016 Mark Johnston <markj@FreeBSD.org>
 */

/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/dtrace.h>
#include <sys/kdb.h>

#include <cddl/dev/dtrace/dtrace_cddl.h>

#include "fbt.h"

#define	FBT_PUSHL_EBP		0x55
#define	FBT_MOVL_ESP_EBP0_V0	0x8b
#define	FBT_MOVL_ESP_EBP1_V0	0xec
#define	FBT_MOVL_ESP_EBP0_V1	0x89
#define	FBT_MOVL_ESP_EBP1_V1	0xe5
#define	FBT_REX_RSP_RBP		0x48

#define	FBT_POPL_EBP		0x5d
#define	FBT_POPQ_RBP		0x5d
#define	FBT_RET			0xc3
#define	FBT_RET_IMM16		0xc2
#define	FBT_LEAVE		0xc9
#define	FBT_JMP_SHORT		0xeb
#define	FBT_JMP_REL32		0xe9
#define	FBT_JMP_ABS		0xff

#ifdef __amd64__
#define	FBT_PATCHVAL		0xcc
#else
#define	FBT_PATCHVAL		0xf0
#endif

#define	FBT_ENTRY	"entry"
#define	FBT_RETURN	"return"

#define	FBT_TRAMPOLINE_ADDR	((uintptr_t)&fbt_tail_ret_trampoline)

static uintptr_t fbt_tail_call_pop(uintptr_t);
static int	fbt_tail_call_push(fbt_probe_t *, uintptr_t);

void
fbt_md_init(void)
{
#ifdef __amd64__
	fbt_probe_t *fbt;
	uintptr_t instr;

	instr = FBT_TRAMPOLINE_ADDR;

	fbt = malloc(sizeof(*fbt), M_FBT, M_WAITOK | M_ZERO);
	fbt->fbtp_patchpoint = (fbt_patchval_t *)instr;
	fbt->fbtp_rval = DTRACE_INVOP_NOP;
	fbt->fbtp_flags = FBTPF_TAIL_RET;

	fbt->fbtp_hashnext = fbt_probetab[FBT_ADDR2NDX(instr)];
	fbt_probetab[FBT_ADDR2NDX(instr)] = fbt;
#endif
}

int
fbt_invop(uintptr_t addr, struct trapframe *frame, uintptr_t rval)
{
	solaris_cpu_t *cpu;
	uintptr_t *stack;
	uintptr_t arg0, arg1, arg2, arg3, arg4, retaddr;
	fbt_probe_t *fbt;

#ifdef __amd64__
	stack = (uintptr_t *)frame->tf_rsp;
	stack = (uintptr_t *)(frame->tf_rsp & ~0xf);
#else
	/* Skip hardware-saved registers. */
	stack = (uintptr_t *)frame->tf_isp + 3;
#endif

	cpu = &solaris_cpu[curcpu];
	fbt = fbt_probetab[FBT_ADDR2NDX(addr)];
	for (; fbt != NULL; fbt = fbt->fbtp_hashnext) {
		if ((uintptr_t)fbt->fbtp_patchpoint != addr)
			continue;
		if ((fbt->fbtp_flags & FBTPF_TAIL_CALL) != 0) {
			/* XXX comment */
			if (fbt_tail_call_push(fbt, stack[1])) {
				/* Update the return address. */
				DTRACE_CPUFLAG_SET(CPU_DTRACE_NOFAULT);
				stack[1] = FBT_TRAMPOLINE_ADDR;
				DTRACE_CPUFLAG_CLEAR(CPU_DTRACE_NOFAULT |
				    CPU_DTRACE_BADADDR);
			}
		} else if ((fbt->fbtp_flags & FBTPF_TAIL_RET) != 0) {
			frame->tf_rip = fbt_tail_call_pop(rval);
			return (DTRACE_INVOP_NOP);
		} else if (fbt->fbtp_roffset == 0) {
#ifdef __amd64__
			DTRACE_CPUFLAG_SET(CPU_DTRACE_NOFAULT);
			cpu->cpu_dtrace_caller = stack[0];
			DTRACE_CPUFLAG_CLEAR(CPU_DTRACE_NOFAULT |
			    CPU_DTRACE_BADADDR);

			arg0 = frame->tf_rdi;
			arg1 = frame->tf_rsi;
			arg2 = frame->tf_rdx;
			arg3 = frame->tf_rcx;
			arg4 = frame->tf_r8;
#else
			int i = 0;

			/*
			 * When accessing the arguments on the stack,
			 * we must protect against accessing beyond
			 * the stack.  We can safely set NOFAULT here
			 * -- we know that interrupts are already
			 * disabled.
			 */
			DTRACE_CPUFLAG_SET(CPU_DTRACE_NOFAULT);
			cpu->cpu_dtrace_caller = stack[i++];
			arg0 = stack[i++];
			arg1 = stack[i++];
			arg2 = stack[i++];
			arg3 = stack[i++];
			arg4 = stack[i++];
			DTRACE_CPUFLAG_CLEAR(CPU_DTRACE_NOFAULT |
			    CPU_DTRACE_BADADDR);
#endif

			dtrace_probe(fbt->fbtp_id, arg0, arg1, arg2, arg3,
			    arg4);
			cpu->cpu_dtrace_caller = 0;
		} else {
#ifdef __amd64__
			/*
			 * On amd64, we instrument the ret, not the
			 * leave.  We therefore need to set the caller
			 * to assure that the top frame of a stack()
			 * action is correct.
			 */
			DTRACE_CPUFLAG_SET(CPU_DTRACE_NOFAULT);
			cpu->cpu_dtrace_caller = stack[0];
			DTRACE_CPUFLAG_CLEAR(CPU_DTRACE_NOFAULT |
			    CPU_DTRACE_BADADDR);
#endif

			dtrace_probe(fbt->fbtp_id, fbt->fbtp_roffset,
			    rval, 0, 0, 0);
			cpu->cpu_dtrace_caller = 0;
		}

		return (fbt->fbtp_rval);
	}

	return (0);
}

void
fbt_patch_tracepoint(fbt_probe_t *fbt, fbt_patchval_t val)
{

	*fbt->fbtp_patchpoint = val;
}

int
fbt_provide_module_function(linker_file_t lf, int symindx,
    linker_symval_t *symval, void *opaque)
{
	char *modname = opaque;
	const char *name = symval->name;
	fbt_probe_t *fbt, *retfbt;
	uint8_t *instr, *limit;
	int j, size;
	uint8_t flags, next;

	if ((strncmp(name, "dtrace_", 7) == 0 &&
	    strncmp(name, "dtrace_safe_", 12) != 0) ||
	    strcmp(name, "trap_check") == 0) {
		/*
		 * Anything beginning with "dtrace_" may be called
		 * from probe context unless it explicitly indicates
		 * that it won't be called from probe context by
		 * using the prefix "dtrace_safe_".
		 *
		 * Additionally, we avoid instrumenting trap_check() to avoid
		 * the possibility of generating a fault in probe context before
		 * DTrace's fault handler is called.
		 */
		return (0);
	}

	if (name[0] == '_' && name[1] == '_')
		return (0);

	flags = 0;
	size = symval->size;

	instr = (uint8_t *) symval->value;
	limit = (uint8_t *) symval->value + symval->size;

#ifdef __amd64__
	while (instr < limit) {
		if (*instr == FBT_PUSHL_EBP)
			break;

		if ((size = dtrace_instr_size(instr)) <= 0)
			break;

		instr += size;
	}

	if (instr >= limit || *instr != FBT_PUSHL_EBP) {
		/*
		 * We either don't save the frame pointer in this
		 * function, or we ran into some disassembly
		 * screw-up.  Either way, we bail.
		 */
		return (0);
	}
#else
	if (instr[0] != FBT_PUSHL_EBP)
		return (0);

	if (!(instr[1] == FBT_MOVL_ESP_EBP0_V0 &&
	    instr[2] == FBT_MOVL_ESP_EBP1_V0) &&
	    !(instr[1] == FBT_MOVL_ESP_EBP0_V1 &&
	    instr[2] == FBT_MOVL_ESP_EBP1_V1))
		return (0);
#endif

	fbt = malloc(sizeof (fbt_probe_t), M_FBT, M_WAITOK | M_ZERO);
	fbt->fbtp_name = name;
	fbt->fbtp_id = dtrace_probe_create(fbt_id, modname,
	    name, FBT_ENTRY, 3, fbt);
	fbt->fbtp_patchpoint = instr;
	fbt->fbtp_ctl = lf;
	fbt->fbtp_loadcnt = lf->loadcnt;
	fbt->fbtp_rval = DTRACE_INVOP_PUSHL_EBP;
	fbt->fbtp_savedval = *instr;
	fbt->fbtp_patchval = FBT_PATCHVAL;
	fbt->fbtp_symindx = symindx;

	fbt->fbtp_hashnext = fbt_probetab[FBT_ADDR2NDX(instr)];
	fbt_probetab[FBT_ADDR2NDX(instr)] = fbt;

	lf->fbt_nentries++;

	retfbt = NULL;
again:
	if (instr >= limit)
		return (0);

	/*
	 * If this disassembly fails, then we've likely walked off into
	 * a jump table or some other unsuitable area.  Bail out of the
	 * disassembly now.
	 */
	if ((size = dtrace_instr_size(instr)) <= 0)
		return (0);

#ifdef __amd64__
	/*
	 * A pop of the frame pointer should be followed by a ret or an
	 * unconditional jmp depending on whether it's part of a normal return
	 * or a tail call respectively.
	 */
	if (*instr == FBT_POPQ_RBP && instr + 1 < limit) {
		next = *(instr + 1);
		if (next == FBT_JMP_SHORT ||
		    next == FBT_JMP_REL32 ||
		    next == FBT_JMP_ABS) {
			/* Make sure we can actually disassemble the jmp. */
			if (dtrace_instr_size(instr) <= 0)
				return (0);
			flags |= FBTPF_TAIL_CALL;
			goto found;
		}

		instr += size;
		goto again;
	}

	/*
	 * We only instrument "ret" on amd64 -- we don't yet instrument
	 * ret imm16, largely because the compiler doesn't seem to
	 * (yet) emit them in the kernel...
	 */
	if (*instr == FBT_RET_IMM16)
		printf("fbt: skipping ret immediate instruction\n");
	if (*instr != FBT_RET) {
		instr += size;
		goto again;
	}
#else
	if (!(size == 1 &&
	    (*instr == FBT_POPL_EBP || *instr == FBT_LEAVE) &&
	    (*(instr + 1) == FBT_RET ||
	    *(instr + 1) == FBT_RET_IMM16))) {
		instr += size;
		goto again;
	}
#endif

found:
	/*
	 * We (desperately) want to avoid erroneously instrumenting a
	 * jump table, especially given that our markers are pretty
	 * short:  two bytes on x86, and just one byte on amd64.  To
	 * determine if we're looking at a true instruction sequence
	 * or an inline jump table that happens to contain the same
	 * byte sequences, we resort to some heuristic sleeze:  we
	 * treat this instruction as being contained within a pointer,
	 * and see if that pointer points to within the body of the
	 * function.  If it does, we refuse to instrument it.
	 */
	for (j = 0; j < sizeof (uintptr_t); j++) {
		caddr_t check = (caddr_t) instr - j;
		uint8_t *ptr;

		if (check < symval->value)
			break;

		if (check + sizeof (caddr_t) > (caddr_t)limit)
			continue;

		ptr = *(uint8_t **)check;

		if (ptr >= (uint8_t *) symval->value && ptr < limit) {
			instr += size;
			goto again;
		}
	}

	/*
	 * We have a winner!
	 */
	fbt = malloc(sizeof (fbt_probe_t), M_FBT, M_WAITOK | M_ZERO);
	fbt->fbtp_name = name;

	if (retfbt == NULL) {
		fbt->fbtp_id = dtrace_probe_create(fbt_id, modname,
		    name, FBT_RETURN, 3, fbt);
	} else {
		retfbt->fbtp_next = fbt;
		fbt->fbtp_id = retfbt->fbtp_id;
	}

	retfbt = fbt;
	fbt->fbtp_flags = flags;
	fbt->fbtp_patchpoint = instr;
	fbt->fbtp_ctl = lf;
	fbt->fbtp_loadcnt = lf->loadcnt;
	fbt->fbtp_symindx = symindx;

#ifdef __i386__
	if (*instr == FBT_POPL_EBP) {
		fbt->fbtp_rval = DTRACE_INVOP_POPL_EBP;
	} else {
		ASSERT(*instr == FBT_LEAVE);
		fbt->fbtp_rval = DTRACE_INVOP_LEAVE;
	}
	fbt->fbtp_roffset =
	    (uintptr_t)(instr - (uint8_t *) symval->value) + 1;
#else
	if (*instr == FBT_POPQ_RBP) {
		fbt->fbtp_rval = DTRACE_INVOP_POPQ_RBP;
	} else {
		ASSERT(*instr == FBT_RET);
		fbt->fbtp_rval = DTRACE_INVOP_RET;
	}
	fbt->fbtp_roffset =
	    (uintptr_t)(instr - (uint8_t *) symval->value);
#endif

	fbt->fbtp_savedval = *instr;
	fbt->fbtp_patchval = FBT_PATCHVAL;
	fbt->fbtp_hashnext = fbt_probetab[FBT_ADDR2NDX(instr)];
	fbt_probetab[FBT_ADDR2NDX(instr)] = fbt;

	lf->fbt_nentries++;

	instr += size;
	goto again;
}

static uintptr_t
fbt_tail_call_pop(uintptr_t rval)
{
	fbt_probe_t *fbt;
	struct thread *td;
	int si;
	uint8_t map;

	td = curthread;
	si = --td->td_dtrace->td_fbt_stack_head;
	map = td->td_dtrace->td_fbt_stack_map;

	MPASS(si >= 0 && si < nitems(td->td_dtrace->td_fbt_stack));
	MPASS((map & (1 << si)) == 0);

	do {
		fbt = td->td_dtrace->td_fbt_stack[si].td_stack_arg;
		dtrace_probe(fbt->fbtp_id, fbt->fbtp_roffset, rval, 0, 0, 0);
	} while ((map & (1 << --si)) == 0);

	MPASS(si >= 0 && si < nitems(td->td_dtrace->td_fbt_stack));
	MPASS((map & (1 << si)) != 0);

	td->td_dtrace->td_fbt_stack_map &= ~(1 << si);
	td->td_dtrace->td_fbt_stack_head = si;
	return (td->td_dtrace->td_fbt_stack[si].td_stack_retaddr);
}

static int
fbt_tail_call_push(fbt_probe_t *fbt, uintptr_t retaddr)
{
	struct thread *td;
	int si;

	td = curthread;
	si = td->td_dtrace->td_fbt_stack_head;
	if (retaddr != FBT_TRAMPOLINE_ADDR) {
		if (si >= nitems(td->td_dtrace->td_fbt_stack) - 1)
			/* XXX flag */
			return (0);
		td->td_dtrace->td_fbt_stack[si].td_stack_retaddr = retaddr;
		td->td_dtrace->td_fbt_stack_map |= (1 << si);
		si++;
	} else if (si >= nitems(td->td_dtrace->td_fbt_stack))
		/* XXX flag */
		return (0);
	td->td_dtrace->td_fbt_stack[si].td_stack_arg = fbt;
	td->td_dtrace->td_fbt_stack_head = ++si;
	return (1);
}
