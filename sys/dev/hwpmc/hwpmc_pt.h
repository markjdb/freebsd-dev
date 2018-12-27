/*-
 * Copyright (c) 2017 Ruslan Bukin <br@bsdpad.com>
 * All rights reserved.
 *
 * This software was developed by BAE Systems, the University of Cambridge
 * Computer Laboratory, and Memorial University under DARPA/AFRL contract
 * FA8650-15-C-7558 ("CADETS"), as part of the DARPA Transparent Computing
 * (TC) research program.
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

#ifndef _DEV_HWPMC_PT_H_
#define _DEV_HWPMC_PT_H_

#include <sys/types.h>
#include <sys/malloc.h>
#include <vm/vm.h>

#include <machine/frame.h>

#define	PT_CPUID	0x14
#define	PT_NADDR	4
#define	PT_NPMCS	1

struct pmc_md_pt_op_pmcallocate {
	uint32_t		flags;
#define	INTEL_PT_FLAG_BRANCHES	(1 << 0)
#define	INTEL_PT_FLAG_TSC	(1 << 1)
#define	INTEL_PT_FLAG_MTC	(1 << 2)
#define	INTEL_PT_FLAG_DISRETC	(1 << 3)
	uint64_t		ranges[2 * PT_NADDR];
	int			nranges;
};

#ifdef	_KERNEL
struct xsave_header {
	uint64_t	xsave_bv;
	uint64_t	xcomp_bv;
	uint8_t		reserved[48];
};

struct pt_ext_area {
	uint64_t	rtit_ctl;
	uint64_t	rtit_output_base;
	uint64_t	rtit_output_mask_ptrs;
	uint64_t	rtit_status;
	uint64_t	rtit_cr3_match;
	uint64_t	rtit_addr0_a;
	uint64_t	rtit_addr0_b;
	uint64_t	rtit_addr1_a;
	uint64_t	rtit_addr1_b;
};

struct pt_save_area {
	uint8_t			legacy_state[512];
	struct xsave_header	header;
	struct pt_ext_area	pt_ext_area;
} __aligned(64);

struct topa_entry {
	uint64_t base;
	uint64_t size;
	uint64_t offset;
};

struct pt_buffer {
	uint64_t		*topa_hw;
	struct topa_entry	*topa_sw;
	uint64_t		cycle;
	vm_object_t		obj;
};

/* MD extension for 'struct pmc' */
struct pmc_md_pt_pmc {
	struct pt_buffer	pt_buffers[MAXCPU];
};

/*
 * Prototypes.
 */

int	pmc_pt_initialize(struct pmc_mdep *_md, int _maxcpu);
void	pmc_pt_finalize(struct pmc_mdep *_md);
int	pmc_pt_intr(int cpu, struct trapframe *tf);

#endif /* !_KERNEL */
#endif /* !_DEV_HWPMC_PT_H */
