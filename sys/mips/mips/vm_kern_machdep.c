/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2003 Alan L. Cox <alc@cs.rice.edu>
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
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/systm.h>
#include <sys/vmmeter.h>
#include <vm/vm.h>
#include <vm/vm_page.h>
#include <vm/vm_pageout.h>
#include <machine/md_var.h>
#include <machine/vmparam.h>

vm_offset_t
kmem_small_alloc_domain(int domain, int flags)
{
	vm_paddr_t pa;
	vm_page_t m;
	vm_offset_t va;
	int pflags;

	pflags = malloc2vm_flags(flags) | VM_ALLOC_WIRED;
#ifndef __mips_n64
	pflags &= ~(VM_ALLOC_WAITOK | VM_ALLOC_WAITFAIL);
	pflags |= VM_ALLOC_NOWAIT;
#endif

	for (;;) {
		m = vm_page_alloc_freelist_domain(domain, VM_FREELIST_DIRECT,
		    pflags);
#ifndef __mips_n64
		if (m == NULL && vm_page_reclaim_contig(pflags, 1,
		    0, MIPS_KSEG0_LARGEST_PHYS, PAGE_SIZE, 0))
			continue;
#endif
		if (m != NULL)
			break;
		if ((flags & M_NOWAIT) != 0)
			return (NULL);
		vm_wait(NULL);
	}

	pa = VM_PAGE_TO_PHYS(m);
	if ((flags & M_NODUMP) == 0)
		dump_add_page(pa);
	va = MIPS_PHYS_TO_DIRECT(pa);
	if ((flags & M_ZERO) && (m->flags & PG_ZERO) == 0)
		bzero((void *)va, PAGE_SIZE);
	return (va);
}

void
kmem_small_free(vm_offset_t addr)
{
	vm_page_t m;
	vm_paddr_t pa;

	pa = MIPS_DIRECT_TO_PHYS(addr);
	dump_drop_page(pa);
	m = PHYS_TO_VM_PAGE(pa);
	vm_page_unwire_noq(m);
	vm_page_free(m);
}
