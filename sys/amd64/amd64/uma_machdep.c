/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2003 Alan L. Cox <alc@cs.rice.edu>
 * All rights reserved.
 * Copyright (c) 2020 The FreeBSD Foundation
 *
 * Portions of this software were developed by Mark Johnston under
 * sponsorship from the FreeBSD Foundation.
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
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/smp.h>
#include <sys/systm.h>
#include <sys/vmem.h>
#include <sys/vmmeter.h>

#include <vm/vm.h>
#include <vm/vm_param.h>
#include <vm/vm_extern.h>
#include <vm/vm_kern.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>
#include <vm/vm_pageout.h>
#include <vm/vm_phys.h>
#include <vm/vm_pagequeue.h>
#include <vm/uma.h>
#include <vm/uma_int.h>

#include <machine/md_var.h>
#include <machine/vmparam.h>

/* Bootstrap data. */
static bool uma_pcpu_bootstrapped = false;
static vm_offset_t uma_pcpu_bootstrap_addr;
static vm_size_t uma_pcpu_bootstrap_size;

static vmem_t *uma_pcpu_arena;

void *
uma_small_alloc(uma_zone_t zone, vm_size_t bytes, int domain, u_int8_t *flags,
    int wait)
{
	vm_page_t m;
	vm_paddr_t pa;
	void *va;

	*flags = UMA_SLAB_PRIV;
	m = vm_page_alloc_domain(NULL, 0, domain,
	    malloc2vm_flags(wait) | VM_ALLOC_NOOBJ | VM_ALLOC_WIRED);
	if (m == NULL)
		return (NULL);
	pa = m->phys_addr;
	if ((wait & M_NODUMP) == 0)
		dump_add_page(pa);
	va = (void *)PHYS_TO_DMAP(pa);
	if ((wait & M_ZERO) && (m->flags & PG_ZERO) == 0)
		pagezero(va);
	return (va);
}

void
uma_small_free(void *mem, vm_size_t size, u_int8_t flags)
{
	vm_page_t m;
	vm_paddr_t pa;

	pa = DMAP_TO_PHYS((vm_offset_t)mem);
	dump_drop_page(pa);
	m = PHYS_TO_VM_PAGE(pa);
	vm_page_unwire_noq(m);
	vm_page_free(m);
}

void *
uma_pcpu_alloc(uma_zone_t zone, vm_size_t size, int domain, uint8_t *flags,
    int wait)
{
	void *pcpu_offset;
	vm_offset_t addr, pcpu_addr;
	vm_size_t pcpu_size;
	int error, i;

	KASSERT(size == (mp_maxid + 1) * PAGE_SIZE,
	    ("%s: unexpected alloc size %#lx", __func__, size));

	*flags = UMA_SLAB_PRIV;
	pcpu_size = PAGE_SIZE;

	if (!uma_pcpu_bootstrapped) {
		if (uma_pcpu_bootstrap_size == 0)
			panic("%s: ran out of per-CPU pages", __func__);
		addr = uma_pcpu_bootstrap_addr;
		uma_pcpu_bootstrap_addr += pcpu_size;
		uma_pcpu_bootstrap_size -= pcpu_size;
		return ((void *)addr);
	}

	error = vmem_alloc(uma_pcpu_arena, pcpu_size, M_BESTFIT | wait, &addr);
	if (error != 0)
		return (NULL);

	/*
	 * If the address comes from the bootstrap region, it is already backed
	 * by physical memory.  Otherwise we must allocate memory.
	 */
	pcpu_offset = zpcpu_base_to_offset((void *)addr);
	if ((vm_offset_t)pcpu_offset >= VM_PCPU_BOOTSTRAP_SIZE) {
		for (i = 0; i <= mp_maxid; i++) {
			domain = cpuid_to_pcpu[i]->pc_domain;
			pcpu_addr = (vm_offset_t)zpcpu_get_cpu(pcpu_offset, i);
			if (VM_DOMAIN_EMPTY(domain))
				error = kmem_back(kernel_object, pcpu_addr,
				    pcpu_size, wait | M_ZERO);
			else
				error = kmem_back_domain(domain, kernel_object,
				    pcpu_addr, pcpu_size, wait | M_ZERO);
			if (error != KERN_SUCCESS)
				goto fail;
		}
	}
	return ((void *)addr);

fail:
	for (; i > 0; i--) {
		pcpu_addr = (vm_offset_t)zpcpu_get_cpu(pcpu_offset, i - 1);
		kmem_unback(kernel_object, pcpu_addr, pcpu_size);
	}
	vmem_xfree(uma_pcpu_arena, addr, pcpu_size);
	return (NULL);
}

void
uma_pcpu_free(void *mem, vm_size_t size, uint8_t flags)
{
	void *pcpu_offset;
	vm_offset_t pcpu_addr;
	vm_size_t pcpu_size;
	int i;

	KASSERT(uma_pcpu_bootstrapped,
	    ("%s: not bootstrapped", __func__));
	KASSERT(size == (mp_maxid + 1) * PAGE_SIZE,
	    ("%s: unexpected free size %#lx", __func__, size));

	pcpu_offset = zpcpu_base_to_offset(mem);
	pcpu_size = PAGE_SIZE;

	/*
	 * Memory allocated from the bootstrap region remains permanently
	 * allocated.
	 */
	if ((vm_offset_t)pcpu_offset >= VM_PCPU_BOOTSTRAP_SIZE)
		for (i = 0; i <= mp_maxid; i++) {
			pcpu_addr = (vm_offset_t)zpcpu_get_cpu(pcpu_offset, i);
			kmem_unback(kernel_object, pcpu_addr, pcpu_size);
		}

	vmem_free(uma_pcpu_arena, (vm_offset_t)mem, pcpu_size);
}

static int
pcpu_import(void *arg, vmem_size_t size, int flags, vmem_addr_t *addrp)
{
	vm_size_t kvasize, nbpdom;

	nbpdom = (int)(uintptr_t)arg * NBPDR;
	kvasize = nbpdom * vm_ndomains;
	return (vmem_xalloc(kernel_arena, kvasize, VM_PCPU_ALIGN, 0, 0,
	    0, ~(vmem_addr_t)0, M_BESTFIT | flags, addrp));
}

void
uma_pcpu_init1(vm_offset_t addr, vm_size_t size)
{
	uma_pcpu_bootstrap_addr = addr;
	uma_pcpu_bootstrap_size = size;
}

void
uma_pcpu_init2(int n4kpgpcpu, int n2mpgpdom)
{
	vmem_addr_t addr, addr1;
	vmem_size_t pcpu_size;
	int error;

	KASSERT(!smp_started, ("%s: called after SMP is started", __func__));

	pcpu_size = PAGE_SIZE;

	uma_pcpu_arena = vmem_create("UMA pcpu arena", 0, 0, pcpu_size, 0,
	    M_WAITOK);
	vmem_set_import(uma_pcpu_arena, pcpu_import, NULL,
	    (void *)(uintptr_t)n2mpgpdom, ptoa(n4kpgpcpu));

	/*
	 * Add the bootstrap region.  Structures allocated during boot may be
	 * freed, for example if a preloaded module is unloaded, so they are
	 * marked here as allocated.
	 */
	error = vmem_add(uma_pcpu_arena, VM_PCPU_BASE_START, ptoa(n4kpgpcpu),
	    M_WAITOK);
	if (error != 0)
		panic("%s: vmem_add() failed: %d", __func__, error);
	for (addr = VM_PCPU_BASE_START; addr < uma_pcpu_bootstrap_addr;
	    addr += pcpu_size) {
		error = vmem_xalloc(uma_pcpu_arena, pcpu_size, 0, 0, 0,
		    addr, addr + pcpu_size, M_BESTFIT | M_WAITOK, &addr1);
		if (error != 0)
			panic("%s: vmem_xalloc() failed: %d", __func__, error);
	}

	uma_pcpu_bootstrapped = true;
}

vm_size_t
uma_pcpu_bootstrap_used(void)
{
	return (uma_pcpu_bootstrap_addr - VM_PCPU_BASE_START);
}
