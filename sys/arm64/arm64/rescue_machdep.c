/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2020 Juniper Networks Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the distribution.
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
#include <sys/bus.h>
#include <sys/conf.h>
#include <sys/cpuset.h>
#include <sys/intr.h>
#include <sys/kernel.h>
#include <sys/kerneldump.h>
#include <sys/linker.h>
#include <sys/msgbuf.h>
#include <sys/pcpu.h>
#include <sys/proc.h>
#include <sys/smp.h>

#include <vm/vm.h>
#include <vm/vm_extern.h>
#include <vm/vm_kern.h>
#include <vm/pmap.h>

#include <machine/machdep.h>
#include <machine/md_var.h>
#include <machine/metadata.h>
#include <machine/pmap.h>
#include <machine/rescue.h>
#include <machine/vmparam.h>

#include <dev/ofw/openfirm.h>
#include <contrib/libfdt/libfdt.h>

int do_rescue_minidump;

/*
 * Parameters for memory reserved for the rescue kernel.  The boundary and
 * alignment are fixed by the requirements of locore.  The size is configurable
 * but of course must be satisfiable by an allocation with the defined alignment
 * and boundary requirements.
 */
#define	RESCUE_RESERV_ALIGN	(2 * 1024 * 1024u)	/* 2MB */
#define	RESCUE_RESERV_BOUNDARY	(1024 * 1024 * 1024u)	/* 1GB */
#define	RESCUE_RESERV_SIZE	(64 * 1024 * 1024u)	/* 64MB */

/*
 * Environment variables beginning with this prefix are copied into the rescue
 * kernel's environment with the prefix stripped.
 */
#define	RESCUE_KENV_PREFIX	"debug.rescue."

static vm_offset_t rescue_va;
static vm_paddr_t rescue_pa;

/*
 * Called from the host kernel to populate rescue dumper parameters.
 * The returned structure is passed to the rescue kernel.
 */
static void
rescue_dump_params_init(struct rescue_dump_params *rdp)
{
	rdp->dp_msgbufpa = vtophys(msgbufp->msg_ptr);
	rdp->dp_msgbufsz = msgbufp->msg_size;
	rdp->dp_vmdumppa = vtophys(vm_page_dump);
	rdp->dp_vmdumpsz = vm_page_dump_size;
	rdp->dp_kernl0pa = vtophys(kernel_pmap->pm_l0);
	rdp->dp_kernstart = VM_MIN_KERNEL_ADDRESS;
	rdp->dp_kernend = kernel_vm_end;
	rdp->dp_kernmax = VM_MAX_KERNEL_ADDRESS;
	rdp->dp_dmapbasepa = DMAP_MIN_PHYSADDR;
	rdp->dp_dmapmin = DMAP_MIN_ADDRESS;
	rdp->dp_dmapmax = DMAP_MAX_ADDRESS;
}

static void
rescue_kernel_cpu_switch(void)
{
	extern struct pcpu __pcpu[];
	struct pcpu *pcpu;

	pcpu = &__pcpu[0];
	if (get_pcpu() != pcpu) {
		CPU_SET_ATOMIC(pcpu->pc_cpuid, &started_cpus);
		for (;;)
			cpu_spinwait();
	}
}

/*
 * Make the final preparations to jump into the rescue kernel, and then do it.
 */
void
rescue_kernel_exec(void)
{
	static pd_entry_t pt_l0[Ln_ENTRIES] __aligned(PAGE_SIZE);
	static pd_entry_t pt_l1[Ln_ENTRIES] __aligned(PAGE_SIZE);
	static pd_entry_t pt_l2[Ln_ENTRIES] __aligned(PAGE_SIZE);
	struct rescue_kernel_params *params;
	void (*rescue)(u_long modulep);
	vm_paddr_t pa;

	/*
	 * Switch to the boot CPU if we are not already on it.
	 */
	rescue_kernel_cpu_switch();

	/*
	 * Acknowledge any active interrupts to avoid leaving the PIC in an
	 * indeterminate state.
	 */
	intr_isrc_reset();

	/*
	 * Prepare the dump parameters structure for the rescue kernel.  The
	 * rest of the parameters must already have been initialized.  These
	 * will be accessed via an aliasing mapping, so make sure the cache is
	 * written back.
	 */
	params = (struct rescue_kernel_params *)rescue_va;
	rescue_dump_params_init(&params->kp_dumpparams);
	cpu_dcache_wb_range((vm_offset_t)params, sizeof(*params));

	/*
	 * Construct an identity map for the rescue kernel's locore.  This
	 * covers the entire reservation.  Because it does not span a 1GB
	 * boundary, only three pages are needed.  This will be replaced by
	 * locore.
	 */
	pt_l0[pmap_l0_index(rescue_pa)] = L0_TABLE | vtophys(pt_l1);
	pt_l1[pmap_l1_index(rescue_pa)] = L1_TABLE | vtophys(pt_l2);
	for (pa = rescue_pa; pa < rescue_pa + RESCUE_RESERV_SIZE; pa += L2_SIZE)
		pt_l2[pmap_l2_index(pa)] = L2_BLOCK | ATTR_DEFAULT |
		    ATTR_IDX(UNCACHED_MEMORY) | pa;

	cpu_setttb(pmap_kextract((vm_offset_t)pt_l0));

	/*
	 * Jump to the entry point.  Currently we pass a dummy module pointer to
	 * ensure that locore maps some memory following the rescue kernel, but
	 * this is really a hack to avoid modifying locore.
	 */
	rescue = (void *)(rescue_pa + RESCUE_RESERV_KERNEL_OFFSET + PAGE_SIZE);
	(rescue)(KERNBASE + RESCUE_RESERV_SIZE);
}

/*
 * Dummy function to satisfy the set_dumper() interface.  This should never be
 * called.
 */
static int
rescue_dumper_dummy(void *priv, void *virtual, vm_offset_t physical,
    off_t offset, size_t length)
{
	printf("%s: unexpected call\n", __func__);
	return (EOPNOTSUPP);
}

static void
rescue_kernel_init(void *arg __unused)
{
	extern u_long __rescue_kernel_start, __rescue_kernel_end;
	struct dumperinfo di;
	struct rescue_kernel_params *params;
	void *dtbp, *fdtp;
	char *envp, *p;
	const uint32_t *addr_cellsp, *size_cellsp;
	uint8_t *buf, *sb;
	caddr_t kmdp;
	size_t dtblen, envlen, kernlen, prefixlen, varlen;
	vm_offset_t off;
	uint32_t addr_cells, size_cells;
	int enabled, error, i, len, memoff, rootoff;

	enabled = 0;
	TUNABLE_INT_FETCH("debug.rescue_minidump", &enabled);
	if (!enabled)
		return;
	if (!do_minidump) {
		printf("rescue: minidumps are not enabled\n");
		return;
	}

	rescue_va = kmem_alloc_contig(RESCUE_RESERV_SIZE, M_WAITOK, 0,
	    ~(vm_paddr_t)0, RESCUE_RESERV_ALIGN, RESCUE_RESERV_BOUNDARY,
	    VM_MEMATTR_DEFAULT);
	if (rescue_va == 0) {
		printf("rescue: failed to reserve contiguous memory\n");
		goto out;
	}
	rescue_pa = pmap_kextract(rescue_va);

	params = (struct rescue_kernel_params *)rescue_va;
	off = round_page(sizeof(*params));

	/*
	 * Copy the DTB into the reserved area.  It would be simpler to copy the
	 * kernel to the base of the reservation and copy the DTB to the space
	 * following the kernel, but we do not know the kernel's full size.
	 * Thus the DTB is copied first and the kernel is copied to the next
	 * 2MB-aligned address.
	 */
	kmdp = preload_search_by_type("elf kernel");
	if (kmdp == NULL)
		kmdp = preload_search_by_type("elf64 kernel");
	dtbp = MD_FETCH(kmdp, MODINFOMD_DTBP, void *);
	dtblen = fdt_totalsize(dtbp);

	fdtp = (void *)(rescue_va + off);
	memcpy(fdtp, dtbp, dtblen);

	params->kp_dtbstart = rescue_pa + off;
	params->kp_dtblen = dtblen;

	/*
	 * Fix up the DTB used by the rescue kernel: update the memory node to
	 * point at reserved memory, and delete the rescue and memreserve nodes.
	 */
	rootoff = fdt_path_offset(fdtp, "/");
	if (rootoff < 0) {
		printf("rescue: failed to look up FDT root offset\n");
		goto out;
	}
	memoff = fdt_path_offset(fdtp, "/memory");
	if (memoff < 0) {
		printf("rescue: failed to look up FDT memory offset\n");
		goto out;
	}
	addr_cellsp = fdt_getprop(fdtp, rootoff, "#address-cells", NULL);
	if (addr_cellsp == NULL) {
		printf("rescue: failed to look up address-cells property\n");
		goto out;
	}
	size_cellsp = fdt_getprop(fdtp, rootoff, "#size-cells", NULL);
	if (addr_cellsp == NULL || size_cellsp == NULL) {
		printf("rescue: failed to look up address-cells property\n");
		goto out;
	}
	addr_cells = fdt32_to_cpu(*addr_cellsp);
	size_cells = fdt32_to_cpu(*size_cellsp);

	len = (addr_cells + size_cells) * sizeof(uint32_t);
	sb = buf = malloc(len, M_TEMP, M_WAITOK | M_ZERO);
	if (addr_cells == 2)
		*(uint64_t *)buf = cpu_to_fdt64(rescue_pa);
	else
		*(uint32_t *)buf = cpu_to_fdt32(rescue_pa);
	buf += addr_cells * sizeof(uint32_t);
	if (size_cells == 2)
		*(uint64_t *)buf = cpu_to_fdt64(RESCUE_RESERV_SIZE);
	else
		*(uint32_t *)buf = cpu_to_fdt32(RESCUE_RESERV_SIZE);
	error = fdt_setprop_inplace(fdtp, memoff, "reg", sb, len);
	if (error != 0) {
		printf("rescue: failed to update reg property: %d\n", error);
		goto out;
	}
	free(sb, M_TEMP);

	/*
	 * Copy select variables from the host kernel's environment to the
	 * rescue kernel's memory following the DTB.
	 */
	off += round_page(dtblen);
	envp = (char *)(rescue_va + off);
	envlen = 0;
	prefixlen = strlen(RESCUE_KENV_PREFIX);
	for (i = 0; kenvp[i] != NULL; i++) {
		p = kenvp[i];
		varlen = strlen(p);
		if (strncmp(p, RESCUE_KENV_PREFIX, prefixlen) == 0) {
			p += prefixlen;
			varlen -= prefixlen;
			memcpy(envp, p, varlen);
			envp += varlen;
			*envp++ = '\0';
			envlen += varlen + 1;
		}
	}
	*envp++ = '\0';
	envlen++;

	params->kp_kenvstart = rescue_pa + off; 
	params->kp_kenvlen = envlen;

	/*
	 * The kernel must be loaded at a 2MB-aligned address.  To simplify
	 * location of the parameter structure, we require that the parameters,
	 * DTB and rescue kernel environment all fit in the first 2MB of the
	 * reservation.
	 */
	if (roundup2(off, L2_SIZE) != RESCUE_RESERV_KERNEL_OFFSET) {
		printf("rescue: DTB (%zd bytes) and kenv are too large\n",
		    dtblen);
		goto out;
	}
	off = L2_SIZE;
	params->kp_kernstart = rescue_pa + off;

	/*
	 * Copy the kernel image.  This must come last since the length does not
	 * include that of allocated sections.
	 */
	kernlen = (u_long)&__rescue_kernel_end - (u_long)&__rescue_kernel_start;
	memcpy((void *)(rescue_va + off), (void *)&__rescue_kernel_start,
	    kernlen);

	cpu_idcache_wbinv_range(rescue_va, RESCUE_RESERV_SIZE);

	/*
	 * Finally tell the generic kernel dump layer that a dump device
	 * exists, so that it calls into rescue_kernel_exec().
	 */
	memset(&di, 0, sizeof(di));
	di.dumper = rescue_dumper_dummy;
	error = set_dumper(&di, "rescue", curthread, KERNELDUMP_COMP_NONE,
	    KERNELDUMP_ENC_NONE, NULL, 0, NULL);
	if (error != 0) {
		printf("rescue: failed to set dump device: %d\n", error);
		goto out;
	}

	do_rescue_minidump = 1;
	printf("rescue: initialized\n");
	return;

out:
	if (rescue_va != 0) {
		kmem_free(rescue_va, RESCUE_RESERV_SIZE);
		rescue_va = 0;
		rescue_pa = 0;
	}
}
SYSINIT(rescue_kernel, SI_SUB_VM_CONF, SI_ORDER_ANY, rescue_kernel_init, NULL);
