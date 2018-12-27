/*-
 * Copyright (c) 2018 Ruslan Bukin <br@bsdpad.com>
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

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/pmc.h>
#include <sys/pmckern.h>
#include <sys/systm.h>
#include <sys/ioccom.h>
#include <sys/malloc.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/rwlock.h>
#include <sys/conf.h>
#include <sys/module.h>
#include <sys/mman.h>
#include <sys/proc.h>
#include <sys/vmem.h>
#include <sys/vmmeter.h>
#include <sys/kthread.h>
#include <sys/pmclog.h>
#include <sys/osd.h>

#include <vm/vm.h>
#include <vm/vm_param.h>
#include <vm/vm_extern.h>
#include <vm/vm_kern.h>
#include <vm/vm_page.h>
#include <vm/vm_map.h>
#include <vm/vm_object.h>
#include <vm/vm_pager.h>
#include <vm/vm_phys.h>
#include <vm/vm_radix.h>
#include <vm/pmap.h>

#include <arm64/coresight/coresight.h>

#include <dev/hwpmc/hwpmc_vm.h>

static MALLOC_DEFINE(M_CORESIGHT, "coresight", "CORESIGHT driver");

extern struct cdev *pmc_cdev[MAXCPU];

/*
 * ARM CORESIGHT support.
 *
 * Limitation of hardware:
 * - Scatter-gather operation is broken in hardware on
 *   Qualcomm Snapdragon 410e processor.
 * - None of coresight interconnect devices provides an interrupt line.
 * - Circular-buffer is the only mode of operation for TMC(ETR).
 *
 * I.e. once buffer filled the operation will not be halted,
 * instead the buffer will be overwritten from start and none of
 * interrupt provided.
 */

#define	CORESIGHT_CAPS (PMC_CAP_READ | PMC_CAP_INTERRUPT | PMC_CAP_SYSTEM | PMC_CAP_USER)

#define	PMC_CORESIGHT_DEBUG
#undef	PMC_CORESIGHT_DEBUG

#ifdef	PMC_CORESIGHT_DEBUG
#define	dprintf(fmt, ...)	printf(fmt, ##__VA_ARGS__)
#else
#define	dprintf(fmt, ...)
#endif

struct coresight_descr {
	struct pmc_descr pm_descr;  /* "base class" */
};

static struct coresight_descr coresight_pmcdesc[CORESIGHT_NPMCS] =
{
    {
	.pm_descr =
	{
		.pd_name  = "CORESIGHT",
		.pd_class = PMC_CLASS_CORESIGHT,
		.pd_caps  = CORESIGHT_CAPS,
		.pd_width = 64
	}
    }
};

/*
 * Per-CPU data structure for PTs.
 */

struct coresight_cpu {
	struct pmc_hw			tc_hw;
	uint32_t			l0_eax;
	uint32_t			l0_ebx;
	uint32_t			l0_ecx;
	uint32_t			l1_eax;
	uint32_t			l1_ebx;
	struct pmc			*pm_mmap;
	uint32_t			flags;
#define	FLAG_CORESIGHT_ALLOCATED		(1 << 0)
	struct coresight_event		event;
};

static struct coresight_cpu **coresight_pcpu;

static int
coresight_buffer_allocate(uint32_t cpu,
    struct coresight_buffer *coresight_buf, uint32_t bufsize)
{
	struct pmc_vm_map *map1;
	struct pmc_vm_map *map;
	uint64_t phys_base;
	struct cdev_cpu *cc;
	vm_object_t obj;
	vm_page_t m;
	int npages;

	dprintf("%s\n", __func__);

	cc = pmc_cdev[cpu]->si_drv1;

	obj = vm_pager_allocate(OBJT_PHYS, 0, bufsize,
	    PROT_READ, 0, curthread->td_ucred);

	npages = bufsize / PAGE_SIZE;

	VM_OBJECT_WLOCK(obj);
	m = vm_page_alloc_contig(obj, 0, VM_ALLOC_NOBUSY | VM_ALLOC_ZERO,
	    npages, 0, ~0, PAGE_SIZE, 0, VM_MEMATTR_DEFAULT);
	if (m == NULL) {
		VM_OBJECT_WUNLOCK(obj);
		printf("%s: Can't allocate memory.\n", __func__);
		vm_object_deallocate(obj);
		return (-1);
	}
	phys_base = VM_PAGE_TO_PHYS(m);
	for (; m != NULL; m = vm_page_next(m)) {
		if ((m->flags & PG_ZERO) == 0)
			pmap_zero_page(m);
		m->valid = VM_PAGE_BITS_ALL;
	}
	VM_OBJECT_WUNLOCK(obj);

	map = malloc(sizeof(struct pmc_vm_map), M_CORESIGHT, M_WAITOK | M_ZERO);
	map->t = curthread;
	map->obj = obj;
	map->buf = (void *)coresight_buf;

	mtx_lock(&cc->vm_mtx);
	map1 = osd_thread_get(curthread, cc->osd_id);
	if (map1) {
		/* Already allocated */
		vm_object_deallocate(obj);
		mtx_unlock(&cc->vm_mtx);
		free(map, M_CORESIGHT);
		return (-1);
	}

	osd_thread_set(curthread, cc->osd_id, map);
	mtx_unlock(&cc->vm_mtx);

	coresight_buf->obj = obj;
	coresight_buf->phys_base = phys_base;

	return (0);
}

static int
coresight_buffer_deallocate(uint32_t cpu,
    struct coresight_buffer *coresight_buf)
{
	struct pmc_vm_map *map;
	struct cdev_cpu *cc;

	cc = pmc_cdev[cpu]->si_drv1;

	dprintf("%s\n", __func__);

	mtx_lock(&cc->vm_mtx);
	map = osd_thread_get(curthread, cc->osd_id);
	osd_thread_del(curthread, cc->osd_id);
	vm_object_deallocate(map->obj);
	free(map, M_CORESIGHT);
	mtx_unlock(&cc->vm_mtx);

	return (0);
}

static int
coresight_buffer_prepare(uint32_t cpu, struct pmc *pm,
    const struct pmc_op_pmcallocate *a)
{
	const struct pmc_md_coresight_op_pmcallocate *pm_coresighta;
	struct coresight_cpu *coresight_pc;
	struct pmc_md_coresight_pmc *pm_coresight;
	struct coresight_buffer *coresight_buf;
	uint32_t bufsize;
	enum pmc_mode mode;
	uint32_t phys_lo;
	uint32_t phys_hi;
	int error;
	struct coresight_event *event;

	coresight_pc = coresight_pcpu[cpu];
	event = &coresight_pc->event;

	pm_coresighta = (const struct pmc_md_coresight_op_pmcallocate *)
	    &a->pm_md.pm_coresight;
	pm_coresight = (struct pmc_md_coresight_pmc *)&pm->pm_md;
	coresight_buf = &pm_coresight->coresight_buffers[cpu];

	bufsize = 16 * 1024 * 1024;
	error = coresight_buffer_allocate(cpu, coresight_buf, bufsize);
	if (error != 0) {
		dprintf("%s: can't allocate buffers\n", __func__);
		return (EINVAL);
	}

	phys_lo = coresight_buf->phys_base & 0xffffffff;
	phys_hi = (coresight_buf->phys_base >> 32) & 0xffffffff;
	event->naddr = 0;

	event->etr.started = 0;
	event->etr.low = phys_lo;
	event->etr.high = phys_hi;

	mode = PMC_TO_MODE(pm);
	if (mode == PMC_MODE_ST)
		event->excp_level = 1;
	else if (mode == PMC_MODE_TT)
		event->excp_level = 0;
	else {
		dprintf("%s: unsupported mode %d\n", __func__, mode);
		return (-1);
	}

	event->src = CORESIGHT_ETMV4;
	event->sink = CORESIGHT_TMC;
	coresight_init_event(cpu, event);

	/*
	 * Set a trace ID
	 * TODO: should be delivered from pmctrace
	 */
	event->etm.trace_id = 0x10;
	event->etr.flags = ETR_FLAG_ALLOCATE;

	return (0);
}

static int
coresight_allocate_pmc(int cpu, int ri, struct pmc *pm,
    const struct pmc_op_pmcallocate *a)
{
	struct coresight_cpu *coresight_pc;
	int i;

	coresight_pc = coresight_pcpu[cpu];

	dprintf("%s: curthread %lx, cpu %d (curcpu %d)\n", __func__,
	    (uint64_t)curthread, cpu, PCPU_GET(cpuid));
	dprintf("%s: cpu %d (curcpu %d)\n", __func__,
	    cpu, PCPU_GET(cpuid));

	KASSERT(cpu >= 0 && cpu < pmc_cpu_max(),
	    ("[coresight,%d] illegal CPU value %d", __LINE__, cpu));
	KASSERT(ri >= 0 && ri < CORESIGHT_NPMCS,
	    ("[coresight,%d] illegal row index %d", __LINE__, ri));

	if (a->pm_class != PMC_CLASS_CORESIGHT)
		return (EINVAL);

	if (a->pm_ev != PMC_EV_CORESIGHT_CORESIGHT)
		return (EINVAL);

	if ((pm->pm_caps & CORESIGHT_CAPS) == 0)
		return (EINVAL);

	if ((pm->pm_caps & ~CORESIGHT_CAPS) != 0)
		return (EPERM);

	if (a->pm_mode != PMC_MODE_ST &&
	    a->pm_mode != PMC_MODE_TT)
		return (EINVAL);

	/* Can't allocate multiple ST */
	if (a->pm_mode == PMC_MODE_ST &&
	    coresight_pc->flags & FLAG_CORESIGHT_ALLOCATED) {
		dprintf("error: coresight is already allocated for CPU %d\n",
		    cpu);
		return (EUSERS);
	}

	if (a->pm_mode == PMC_MODE_TT) {
		for (i = 0; i < pmc_cpu_max(); i++)
			if (coresight_buffer_prepare(i, pm, a))
				return (EINVAL);
	} else
		if (coresight_buffer_prepare(cpu, pm, a))
			return (EINVAL);

	if (a->pm_mode == PMC_MODE_ST)
		coresight_pc->flags |= FLAG_CORESIGHT_ALLOCATED;

	return (0);
}

static int
coresight_config_pmc(int cpu, int ri, struct pmc *pm)
{
	struct coresight_cpu *coresight_pc;
	struct pmc_hw *phw;

	dprintf("%s: cpu %d (pm %lx)\n", __func__, cpu, (uint64_t)pm);

	PMCDBG3(MDP,CFG,1, "cpu=%d ri=%d pm=%p", cpu, ri, pm);

	KASSERT(cpu >= 0 && cpu < pmc_cpu_max(),
	    ("[coresight,%d] illegal CPU value %d", __LINE__, cpu));
	KASSERT(ri == 0, ("[coresight,%d] illegal row-index %d", __LINE__, ri));

	coresight_pc = coresight_pcpu[cpu];
	phw = &coresight_pc->tc_hw;

	KASSERT(pm == NULL || phw->phw_pmc == NULL,
	    ("[coresight,%d] pm=%p phw->pm=%p hwpmc not unconfigured", __LINE__,
	    pm, phw->phw_pmc));

	phw->phw_pmc = pm;

	return (0);
}

static int
coresight_describe(int cpu, int ri, struct pmc_info *pi, struct pmc **ppmc)
{
	const struct coresight_descr *pd;
	struct pmc_hw *phw;
	size_t copied;
	int error;

	dprintf("%s\n", __func__);

	KASSERT(cpu >= 0 && cpu < pmc_cpu_max(),
	    ("[coresight,%d] illegal CPU %d", __LINE__, cpu));
	KASSERT(ri == 0, ("[coresight,%d] illegal row-index %d", __LINE__, ri));

	phw = &coresight_pcpu[cpu]->tc_hw;
	pd = &coresight_pmcdesc[ri];

	if ((error = copystr(pd->pm_descr.pd_name, pi->pm_name,
	    PMC_NAME_MAX, &copied)) != 0)
		return (error);

	pi->pm_class = pd->pm_descr.pd_class;

	if (phw->phw_state & PMC_PHW_FLAG_IS_ENABLED) {
		pi->pm_enabled = TRUE;
		*ppmc          = phw->phw_pmc;
	} else {
		pi->pm_enabled = FALSE;
		*ppmc          = NULL;
	}

	return (0);
}

static int
coresight_get_config(int cpu, int ri, struct pmc **ppm)
{
	struct coresight_cpu *coresight_pc;
	struct pmc_hw *phw;

	KASSERT(cpu >= 0 && cpu < pmc_cpu_max(),
	    ("[coresight,%d] illegal CPU %d", __LINE__, cpu));
	KASSERT(ri == 0, ("[coresight,%d] illegal row-index %d", __LINE__, ri));

	coresight_pc = coresight_pcpu[cpu];
	phw = &coresight_pc->tc_hw;

	*ppm = phw->phw_pmc;

	return (0);
}

static int
coresight_pcpu_init(struct pmc_mdep *md, int cpu)
{
	struct pmc_cpu *pc;
	struct coresight_cpu *coresight_pc;
	int ri;

	dprintf("%s: cpu %d\n", __func__, cpu);

	KASSERT(cpu == PCPU_GET(cpuid), ("Init on wrong CPU\n"));

	KASSERT(cpu >= 0 && cpu < pmc_cpu_max(),
	    ("[coresight,%d] illegal cpu %d", __LINE__, cpu));
	KASSERT(coresight_pcpu, ("[coresight,%d] null pcpu", __LINE__));
	KASSERT(coresight_pcpu[cpu] == NULL, ("[coresight,%d] non-null per-cpu",
	    __LINE__));

	coresight_pc = malloc(sizeof(struct coresight_cpu),
	    M_CORESIGHT, M_WAITOK | M_ZERO);
	coresight_pc->tc_hw.phw_state = PMC_PHW_FLAG_IS_ENABLED |
	    PMC_PHW_CPU_TO_STATE(cpu) | PMC_PHW_INDEX_TO_STATE(0) |
	    PMC_PHW_FLAG_IS_SHAREABLE;

	coresight_pcpu[cpu] = coresight_pc;

	ri = md->pmd_classdep[PMC_MDEP_CLASS_INDEX_CORESIGHT].pcd_ri;

	KASSERT(pmc_pcpu, ("[coresight,%d] null generic pcpu", __LINE__));

	pc = pmc_pcpu[cpu];

	KASSERT(pc, ("[coresight,%d] null generic per-cpu", __LINE__));

	pc->pc_hwpmcs[ri] = &coresight_pc->tc_hw;

	return (0);
}

static int
coresight_pcpu_fini(struct pmc_mdep *md, int cpu)
{
	int ri;
	struct pmc_cpu *pc;
	struct coresight_cpu *coresight_pc;

	dprintf("%s: cpu %d\n", __func__, cpu);

	KASSERT(cpu >= 0 && cpu < pmc_cpu_max(),
	    ("[coresight,%d] illegal cpu %d", __LINE__, cpu));
	KASSERT(coresight_pcpu[cpu] != NULL, ("[coresight,%d] null pcpu",
	    __LINE__));

	coresight_pc = coresight_pcpu[cpu];

	free(coresight_pcpu[cpu], M_CORESIGHT);
	coresight_pcpu[cpu] = NULL;

	ri = md->pmd_classdep[PMC_MDEP_CLASS_INDEX_CORESIGHT].pcd_ri;

	pc = pmc_pcpu[cpu];
	pc->pc_hwpmcs[ri] = NULL;

	return (0);
}

static int
coresight_trace_config(int cpu, int ri, struct pmc *pm,
    uint64_t *ranges, uint32_t nranges)
{
	struct coresight_event *event;
	struct coresight_cpu *coresight_pc;
	int i;

	dprintf("%s\n", __func__);

	coresight_pc = coresight_pcpu[cpu];
	event = &coresight_pc->event;

	KASSERT(cpu == PCPU_GET(cpuid), ("Configuring wrong CPU\n"));

	for (i = 0; i < nranges * 2; i++)
		event->addr[i] = ranges[i];

	event->naddr = nranges;

	enum pmc_mode mode;
	mode = PMC_TO_MODE(pm);
	if (mode == PMC_MODE_ST)
		event->excp_level = 1;
	else
		event->excp_level = 0;

	event->src = CORESIGHT_ETMV4;
	event->sink = CORESIGHT_TMC;

	return (0);
}

static int
coresight_read_trace(int cpu, int ri, struct pmc *pm,
    pmc_value_t *vcycle, pmc_value_t *voffset)
{
	struct pmc_md_coresight_pmc *pm_coresight;
	struct coresight_event *event;
	struct coresight_buffer *coresight_buf;
	struct coresight_cpu *coresight_pc;
	uint64_t offset;
	uint64_t cycle;

	dprintf("%s\n", __func__);

	coresight_pc = coresight_pcpu[cpu];
	coresight_pc->pm_mmap = pm;
	event = &coresight_pc->event;

	coresight_read(cpu, event);

	cycle = event->etr.cycle;
	offset = event->etr.offset;

	pm_coresight = (struct pmc_md_coresight_pmc *)&pm->pm_md;
	coresight_buf = &pm_coresight->coresight_buffers[cpu];

	*vcycle = cycle;
	*voffset = offset;

	return (0);
}

static int
coresight_read_pmc(int cpu, int ri, pmc_value_t *v)
{

	dprintf("%s\n", __func__);

	KASSERT(cpu >= 0 && cpu < pmc_cpu_max(),
	    ("[coresight,%d] illegal CPU value %d", __LINE__, cpu));
	KASSERT(ri == 0, ("[coresight,%d] illegal ri %d", __LINE__, ri));

	*v = 0;

	return (0);
}

static int
coresight_release_pmc(int cpu, int ri, struct pmc *pm)
{
	struct pmc_md_coresight_pmc *pm_coresight;
	struct coresight_event *event;
	struct coresight_cpu *coresight_pc;
	enum pmc_mode mode;
	struct pmc_hw *phw;
	int i;

	pm_coresight = (struct pmc_md_coresight_pmc *)&pm->pm_md;
	coresight_pc = coresight_pcpu[cpu];
	event = &coresight_pc->event;

	dprintf("%s: cpu %d (curcpu %d)\n", __func__, cpu, PCPU_GET(cpuid));

	KASSERT(cpu >= 0 && cpu < pmc_cpu_max(),
	    ("[coresight,%d] illegal CPU value %d", __LINE__, cpu));
	KASSERT(ri == 0,
	    ("[coresight,%d] illegal row-index %d", __LINE__, ri));

	phw = &coresight_pcpu[cpu]->tc_hw;
	phw->phw_pmc = NULL;

	KASSERT(phw->phw_pmc == NULL,
	    ("[coresight,%d] PHW pmc %p non-NULL", __LINE__, phw->phw_pmc));

	event->etr.flags = ETR_FLAG_RELEASE;
	coresight_disable(cpu, event);

	mode = PMC_TO_MODE(pm);
	if (mode == PMC_MODE_TT)
		for (i = 0; i < pmc_cpu_max(); i++)
			coresight_buffer_deallocate(i,
			    &pm_coresight->coresight_buffers[i]);
	else
		coresight_buffer_deallocate(cpu,
		    &pm_coresight->coresight_buffers[cpu]);

	if (mode == PMC_MODE_ST)
		coresight_pc->flags &= ~FLAG_CORESIGHT_ALLOCATED;

	return (0);
}

static int
coresight_start_pmc(int cpu, int ri)
{
	struct coresight_event *event;
	struct coresight_cpu *coresight_pc;
	struct pmc_hw *phw;

	dprintf("%s: cpu %d (curcpu %d)\n", __func__, cpu, PCPU_GET(cpuid));

	coresight_pc = coresight_pcpu[cpu];
	event = &coresight_pc->event;
	phw = &coresight_pc->tc_hw;
	if (phw == NULL || phw->phw_pmc == NULL)
		return (-1);

	KASSERT(cpu >= 0 && cpu < pmc_cpu_max(),
	    ("[coresight,%d] illegal CPU value %d", __LINE__, cpu));
	KASSERT(ri == 0, ("[coresight,%d] illegal row-index %d", __LINE__, ri));

	coresight_enable(cpu, event);

	return (0);
}

static int
coresight_stop_pmc(int cpu, int ri)
{
	struct coresight_event *event;
	struct coresight_cpu *coresight_pc;

	dprintf("%s\n", __func__);

	coresight_pc = coresight_pcpu[cpu];
	event = &coresight_pc->event;

	KASSERT(cpu >= 0 && cpu < pmc_cpu_max(),
	    ("[coresight,%d] illegal CPU value %d", __LINE__, cpu));
	KASSERT(ri == 0, ("[coresight,%d] illegal row-index %d", __LINE__, ri));

	coresight_disable(cpu, event);

	return (0);
}

static int
coresight_write_pmc(int cpu, int ri, pmc_value_t v)
{

	dprintf("%s\n", __func__);

	KASSERT(cpu >= 0 && cpu < pmc_cpu_max(),
	    ("[coresight,%d] illegal CPU value %d", __LINE__, cpu));
	KASSERT(ri == 0, ("[coresight,%d] illegal row-index %d", __LINE__, ri));

	return (0);
}

int
pmc_coresight_initialize(struct pmc_mdep *md, int maxcpu)
{
	struct pmc_classdep *pcd;

	dprintf("%s\n", __func__);

	KASSERT(md != NULL, ("[coresight,%d] md is NULL", __LINE__));
	KASSERT(md->pmd_nclass >= 1, ("[coresight,%d] dubious md->nclass %d",
	    __LINE__, md->pmd_nclass));

	coresight_pcpu = malloc(sizeof(struct coresight_cpu *) * maxcpu,
	    M_CORESIGHT, M_WAITOK | M_ZERO);

	pcd = &md->pmd_classdep[PMC_MDEP_CLASS_INDEX_CORESIGHT];

	pcd->pcd_caps	= CORESIGHT_CAPS;
	pcd->pcd_class	= PMC_CLASS_CORESIGHT;
	pcd->pcd_num	= CORESIGHT_NPMCS;
	pcd->pcd_ri	= md->pmd_npmc;
	pcd->pcd_width	= 64;

	pcd->pcd_allocate_pmc = coresight_allocate_pmc;
	pcd->pcd_config_pmc   = coresight_config_pmc;
	pcd->pcd_describe     = coresight_describe;
	pcd->pcd_get_config   = coresight_get_config;
	pcd->pcd_pcpu_init    = coresight_pcpu_init;
	pcd->pcd_pcpu_fini    = coresight_pcpu_fini;
	pcd->pcd_read_pmc     = coresight_read_pmc;
	pcd->pcd_read_trace   = coresight_read_trace;
	pcd->pcd_trace_config = coresight_trace_config;
	pcd->pcd_release_pmc  = coresight_release_pmc;
	pcd->pcd_start_pmc    = coresight_start_pmc;
	pcd->pcd_stop_pmc     = coresight_stop_pmc;
	pcd->pcd_write_pmc    = coresight_write_pmc;

	md->pmd_npmc += CORESIGHT_NPMCS;

	return (0);
}

void
pmc_coresight_finalize(struct pmc_mdep *md)
{

	dprintf("%s\n", __func__);

#ifdef INVARIANTS
	int i, ncpus;

	ncpus = pmc_cpu_max();
	for (i = 0; i < ncpus; i++)
		KASSERT(coresight_pcpu[i] == NULL,
		    ("[coresight,%d] non-null pcpu cpu %d", __LINE__, i));

	KASSERT(md->pmd_classdep[PMC_MDEP_CLASS_INDEX_CORESIGHT].pcd_class ==
	    PMC_CLASS_CORESIGHT, ("[coresight,%d] class mismatch", __LINE__));
#endif

	free(coresight_pcpu, M_CORESIGHT);
	coresight_pcpu = NULL;
}
