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

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/pmckern.h>
#include <sys/conf.h>
#include <sys/malloc.h>
#include <sys/mman.h>
#include <sys/mutex.h>
#include <sys/rwlock.h>
#include <sys/smp.h>
#include <sys/osd.h>

#include <vm/vm.h>
#include <vm/pmap.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>
#include <vm/vm_pager.h>

#define	PMC_VM_DEBUG
#undef	PMC_VM_DEBUG

#ifdef	PMC_VM_DEBUG
#define	dprintf(fmt, ...)	printf(fmt, ##__VA_ARGS__)
#else
#define	dprintf(fmt, ...)
#endif

#include "hwpmc_vm.h"

struct cdev *pmc_cdev[MAXCPU];

static int
pmc_mmap_single(struct cdev *cdev, vm_ooffset_t *offset,
    vm_size_t mapsize, struct vm_object **objp, int nprot)
{
	struct pmc_vm_map *map;
	struct cdev_cpu *cc;

	cc = cdev->si_drv1;

	if (nprot != PROT_READ || *offset != 0)
		return (ENXIO);

	mtx_lock(&cc->vm_mtx);
	map = osd_thread_get(curthread, cc->osd_id);
	if (map) {
		vm_object_reference(map->obj);
		*objp = map->obj;
		mtx_unlock(&cc->vm_mtx);
		return (0);
	}
	mtx_unlock(&cc->vm_mtx);

	return (ENXIO);
}

static struct cdevsw pmc_cdevsw = {
	.d_version =		D_VERSION,
	.d_mmap_single =	pmc_mmap_single,
	.d_name =		"HWPMC",
};

int
pmc_vm_initialize(struct pmc_mdep *md)
{
	struct make_dev_args args;
	struct cdev_cpu *cc_all;
	struct cdev_cpu *cc;
	int error;
	int cpu;
	int i;

	cc_all = malloc(sizeof(struct cdev_cpu) * (mp_maxid + 1),
	    M_PMC, M_WAITOK | M_ZERO);

	CPU_FOREACH(cpu) {
		cc = &cc_all[cpu];
		cc->cpu = cpu;
		cc->md = md;
		cc->osd_id = osd_thread_register(NULL);

		mtx_init(&cc->vm_mtx, "PMC VM", NULL, MTX_DEF);

		/* Register the device */
		make_dev_args_init(&args);
		args.mda_devsw = &pmc_cdevsw;
		args.mda_unit = cpu;
		args.mda_uid = UID_ROOT;
		args.mda_gid = GID_WHEEL;
		args.mda_mode = 0666;
		args.mda_si_drv1 = cc;
		error = make_dev_s(&args, &pmc_cdev[cpu], "pmc%d", cpu);
		if (error != 0) {
			for (i = 0; i < cpu; i++)
				destroy_dev(pmc_cdev[cpu]);
			return (-1);
		}
	}

	return (0);
}

int
pmc_vm_finalize(void)
{
	struct cdev_cpu *cc_all;
	struct cdev_cpu *cc;
	int cpu;

	cc_all = pmc_cdev[0]->si_drv1;

	CPU_FOREACH(cpu) {
		cc = &cc_all[cpu];
		mtx_destroy(&cc->vm_mtx);
		destroy_dev(pmc_cdev[cpu]);
	}

	free(cc_all, M_PMC);

	return (0);
}
