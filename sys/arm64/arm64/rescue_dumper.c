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
#include <sys/conf.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/sysctl.h>
#include <sys/uio.h>

#include <vm/vm.h>
#include <vm/vm_extern.h>
#include <vm/pmap.h>

#include <machine/minidump.h>
#include <machine/pmap.h>
#include <machine/pte.h>
#include <machine/rescue.h>

enum dump_segs {
	DUMP_SEG_MDHDR = 0,	/* minidump header */
	DUMP_SEG_MSGBUF,	/* kernel message buffer */
	DUMP_SEG_BITMAP,	/* vm_page_dump array */
	DUMP_SEG_PTPS,		/* kernel page table pages */
	DUMP_SEG_PAGES,		/* pages marked in vm_page_dump */
	DUMP_SEG_COUNT,
};

struct dump_seg {
	vm_offset_t	ds_addr;
	vm_size_t	ds_sz;
};

struct dump_softc {
	struct minidumphdr	*sc_mdhdr;
	struct dump_seg		sc_segs[DUMP_SEG_COUNT];
	vm_offset_t		sc_kernl0;
	vm_offset_t		sc_scratchkva;
	char			*sc_scratchbuf;
	u_long			sc_npages;
	off_t			sc_cursor;
};

FEATURE(rescue, "rescue kernel dumper");

static MALLOC_DEFINE(M_DUMPER, "dumper", "Rescue dumper structures");

static struct rescue_dump_params params;

void
rescue_dumper_init(struct rescue_dump_params *p)
{
	memcpy(&params, p, sizeof(params));
}

static void
dump_seg_init(struct dump_seg *seg, vm_offset_t addr, vm_size_t sz)
{
	seg->ds_addr = addr;
	seg->ds_sz = sz;
}

static vm_offset_t
map_host_seg(vm_paddr_t pa, vm_size_t size)
{
	vm_offset_t va;

	va = kva_alloc(size);
	if (va != 0)
		pmap_kenter(va, size, pa, CACHED_MEMORY);
	return (va);
}

static void
unmap_host_seg(vm_offset_t va, vm_size_t size)
{
	vm_size_t off;

	for (off = 0; off < size; off += PAGE_SIZE)
		pmap_kremove(va + off);
	kva_free(va, size);
}

static void
dumper_cdevpriv_dtr(void *arg)
{
	struct dump_softc *sc;
	struct dump_seg *seg;

	sc = arg;

	free(sc->sc_scratchbuf, M_DUMPER);
	if (sc->sc_scratchkva != 0) {
		//pmap_kremove(sc->sc_scratchkva);
		kva_free(sc->sc_scratchkva, PAGE_SIZE);
	}
	if (sc->sc_kernl0 != 0)
		unmap_host_seg(sc->sc_kernl0, PAGE_SIZE);

	seg = &sc->sc_segs[DUMP_SEG_BITMAP];
	if (seg->ds_addr != 0)
		unmap_host_seg(seg->ds_addr, seg->ds_sz);
	seg = &sc->sc_segs[DUMP_SEG_MSGBUF];
	if (seg->ds_addr != 0)
		unmap_host_seg(seg->ds_addr, seg->ds_sz);

	free(sc->sc_mdhdr, M_DUMPER);
	free(sc, M_DUMPER);
}

CTASSERT(sizeof(struct minidumphdr) <= PAGE_SIZE);

static int
dumper_open(struct cdev *dev, int flags, int fmt, struct thread *td)
{
	struct dump_softc *sc;
	struct minidumphdr *mdhdr;
	uint64_t *bitmap;
	vm_offset_t va;
	u_long i;
	int error;

	sc = malloc(sizeof(*sc), M_DUMPER, M_WAITOK | M_ZERO);

	/*
	 * The minidump header gets padded out to a full page.
	 */
	mdhdr = malloc(PAGE_SIZE, M_DUMPER, M_WAITOK | M_ZERO);
	(void)strcpy(mdhdr->magic, MINIDUMP_MAGIC);
	mdhdr->version = MINIDUMP_VERSION;
	mdhdr->msgbufsize = round_page(params.dp_msgbufsz);
	mdhdr->bitmapsize = round_page(params.dp_vmdumpsz);
	mdhdr->pmapsize = howmany(params.dp_kernend - params.dp_kernstart,
	    L2_SIZE) * PAGE_SIZE;
	mdhdr->kernbase = params.dp_kernstart;
	mdhdr->dmapphys = params.dp_dmapbasepa;
	mdhdr->dmapbase = params.dp_dmapmin;
	mdhdr->dmapend = params.dp_dmapmax;
	sc->sc_mdhdr = mdhdr;

	dump_seg_init(&sc->sc_segs[DUMP_SEG_MDHDR], (vm_offset_t)mdhdr,
	    PAGE_SIZE);

	/*
	 * Map the root kernel page table page.  It is not included in the dump,
	 * but is needed in order to walk the page tables so it might as well be
	 * statically mapped.
	 *
	 * Also allocate a page of KVA to map the rest of the kernel page table
	 * pages during walks.
	 */
	sc->sc_kernl0 = map_host_seg(params.dp_kernl0pa, PAGE_SIZE);
	if (sc->sc_kernl0 == 0) {
		error = ENOMEM;
		goto err;
	}
	sc->sc_scratchkva = kva_alloc(PAGE_SIZE);
	if (sc->sc_scratchkva == 0) {
		error = ENOMEM;
		goto err;
	}

	/*
	 * In some cases it is necessary to synthesize a fake page table page.
	 */
	sc->sc_scratchbuf = malloc(PAGE_SIZE, M_DUMPER, M_WAITOK | M_ZERO);

	/*
	 * Map segments of the host kernel that get included in the minidump.
	 */
	va = map_host_seg(params.dp_msgbufpa, mdhdr->msgbufsize);
	if (va == 0) {
		error = ENOMEM;
		goto err;
	}
	dump_seg_init(&sc->sc_segs[DUMP_SEG_MSGBUF], va, mdhdr->msgbufsize);

	va = map_host_seg(params.dp_vmdumppa, mdhdr->bitmapsize);
	if (va == 0) {
		error = ENOMEM;
		goto err;
	}
	dump_seg_init(&sc->sc_segs[DUMP_SEG_BITMAP], va, mdhdr->bitmapsize);

	/*
	 * Create a virtual dump segment for the kernel page tables and marked
	 * host pages.
	 */
	dump_seg_init(&sc->sc_segs[DUMP_SEG_PTPS], 0, mdhdr->pmapsize);

	sc->sc_npages = 0;
	bitmap = (uint64_t *)sc->sc_segs[DUMP_SEG_BITMAP].ds_addr;
	for (i = 0; i < mdhdr->bitmapsize / sizeof(uint64_t); i++)
		sc->sc_npages += bitcount64(bitmap[i]);
	dump_seg_init(&sc->sc_segs[DUMP_SEG_PAGES], 0,
	    sc->sc_npages * PAGE_SIZE);

	error = devfs_set_cdevpriv(sc, dumper_cdevpriv_dtr);
	if (error != 0)
		goto err;

	return (0);

err:
	dumper_cdevpriv_dtr(sc);
	return (error);
}

/*
 * Map a host page directory page.
 */
static pd_entry_t *
map_pde(struct dump_softc *sc, pd_entry_t pde)
{
	vm_offset_t scratch;

	scratch = sc->sc_scratchkva;
	pmap_kenter(scratch, PAGE_SIZE, pde & ~ATTR_MASK, CACHED_MEMORY);
	return ((pd_entry_t *)scratch);
}

/*
 * Return a host page table page mapping the specified virtual address.
 */
static void *
map_ptp(struct dump_softc *sc, vm_offset_t va)
{
	pd_entry_t *l0, *l1, *l2, *l3;
	vm_paddr_t pa;
	int i;

	KASSERT((va & L2_OFFSET) == 0, ("%s: unaligned VA %#lx", __func__, va));

	l0 = (pd_entry_t *)sc->sc_kernl0 + pmap_l0_index(va);
	if ((*l0 & ATTR_DESCR_MASK) != L0_TABLE) {
		/* Invalid entry, return a zero-filled page. */
		memset(sc->sc_scratchbuf, 0, PAGE_SIZE);
		return (sc->sc_scratchbuf);
	}

	l1 = map_pde(sc, *l0);
	l1 = &l1[pmap_l1_index(va)];
	if ((*l1 & ATTR_DESCR_MASK) == L1_BLOCK) {
		/* Dump a 1GB mapping using a fake PTP. */
		pa = (*l1 & ~ATTR_MASK) | (va & L1_OFFSET);
		l3 = (pd_entry_t *)sc->sc_scratchbuf;
		for (i = 0; i < Ln_ENTRIES; i++)
			l3[i] = pa + (i * PAGE_SIZE) | ATTR_DEFAULT | L3_PAGE;
		return (l3);
	}
	if ((*l1 & ATTR_DESCR_MASK) != L1_TABLE) {
		/* Invalid entry, return a zero-filled page. */
		memset(sc->sc_scratchbuf, 0, PAGE_SIZE);
		return (sc->sc_scratchbuf);
	}

	l2 = map_pde(sc, *l1);
	l2 = &l2[pmap_l2_index(va)];
	if ((*l2 & ATTR_DESCR_MASK) == L2_BLOCK) {
		/* Dump a 2MB mapping using a fake PTP. */
		pa = *l2 & ~ATTR_MASK;
		l3 = (pd_entry_t *)sc->sc_scratchbuf;
		for (i = 0; i < Ln_ENTRIES; i++)
			l3[i] = pa + (i * PAGE_SIZE) | ATTR_DEFAULT | L3_PAGE;
		return (l3);
	}
	if ((*l2 & ATTR_DESCR_MASK) != L2_TABLE)  {
		/* Invalid entry, return a zero-filled page. */
		memset(sc->sc_scratchbuf, 0, PAGE_SIZE);
		return (sc->sc_scratchbuf);
	}

	/* Dump the leaf page table page. */
	l3 = map_pde(sc, *l2);
	return (l3);
}

static int
dumper_read_seg(struct dump_softc *sc, enum dump_segs idx, struct dump_seg *seg,
    off_t baseoff, struct uio *uio)
{
	uint64_t bit, bitcount, bits, *bitmap;
	char *ptp;
	vm_offset_t va;
	vm_paddr_t pa;
	off_t off, off1;
	u_long i;
	uint32_t bitmapsize;
	int error;

	KASSERT(baseoff <= uio->uio_offset &&
	    baseoff + seg->ds_sz > uio->uio_offset,
	    ("%s: invalid offset %#lx into seg at %#lx-%#lx", __func__,
	    uio->uio_offset, baseoff, baseoff + seg->ds_sz));

	error = 0;
	off = uio->uio_offset - baseoff;
	switch (idx) {
	case DUMP_SEG_MDHDR:
	case DUMP_SEG_MSGBUF:
	case DUMP_SEG_BITMAP:
		/* Linear segments can simply be copied. */
		error = uiomove((char *)seg->ds_addr + off, seg->ds_sz - off,
		    uio);
		break;
	case DUMP_SEG_PTPS:
		/* Dump leaf page table pages. */
		for (va = params.dp_kernstart + (off / PAGE_SIZE) * L2_SIZE;
		    va < params.dp_kernend; va += L2_SIZE) {
			ptp = map_ptp(sc, va);
			error = uiomove(ptp + (off & PAGE_MASK),
			    PAGE_SIZE - (off & PAGE_MASK), uio);
			if (error != 0 || uio->uio_resid == 0)
				break;
			off = uio->uio_offset - baseoff;
		}
		break;
	case DUMP_SEG_PAGES:
		/* Dump pages marked in the bitmap.  This is non-destructive. */
		bitmap = (uint64_t *)sc->sc_segs[DUMP_SEG_BITMAP].ds_addr;
		bitmapsize = (uint32_t)sc->sc_segs[DUMP_SEG_BITMAP].ds_sz;
		off1 = 0;
		for (i = 0; i < bitmapsize / sizeof(uint64_t); i++) {
			bits = bitmap[i];
			if (off1 < off) {
				/*
				 * Seek forward in the array until we find where
				 * we left off during the last read.
				 */
				bitcount = bitcount64(bits);
				if (off1 + bitcount * PAGE_SIZE <= off) {
					off1 += bitcount * PAGE_SIZE;
					continue;
				}
				do {
					bits &= ~(1ul << (ffsl(bits) - 1));
					off1 += PAGE_SIZE;
				} while (off1 < off);
			}
			while (bits != 0) {
				bit = ffsl(bits) - 1;
				bits &= ~(1ul << bit);
#define	NBDUMPSLOT	(sizeof(uint64_t) * NBBY)
				pa = ((uint64_t)i * NBDUMPSLOT + bit) *
				    PAGE_SIZE;
				pmap_kenter(sc->sc_scratchkva, PAGE_SIZE, pa,
				    CACHED_MEMORY);
				error = uiomove((char *)sc->sc_scratchkva +
				    (off % PAGE_SIZE),
				    PAGE_SIZE - (off % PAGE_SIZE), uio);
				if (error != 0)
					goto out;
				if (uio->uio_resid == 0)
					goto out;
				off = off1 = uio->uio_offset - baseoff;
			}
		}
out:
		break;
	default:
		panic("%s: unknown segment index %d", __func__, idx);
	}

	return (error);
}

static int
dumper_read(struct cdev *dev, struct uio *uio, int flags)
{
	struct dump_softc *sc;
	struct dump_seg *seg;
	off_t baseoff, off;
	int error, i;

	error = devfs_get_cdevpriv((void **)&sc);
	if (error != 0)
		return (error);

	off = uio->uio_offset;
	if (off < 0)
		return (EINVAL);

	/* Seeks are not supported. */
	if (off != sc->sc_cursor)
		return (ESPIPE);

	for (baseoff = 0, i = 0; i < DUMP_SEG_COUNT; i++) {
		seg = &sc->sc_segs[i];
		if (off >= baseoff && off < baseoff + seg->ds_sz) {
			error = dumper_read_seg(sc, i, seg, baseoff, uio);
			break;
		}
		baseoff += seg->ds_sz;
		MPASS((baseoff & PAGE_MASK) == 0);
	}

	sc->sc_cursor = uio->uio_offset;
	return (error);
}

static struct cdevsw dumper_cdevsw = {
	.d_version =	D_VERSION,
	.d_open =	dumper_open,
	.d_read =	dumper_read,
	.d_name =	"dumper",
};

static int
dumper_modevent(module_t mod __unused, int type, void *data __unused)
{
	static struct cdev *dumper_dev;

	switch (type) {
	case MOD_LOAD:
		dumper_dev = make_dev(&dumper_cdevsw, 0, UID_ROOT, GID_WHEEL,
		    0600, "dumper");
		break;
	case MOD_UNLOAD:
		destroy_dev(dumper_dev);
		break;
	}
	return (0);
}
DEV_MODULE(dumper, dumper_modevent, NULL);
MODULE_VERSION(dumper, 1);
