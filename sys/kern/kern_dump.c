/*-
 * Copyright (c) 2002 Marcel Moolenaar
 * Copyright (c) 2015 EMC Corporation
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include "opt_ddb.h"
#include "opt_gzio.h"
#include "opt_watchdog.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/cons.h>
#include <sys/gzio.h>
#include <sys/jail.h>
#include <sys/kernel.h>
#include <sys/kerneldump.h>
#include <sys/malloc.h>
#include <sys/priv.h>
#include <sys/proc.h>
#include <sys/sysctl.h>
#ifdef SW_WATCHDOG
#include <sys/watchdog.h>
#endif

#include <ddb/ddb.h>

#include <vm/vm.h>
#include <vm/vm_param.h>
#include <vm/pmap.h>

#include <machine/dump.h>
#include <machine/elf.h>
#include <machine/md_var.h>
#include <machine/pcb.h>

CTASSERT(sizeof(struct kerneldumpheader) == 512);

/*
 * Don't touch the first SIZEOF_METADATA bytes on the dump device. This
 * is to protect us from metadata and to protect metadata from us.
 */
#define	SIZEOF_METADATA		(64*1024)

#define	MD_ALIGN(x)	(((off_t)(x) + PAGE_MASK) & ~PAGE_MASK)
#define	DEV_ALIGN(x)	(((off_t)(x) + (DEV_BSIZE-1)) & ~(DEV_BSIZE-1))

struct dump_pa dump_map[DUMPSYS_MD_PA_NPAIRS];

/* Our selected dumper. */
static struct dumperinfo dumper;

/* Context information for dump-debuggers. */
static struct pcb dumppcb;		/* Registers. */
lwpid_t dumptid;			/* Thread ID. */

/* Dump state. */
static off_t dumpoff;
static char buffer[DEV_BSIZE];
static size_t fragsz;
#ifdef GZIO
static struct gzio_stream *gzs;
static uint8_t *gzbuffer;
#endif

static char dumpdevname[sizeof(((struct cdev *)NULL)->si_name)];
SYSCTL_DECL(_kern_shutdown);
SYSCTL_STRING(_kern_shutdown, OID_AUTO, dumpdevname, CTLFLAG_RD, dumpdevname, 0,
    "Device for kernel dumps");

static int compress_kernel_dumps = 0;

#ifdef GZIO
static int compress_kernel_dumps_gzlevel = 6;
SYSCTL_INT(_kern, OID_AUTO, compress_kernel_dumps_gzlevel, CTLFLAG_RW,
    &compress_kernel_dumps_gzlevel, 0,
    "Kernel crash dump compression level");

static int sysctl_dump_gz_toggle(SYSCTL_HANDLER_ARGS);
SYSCTL_PROC(_kern, OID_AUTO, compress_kernel_dumps, CTLFLAG_RW | CTLTYPE_INT,
    &compress_kernel_dumps, 0, sysctl_dump_gz_toggle, "I",
    "Enable compressed kernel crash dumps");

static int	dump_gz_configure(struct dumperinfo *);
static void	dump_gz_disable(void);
static int	dump_gz_write_cb(void *, size_t, off_t, void *);

static int
sysctl_dump_gz_toggle(SYSCTL_HANDLER_ARGS)
{
	int error, value;

	value = *(int *)arg1;
	error = sysctl_handle_int(oidp, &value, 0, req);
	if (error != 0 || req->newptr == NULL)
		return (error);

	if (value == 0) {
		compress_kernel_dumps = 0;
		dump_gz_disable();
	} else if (compress_kernel_dumps == 0) {
		if (strlen(dumpdevname) > 0)
			error = dump_gz_configure(&dumper);
		if (error == 0)
			compress_kernel_dumps = 1;
	}
	return (error);
}
#endif /* GZIO */

/*
 * When writing a kernel dump to disk, we also include dump metadata that is
 * used by savecore(8) to locate and recover the dump.  This metadata is
 * represented by the struct kerneldumpheader type.  When a kernel dump is
 * complete, two copies of the header are written: one to the last sector of
 * the dump medium, and one immediately before the beginning of the dump.  The
 * last header is used to locate the first header, and thus, the dump itself.
 *
 * When the dump is written without compression, things are simple: we know
 * exactly how long the dump will be, so the initial offset in the medium can be
 * chosen such that the end of the dump is flush with the terminating header.
 * In this case, the "extent" of the dump (the space between the two headers) is
 * equal to its length.  In the compressed case we don't know the dump length
 * a priori, so we write the dump starting at the same offset as we would in the
 * uncompressed case.  Once the dump is complete, we know its compressed length,
 * so the dump headers are updated and written to the medium.  In this case, the
 * extent tells savecore(8) where to find the beginning of the dump, and the
 * length tells it how far into the extent it must read to recover the dump.
 */

int
doadump(boolean_t textdump)
{
	boolean_t coredump;
	int error;

	error = 0;
	if (dumping)
		return (EBUSY);
	if (dumper.dumper == NULL)
		return (ENXIO);

	savectx(&dumppcb);
	dumptid = curthread->td_tid;
	dumping++;

	coredump = TRUE;
#ifdef DDB
	if (textdump && textdump_pending) {
		coredump = FALSE;
		textdump_dumpsys(&dumper);
	}
#endif
	if (coredump)
		error = dumpsys(&dumper);

	dumping--;
	return (error);
}

/* Perform any needed initialization in preparation for a kernel dump. */
int
dump_start(struct dumperinfo *di, struct kerneldumpheader *kdh)
{
	uint64_t length;

	length = dtoh64(kdh->dumplength);
	if (di->mediasize < SIZEOF_METADATA + length + sizeof(*kdh) * 2) {
		if (compress_kernel_dumps)
			/*
			 * We don't yet know how much space the compressed dump
			 * will occupy, so try to use the whole swap partition
			 * (minus the first 64KB). If that doesn't turn out to
			 * be enough, the bounds checking in dump_write_raw()
			 * will catch us.
			 */
			length = di->mediasize - SIZEOF_METADATA -
			    2 * sizeof(*kdh);
		else
			return (ENOSPC);
	}

	/*
	 * The initial offset at which we're going to write the dump (excluding
	 * the leading kernel dump header).
	 */
	dumpoff = di->mediaoffset + di->mediasize - length - sizeof(*kdh);
	kdh->dumpextent = htod64(length);
	return (0);
}

/* Complete a kernel dump. */
int
dump_finish(struct dumperinfo *di, struct kerneldumpheader *kdh)
{
	uint64_t extent;
	int error;

	extent = dtoh64(kdh->dumpextent);

#ifdef GZIO
	if (compress_kernel_dumps) {
		error = gzio_flush(gzs);
		if (error != 0)
			return (error);

		/*
		 * Now that we've completed the compressed dump, we know its
		 * size, so update the header accordingly and recompute parity.
		 */
		kdh->dumplength = htod64(dumpoff -
		    (di->mediaoffset + di->mediasize - extent - sizeof(*kdh)));
		kdh->parity = 0;
		kdh->parity = kerneldump_parity(kdh);
	}
#endif

	/* Write dump headers at the beginning and end of the dump extent. */
	error = dump_write_raw(di, kdh, 0,
	    di->mediaoffset + di->mediasize - sizeof(*kdh), sizeof(*kdh));
	if (error != 0)
		return (error);
	error = dump_write_raw(di, kdh, 0,
	    di->mediaoffset + di->mediasize - extent - 2 * sizeof(*kdh),
	    sizeof(*kdh));
	if (error != 0)
		return (error);

	/* Reset dump state. */
#ifdef GZIO
	if (compress_kernel_dumps)
		gzio_reset(gzs);
#endif
	dumpoff = 0;

	/* Tell the dump media driver that we're done. */
	return (dump_write_raw(di, NULL, 0, 0, 0));
}

/* Write starting at the current kernel dump offset. */
int
dump_append(struct dumperinfo *di, void *virtual, vm_offset_t physical,
    size_t length)
{
	int error;

#ifdef GZIO
	if (compress_kernel_dumps) {
		/* Bounce through a buffer to avoid gzip CRC errors. */
		memmove(gzbuffer, virtual, length);
		return (gzio_write(gzs, gzbuffer, length));
	}
#endif

	error = dump_write_raw(di, virtual, physical, dumpoff, length);
	if (error == 0)
		dumpoff += length;
	return (error);
}

/* Seek forward by the specified number of bytes. */
int
dump_skip(struct dumperinfo *di, size_t gap)
{

	if (gap > di->maxiosize)
		return (ENXIO);

#ifdef GZIO
	if (compress_kernel_dumps) {
		memset(gzbuffer, 0, di->maxiosize);
		return (gzio_write(gzs, gzbuffer, gap));
	}
#endif

	dumpoff += gap;
	return (0);
}

/* Call dumper with bounds checking. */
int
dump_write_raw(struct dumperinfo *di, void *virtual, vm_offset_t physical,
    off_t offset, size_t length)
{

	if (length != 0 && (offset < di->mediaoffset ||
	    offset - di->mediaoffset + length > di->mediasize)) {
		printf("Attempt to write outside dump device boundaries.\n"
	    "offset(%jd), mediaoffset(%jd), length(%ju), mediasize(%jd).\n",
		    (intmax_t)offset, (intmax_t)di->mediaoffset,
		    (uintmax_t)length, (intmax_t)di->mediasize);
		return (ENOSPC);
	}
	return (di->dumper(di->priv, virtual, physical, offset, length));
}

#ifdef GZIO
static int
dump_gz_configure(struct dumperinfo *di)
{

	MPASS(gzs == NULL);
	gzs = gzio_init(dump_gz_write_cb, GZIO_DEFLATE, di->maxiosize,
	    compress_kernel_dumps_gzlevel, di);
	if (gzs == NULL)
		return (EINVAL);
	gzbuffer = malloc(di->maxiosize, M_TEMP, M_WAITOK | M_NODUMP);
	return (0);
}

static void
dump_gz_disable(void)
{

	if (gzs != NULL) {
		gzio_fini(gzs);
		gzs = NULL;
	}
	free(gzbuffer, M_TEMP);
	gzbuffer = NULL;
}

/* Write compressed data to the dump medium. */
static int
dump_gz_write_cb(void *base, size_t length, off_t offset __unused, void *arg)
{
	struct dumperinfo *di;
	int error;

	di = (struct dumperinfo *)arg;
	error = dump_write_raw(di, base, 0, dumpoff,
	    roundup(length, di->blocksize));
	if (error == 0)
		dumpoff += length;
	return (error);
}
#endif /* GZIO */

/* Register a dumper. */
int
set_dumper(struct dumperinfo *di, const char *devname, struct thread *td)
{
	size_t wantcopy;
	int error;

	error = priv_check(td, PRIV_SETDUMPER);
	if (error != 0)
		return (error);

	if (di == NULL) {
		bzero(&dumper, sizeof dumper);
		dumpdevname[0] = '\0';
#ifdef GZIO
		if (compress_kernel_dumps)
			dump_gz_disable();
#endif
		return (0);
	}
	if (dumper.dumper != NULL)
		return (EBUSY);
	dumper = *di;
	wantcopy = strlcpy(dumpdevname, devname, sizeof(dumpdevname));
	if (wantcopy >= sizeof(dumpdevname))
		printf("set_dumper: device name truncated from '%s' -> '%s'\n",
		    devname, dumpdevname);
#ifdef GZIO
	if (compress_kernel_dumps)
		error = dump_gz_configure(di);
#endif
	return (error);
}

void
mkdumpheader(struct kerneldumpheader *kdh, char *magic, uint32_t archver,
    uint64_t dumplen, uint32_t blksz)
{

	bzero(kdh, sizeof(*kdh));
	strlcpy(kdh->magic, magic, sizeof(kdh->magic));
	strlcpy(kdh->architecture, MACHINE_ARCH, sizeof(kdh->architecture));
	if (compress_kernel_dumps && strcmp(magic, KERNELDUMPMAGIC) == 0)
		strlcpy(kdh->magic, GZDUMPMAGIC, sizeof(kdh->magic));
	else
		strlcpy(kdh->magic, magic, sizeof(kdh->magic));
	kdh->version = htod32(KERNELDUMPVERSION);
	kdh->architectureversion = htod32(archver);
	kdh->dumplength = htod64(dumplen);
	kdh->dumpextent = kdh->dumplength;
	kdh->dumptime = htod64(time_second);
	kdh->blocksize = htod32(blksz);
	strlcpy(kdh->hostname, prison0.pr_hostname, sizeof(kdh->hostname));
	strlcpy(kdh->versionstring, version, sizeof(kdh->versionstring));
	if (panicstr != NULL)
		strlcpy(kdh->panicstring, panicstr, sizeof(kdh->panicstring));
	kdh->parity = kerneldump_parity(kdh);
}

#if !defined(__powerpc__) && !defined(__sparc__)
void
dumpsys_gen_pa_init(void)
{
	int n, idx;

	bzero(dump_map, sizeof(dump_map));
	for (n = 0; n < sizeof(dump_map) / sizeof(dump_map[0]); n++) {
		idx = n * 2;
		if (dump_avail[idx] == 0 && dump_avail[idx + 1] == 0)
			break;
		dump_map[n].pa_start = dump_avail[idx];
		dump_map[n].pa_size = dump_avail[idx + 1] - dump_avail[idx];
	}
}
#endif

struct dump_pa *
dumpsys_gen_pa_next(struct dump_pa *mdp)
{

	if (mdp == NULL)
		return (&dump_map[0]);

	mdp++;
	if (mdp->pa_size == 0)
		mdp = NULL;
	return (mdp);
}

void
dumpsys_gen_wbinv_all(void)
{

}

void
dumpsys_gen_unmap_chunk(vm_paddr_t pa __unused, size_t chunk __unused,
    void *va __unused)
{

}

#if !defined(__sparc__)
int
dumpsys_gen_write_aux_headers(struct dumperinfo *di)
{

	return (0);
}
#endif

int
dumpsys_buf_write(struct dumperinfo *di, char *ptr, size_t sz)
{
	size_t len;
	int error;

	while (sz) {
		len = DEV_BSIZE - fragsz;
		if (len > sz)
			len = sz;
		bcopy(ptr, buffer + fragsz, len);
		fragsz += len;
		ptr += len;
		sz -= len;
		if (fragsz == DEV_BSIZE) {
			error = dump_append(di, buffer, 0, DEV_BSIZE);
			if (error)
				return (error);
			fragsz = 0;
		}
	}
	return (0);
}

int
dumpsys_buf_flush(struct dumperinfo *di)
{
	int error;

	if (fragsz == 0)
		return (0);

	error = dump_append(di, buffer, 0, DEV_BSIZE);
	fragsz = 0;
	return (error);
}

CTASSERT(PAGE_SHIFT < 20);
#define PG2MB(pgs) ((pgs + (1 << (20 - PAGE_SHIFT)) - 1) >> (20 - PAGE_SHIFT))

int
dumpsys_cb_dumpdata(struct dump_pa *mdp, int seqnr, void *arg)
{
	struct dumperinfo *di = (struct dumperinfo*)arg;
	vm_paddr_t pa;
	void *va;
	uint64_t pgs;
	size_t counter, sz, chunk;
	int c, error;
	u_int maxdumppgs;

	error = 0;	/* catch case in which chunk size is 0 */
	counter = 0;	/* Update twiddle every 16MB */
	va = 0;
	pgs = mdp->pa_size / PAGE_SIZE;
	pa = mdp->pa_start;
	maxdumppgs = min(di->maxiosize / PAGE_SIZE, MAXDUMPPGS);
	if (maxdumppgs == 0)	/* seatbelt */
		maxdumppgs = 1;

	printf("  chunk %d: %juMB (%ju pages)", seqnr, (uintmax_t)PG2MB(pgs),
	    (uintmax_t)pgs);

	dumpsys_wbinv_all();
	while (pgs) {
		chunk = pgs;
		if (chunk > maxdumppgs)
			chunk = maxdumppgs;
		sz = chunk << PAGE_SHIFT;
		counter += sz;
		if (counter >> 24) {
			printf(" %ju", (uintmax_t)PG2MB(pgs));
			counter &= (1 << 24) - 1;
		}

		dumpsys_map_chunk(pa, chunk, &va);
#ifdef SW_WATCHDOG
		wdog_kern_pat(WD_LASTVAL);
#endif

		error = dump_append(di, va, 0, sz);
		dumpsys_unmap_chunk(pa, chunk, va);
		if (error)
			break;
		pgs -= chunk;
		pa += sz;

		/* Check for user abort. */
		c = cncheckc();
		if (c == 0x03)
			return (ECANCELED);
		if (c != -1)
			printf(" (CTRL-C to abort) ");
	}
	printf(" ... %s\n", (error) ? "fail" : "ok");
	return (error);
}

int
dumpsys_foreach_chunk(dumpsys_callback_t cb, void *arg)
{
	struct dump_pa *mdp;
	int error, seqnr;

	seqnr = 0;
	mdp = dumpsys_pa_next(NULL);
	while (mdp != NULL) {
		error = (*cb)(mdp, seqnr++, arg);
		if (error)
			return (-error);
		mdp = dumpsys_pa_next(mdp);
	}
	return (seqnr);
}

#if !defined(__sparc__)
static off_t fileofs;

static int
cb_dumphdr(struct dump_pa *mdp, int seqnr, void *arg)
{
	struct dumperinfo *di = (struct dumperinfo*)arg;
	Elf_Phdr phdr;
	uint64_t size;
	int error;

	size = mdp->pa_size;
	bzero(&phdr, sizeof(phdr));
	phdr.p_type = PT_LOAD;
	phdr.p_flags = PF_R;			/* XXX */
	phdr.p_offset = fileofs;
#ifdef __powerpc__
	phdr.p_vaddr = (do_minidump? mdp->pa_start : ~0L);
	phdr.p_paddr = (do_minidump? ~0L : mdp->pa_start);
#else
	phdr.p_vaddr = mdp->pa_start;
	phdr.p_paddr = mdp->pa_start;
#endif
	phdr.p_filesz = size;
	phdr.p_memsz = size;
	phdr.p_align = PAGE_SIZE;

	error = dumpsys_buf_write(di, (char*)&phdr, sizeof(phdr));
	fileofs += phdr.p_filesz;
	return (error);
}

static int
cb_size(struct dump_pa *mdp, int seqnr, void *arg)
{
	uint64_t *sz;

	sz = (uint64_t *)arg;
	*sz += (uint64_t)mdp->pa_size;
	return (0);
}

int
dumpsys_generic(struct dumperinfo *di)
{
	static struct kerneldumpheader kdh;
	Elf_Ehdr ehdr;
	uint64_t dumpsize;
	off_t hdrgap;
	size_t hdrsz;
	int error;

#ifndef __powerpc__
	if (do_minidump)
		return (minidumpsys(di));
#endif

	bzero(&ehdr, sizeof(ehdr));
	ehdr.e_ident[EI_MAG0] = ELFMAG0;
	ehdr.e_ident[EI_MAG1] = ELFMAG1;
	ehdr.e_ident[EI_MAG2] = ELFMAG2;
	ehdr.e_ident[EI_MAG3] = ELFMAG3;
	ehdr.e_ident[EI_CLASS] = ELF_CLASS;
#if BYTE_ORDER == LITTLE_ENDIAN
	ehdr.e_ident[EI_DATA] = ELFDATA2LSB;
#else
	ehdr.e_ident[EI_DATA] = ELFDATA2MSB;
#endif
	ehdr.e_ident[EI_VERSION] = EV_CURRENT;
	ehdr.e_ident[EI_OSABI] = ELFOSABI_STANDALONE;	/* XXX big picture? */
	ehdr.e_type = ET_CORE;
	ehdr.e_machine = EM_VALUE;
	ehdr.e_phoff = sizeof(ehdr);
	ehdr.e_flags = 0;
	ehdr.e_ehsize = sizeof(ehdr);
	ehdr.e_phentsize = sizeof(Elf_Phdr);
	ehdr.e_shentsize = sizeof(Elf_Shdr);

	dumpsys_pa_init();

	/* Calculate dump size. */
	dumpsize = 0L;
	ehdr.e_phnum = dumpsys_foreach_chunk(cb_size, &dumpsize) +
	    DUMPSYS_NUM_AUX_HDRS;
	hdrsz = ehdr.e_phoff + ehdr.e_phnum * ehdr.e_phentsize;
	fileofs = MD_ALIGN(hdrsz);
	dumpsize += fileofs;
	hdrgap = fileofs - DEV_ALIGN(hdrsz);

	mkdumpheader(&kdh, KERNELDUMPMAGIC, KERNELDUMP_ARCH_VERSION, dumpsize,
	    di->blocksize);

	printf("Dumping %ju MB (%d chunks)\n", (uintmax_t)dumpsize >> 20,
	    ehdr.e_phnum - DUMPSYS_NUM_AUX_HDRS);

	error = dump_start(di, &kdh);
	if (error)
		goto fail;

	/* Dump ELF header */
	error = dumpsys_buf_write(di, (char*)&ehdr, sizeof(ehdr));
	if (error)
		goto fail;

	/* Dump program headers */
	error = dumpsys_foreach_chunk(cb_dumphdr, di);
	if (error < 0)
		goto fail;
	error = dumpsys_write_aux_headers(di);
	if (error < 0)
		goto fail;
	dumpsys_buf_flush(di);

	/*
	 * All headers are written using blocked I/O, so we know the
	 * current offset is (still) block aligned. Skip the alignement
	 * in the file to have the segment contents aligned at page
	 * boundary. We cannot use MD_ALIGN on the current offset, because
	 * we don't care and may very well be unaligned within the dump
	 * device.
	 */
	error = dump_skip(di, hdrgap);
	if (error != 0)
		goto fail;

	/* Dump memory chunks. */
	error = dumpsys_foreach_chunk(dumpsys_cb_dumpdata, di);
	if (error < 0)
		goto fail;

	/* Signal completion, signoff and exit stage left. */
	error = dump_finish(di, &kdh);
	if (error != 0)
		goto fail;
	printf("\nDump complete\n");
	return (0);

 fail:
	if (error < 0)
		error = -error;

	if (error == ECANCELED)
		printf("\nDump aborted\n");
	else if (error == ENOSPC)
		printf("\nDump failed. Partition too small.\n");
	else
		printf("\n** DUMP FAILED (ERROR %d) **\n", error);
	return (error);
}
#endif
