/*-
 * Copyright 2006-2008 John Birrell <jb@FreeBSD.org>
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

#include <sys/eventhandler.h>
#include <sys/linker.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/queue.h>
#include <sys/sdt.h>

#include <machine/cpu.h>

SDT_PROVIDER_DEFINE(sdt);

static MALLOC_DEFINE(M_SDT, "sdt", "statically-defined tracing");

static eventhandler_tag sdt_kld_unload_try_tag;

static void
sdt_kld_unload_try(void *arg __unused, linker_file_t lf, int *error)
{
	struct sdt_probe **probe, **start, **end;
	struct sdt_probedesc *desc;

	if (*error != 0)
		return;
	if (linker_file_lookup_set(lf, "sdt_probes_set", &start, &end,
	    NULL) != 0)
		return;

	for (probe = start; probe < end; probe++) {
		while ((desc = SLIST_FIRST(&(*probe)->site_list)) != NULL) {
			SLIST_REMOVE_HEAD(&(*probe)->site_list, li.spd_entry);
			free(*probe, M_SDT);
		}
	}
}

static void
sdt_patch_callsite(struct sdt_probe *probe, struct sdt_probedesc *desc,
    uint64_t offset)
{

	offset = sdt_md_patch_callsite(probe, offset, desc == NULL);
	if (offset == 0)
		return;

	/*
	 * The probe site is patched; now we can associate the site with
	 * the probe itself. Descriptors allocated here are freed in the
	 * kld_unload event handler.
	 */
	if (desc == NULL)
		desc = malloc(sizeof(*desc), M_SDT, M_WAITOK);
	desc->spd_offset = offset;
	SLIST_INSERT_HEAD(&probe->site_list, desc, li.spd_entry);
}

/*
 * Use the SDT probe sites specified in the probe site linker set to overwrite
 * each probe site with NOPs. At the moment, only the kernel will contain such a
 * set - probe sites in KLDs are patched when the load-time linker sees a
 * relocation against a symbol with a prefix of "__dtrace_sdt_".
 */
static int
sdt_patch_linker_file(linker_file_t lf, void *arg __unused)
{
	struct sdt_probedesc *desc, *start, *end;
	struct sdt_probe *probe;

	if (linker_file_lookup_set(lf, "sdt_probe_site_set", &start, &end,
	    NULL) != 0)
		return (0);

	/*
	 * Linker set iteration here deviates from the normal pattern because
	 * this linker set is special: it contains the probe descriptor structs
	 * themselves rather than pointers.
	 */
	for (desc = start; desc < end; desc++) {
		probe = desc->li.spd_probe;
		sdt_patch_callsite(probe, desc, desc->spd_offset +
		    (uintptr_t)btext);
	}
	return (0);
}

/*
 * Patch the kernel's probe sites.
 */
static void
sdt_patch_kernel(void *arg __unused)
{

	linker_file_foreach(sdt_patch_linker_file, NULL);
	sdt_kld_unload_try_tag = EVENTHANDLER_REGISTER(kld_unload_try,
	    sdt_kld_unload_try, NULL, EVENTHANDLER_PRI_ANY);
}
SYSINIT(sdt_hotpatch, SI_SUB_KDTRACE, SI_ORDER_FIRST, sdt_patch_kernel, NULL);

void
sdt_patch_reloc(linker_file_t lf, const char *symname, uint64_t base,
    uint64_t offset)
{
	struct sdt_probe *probe;
	caddr_t sym;

	KASSERT(strncmp(symname, SDT_PROBE_STUB_PREFIX,
	    sizeof(SDT_PROBE_STUB_PREFIX) - 1) == 0,
	    ("invalid reloc sym %s", symname));

	symname += sizeof("__dtrace_") - 1; /* XXX */
	sym = linker_file_lookup_symbol(lf, symname, 0);
	if (sym == 0) {
		printf("sdt: couldn't find symbol %s\n", symname);
		return;
	}

	probe = (struct sdt_probe *)sym;
	sdt_patch_callsite(probe, NULL, base + offset);
}
