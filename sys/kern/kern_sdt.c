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

#include <sys/linker.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/queue.h>
#include <sys/sdt.h>

#include <machine/cpu.h>

CTASSERT(sizeof(struct sdt_probedesc) == 16);

SDT_PROVIDER_DEFINE(sdt);

MALLOC_DEFINE(M_SDT, "sdt", "statically-defined tracing");

#define	CALL_SITE_LEN	5

#define	AMD64_CALL32	0xe8
#define	AMD64_JMP32	0xe9
#define	AMD64_NOP	0x90
#define	AMD64_RET	0xc3

/*
 * Defined by sdtstubs.sh at compile-time.
 */
void	_sdt_probe_stub(void);

static void
sdt_patch_site(struct sdt_probe *probe, struct sdt_probedesc *desc,
    uint64_t offset)
{
	uintptr_t stubaddr;
	uint32_t target;
	uint8_t *callinstr, opcode;

	callinstr = (uint8_t *)(uintptr_t)(offset - 1);
	opcode = callinstr[0];
	switch (opcode) {
	case AMD64_CALL32:
	case AMD64_JMP32:
		break;
	default:
		printf("sdt: opcode mismatch (0x%x) for %s:::%s@%p\n",
		    callinstr[0], probe->prov->name, probe->name,
		    (void *)(uintptr_t)offset);
		return;
	}

	/*
	 * If we've been passed a probe descriptor, verify that the call/jmp
	 * target is in fact the SDT stub. If it's not, something's wrong and
	 * we shouldn't touch anything.
	 */
	stubaddr = (uintptr_t)_sdt_probe_stub;
	memcpy(&target, &callinstr[1], sizeof(target));
	if (desc != NULL &&
	    roundup2(target + (uintptr_t)callinstr, 16) != stubaddr) {
		printf("sdt: offset mismatch: %p vs. %p\n",
		    (void *)roundup2(target + (uintptr_t)callinstr, 16),
		    (void *)stubaddr);
		return;
	}

	switch (opcode) {
	case AMD64_CALL32:
		memset(callinstr, AMD64_NOP, CALL_SITE_LEN);
		break;
	case AMD64_JMP32:
		/*
		 * The probe site is a tail call, so we need a "ret"
		 * when the probe isn't enabled. We overwrite the second
		 * byte instead of the first: the first byte will be
		 * replaced with a breakpoint when the probe is enabled.
		 */
		memset(callinstr, AMD64_NOP, CALL_SITE_LEN);
		callinstr[1] = AMD64_RET;
		break;
	}

	/*
	 * The probe site is patched; now we can associate the site with
	 * the probe itself.
	 */
	if (desc == NULL)
		desc = malloc(sizeof(*desc), M_SDT, M_WAITOK);
	desc->spd_offset = (uintptr_t)callinstr;
	SLIST_INSERT_HEAD(&probe->site_list, desc, li.spd_entry);
}

/*
 * Use the SDT probe sites specified in the probe site linker set to overwrite
 * each probe site with NOPs. At the moment, only the kernel will contain such a
 * set - probe sites in KLDs are patched when the linker sees a relocation
 * against a symbol with a prefix of "__dtrace_sdt_".
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
	 * this linker set is special: it contains the probe info structs
	 * themselves rather than pointers.
	 */
	for (desc = start; desc < end; desc++) {
		probe = desc->li.spd_probe;
		sdt_patch_site(probe, desc, desc->spd_offset +
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
	sdt_patch_site(probe, NULL, base + offset);
}
