/*-
 * Copyright 2006-2008 John Birrell <jb@FreeBSD.org>
 * Copyright (c) 2015 Mark Johnston <markj@FreeBSD.org>
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
#include <sys/queue.h>
#include <sys/sdt.h>

#include <machine/cpu.h>

CTASSERT(sizeof(struct sdt_probedesc) == 16);

SDT_PROVIDER_DEFINE(sdt);

#define	CALL_SITE_LEN	5

#define	AMD64_CALL32	0xe8
#define	AMD64_JMP32	0xe9
#define	AMD64_NOP	0x90
#define	AMD64_RET	0xc3

static eventhandler_tag sdt_kld_load_tag;

/*
 * Defined by sdtstubs.sh at compile-time.
 */
void	_sdt_probe_stub(void);

static int
sdt_patch_linker_file(linker_file_t lf, void *arg __unused)
{
	struct sdt_probedesc *spd, *start, *end;
	struct sdt_probe *probe;
	uintptr_t stubaddr;
	uint32_t offset;
	uint8_t *callbuf, opcode;

	if (linker_file_lookup_set(lf, "sdt_probe_site_set", &start, &end,
	    NULL) != 0)
		return (0);

	stubaddr = (uintptr_t)_sdt_probe_stub;

	/*
	 * Linker set iteration deviates from the normal pattern because this
	 * linker set is special: it contains the probe info structs themselves
	 * rather than pointers.
	 */
	for (spd = start; spd < end; spd++) {
		callbuf = (uint8_t *)(uintptr_t)(spd->spd_offset - 1 +
		    (uintptr_t)btext);
		opcode = callbuf[0];
		switch (opcode) {
		case AMD64_CALL32:
		case AMD64_JMP32:
			break;
		default:
			printf("sdt: opcode mismatch (0x%x) for %s:::%s@%p\n",
			    callbuf[0], spd->link.spd_probe->prov->name,
			    spd->link.spd_probe->name, (void *)spd->spd_offset);
			continue;
		}

		/*
		 * Verify that the call/jmp target is in fact the SDT stub.
		 * If it's not, we shouldn't touch anything.
		 */
		memcpy(&offset, &callbuf[1], sizeof(offset));
		if (roundup2(offset + (uintptr_t)callbuf, 16) != stubaddr) {
			printf("sdt: offset mismatch: %p vs. %p\n",
			    (void *)roundup2(offset + (uintptr_t)callbuf, 16),
			    (void *)stubaddr);
			continue;
		}

		switch (opcode) {
		case AMD64_CALL32:
			memset(callbuf, AMD64_NOP, CALL_SITE_LEN);
			break;
		case AMD64_JMP32:
			/* The probe site is a tail call; just return. */
			callbuf[0] = AMD64_RET;
			memset(&callbuf[1], AMD64_NOP, CALL_SITE_LEN - 1);
			break;
		}
		spd->spd_offset = (uintptr_t)callbuf;

		/*
		 * The probe site is patched; now we can associate the site with
		 * the probe itself.
		 */
		probe = spd->link.spd_probe;
		SLIST_INSERT_HEAD(&probe->site_list, spd, link.spd_entry);
	}
	return (0);
}

static void
sdt_kld_load(void *arg __unused, linker_file_t lf)
{

	sdt_patch_linker_file(lf, NULL);
}

static void
sdt_patch_kernel(void *arg __unused)
{

	linker_file_foreach(sdt_patch_linker_file, NULL);
	sdt_kld_load_tag = EVENTHANDLER_REGISTER(kld_load, sdt_kld_load, NULL,
	    EVENTHANDLER_PRI_FIRST);
}
SYSINIT(sdt_hotpatch, SI_SUB_KDTRACE, SI_ORDER_FIRST, sdt_patch_kernel, NULL);
