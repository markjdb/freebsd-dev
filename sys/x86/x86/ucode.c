/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2018 The FreeBSD Foundation
 *
 * This software was developed by Mark Johnston under sponsorship from
 * the FreeBSD foundation.
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
#include <sys/cpuset.h>
#include <sys/kernel.h>
#include <sys/linker.h>
#include <sys/malloc.h>
#include <sys/pcpu.h>
#include <sys/smp.h>
#include <sys/systm.h>

#include <machine/cpufunc.h>
#include <x86/specialreg.h>
#include <machine/stdarg.h>
#include <x86/ucode.h>
#include <x86/x86_smp.h>

#include <vm/vm.h>
#include <vm/vm_extern.h>
#include <vm/vm_kern.h>

struct ucode_ops {
	const char *vendor;
	int (*load)(void *, bool);
	void *(*match)(uint8_t *, size_t *);
};

struct ucode_intel_header {
	uint32_t	header_version;
	int32_t		update_revision;
	uint32_t	dat;
	uint32_t	processor_signature;
	uint32_t	checksum;
	uint32_t	loader_revision;
	uint32_t	processor_flags;
#define	UCODE_INTEL_DEFAULT_DATA_SIZE		2000
	uint32_t	data_size;
	uint32_t	total_size;
	uint32_t	reserved[3];
};

struct ucode_intel_extsig_table {
	uint32_t	signature_count;
	uint32_t	signature_table_checksum;
	uint32_t	reserved[3];
	struct ucode_intel_extsig {
		uint32_t	processor_signature;
		uint32_t	processor_flags;
		uint32_t	checksum;
	} entries[0];
};

static void	*ucode_intel_match(uint8_t *data, size_t *len);
static int	ucode_intel_verify(struct ucode_intel_header *hdr,
		    size_t resid);

static struct ucode_ops loaders[] = {
	{
		.vendor = INTEL_VENDOR_ID,
		.load = ucode_intel_load,
		.match = ucode_intel_match,
	},
};

/* Selected microcode update data. */
static void *ucode_data;
static size_t ucode_len;

static char errbuf[128];

static void __printflike(1, 2)
log_err(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(errbuf, sizeof(errbuf), fmt, ap);
	va_end(ap);
}

static void
print_err(void *arg __unused)
{

	if (errbuf[0] != '\0')
		printf("microcode load error: %s\n", errbuf);
}
SYSINIT(ucode_print_err, SI_SUB_CPU, SI_ORDER_FIRST, print_err, NULL);

int
ucode_intel_load(void *data, bool unsafe)
{
	uint64_t rev0, rev1;
	uint32_t cpuid[4];

	rev0 = rdmsr(MSR_BIOS_SIGN);

	/*
	 * Perform update.  Flush caches first to work around seemingly
	 * undocumented errata applying to some Broadwell CPUs.
	 */
	wbinvd();
	if (unsafe)
		wrmsr_safe(MSR_BIOS_UPDT_TRIG, (uint64_t)(uintptr_t)data);
	else
		wrmsr(MSR_BIOS_UPDT_TRIG, (uint64_t)(uintptr_t)data);
	wrmsr(MSR_BIOS_SIGN, 0);

	/*
	 * Serialize instruction flow.
	 */
	do_cpuid(0, cpuid);

	rev1 = rdmsr(MSR_BIOS_SIGN);
	if (rev1 <= rev0)
		return (EEXIST);
	return (0);
}

static int
ucode_intel_verify(struct ucode_intel_header *hdr, size_t resid)
{
	uint32_t cksum, *data, size;
	int i;

	if (resid < sizeof(struct ucode_intel_header)) {
		log_err("truncated update header");
		return (1);
	}
	if ((uintptr_t)hdr % 16 != 0) {
		log_err("unaligned update header");
		return (1);
	}
	size = hdr->total_size;
	if (size == 0)
		size = UCODE_INTEL_DEFAULT_DATA_SIZE +
		    sizeof(struct ucode_intel_header);

	if (hdr->header_version != 1) {
		log_err("unexpected header version %u", hdr->header_version);
		return (1);
	}
	if (size % 16 != 0) {
		log_err("unexpected update size %u", hdr->total_size);
		return (1);
	}
	if (resid < size) {
		log_err("truncated update");
		return (1);
	}

	cksum = 0;
	data = (uint32_t *)hdr;
	for (i = 0; i < size / sizeof(uint32_t); i++)
		cksum += data[i];
	if (cksum != 0) {
		log_err("checksum failed");
		return (1);
	}
	return (0);
}

static void *
ucode_intel_match(uint8_t *data, size_t *len)
{
	struct ucode_intel_header *hdr;
	struct ucode_intel_extsig_table *table;
	struct ucode_intel_extsig *entry;
	uint64_t platformid;
	size_t resid;
	uint32_t data_size, flags, regs[4], sig, total_size;
	int i;

	do_cpuid(1, regs);
	sig = regs[0];

	platformid = rdmsr(MSR_IA32_PLATFORM_ID);
	flags = 1 << ((platformid >> 50) & 0x7);

	for (resid = *len; resid > 0; data += total_size, resid -= total_size) {
		hdr = (struct ucode_intel_header *)data;
		if (ucode_intel_verify(hdr, resid) != 0)
			break;

		data_size = hdr->data_size;
		total_size = hdr->total_size;
		if (data_size == 0)
			data_size = UCODE_INTEL_DEFAULT_DATA_SIZE;
		if (total_size == 0)
			total_size = UCODE_INTEL_DEFAULT_DATA_SIZE +
			    sizeof(struct ucode_intel_header);
		if (data_size > total_size + sizeof(struct ucode_intel_header))
			table = (struct ucode_intel_extsig_table *)
			    ((uint8_t *)(hdr + 1) + data_size);
		else
			table = NULL;

		if (hdr->processor_signature == sig) {
			if ((hdr->processor_flags & flags) != 0) {
				*len = data_size;
				return (hdr + 1);
			}
		} else if (table != NULL) {
			for (i = 0; i < table->signature_count; i++) {
				entry = &table->entries[i];
				if (entry->processor_signature == sig &&
				    (entry->processor_flags & flags) != 0) {
					*len = data_size;
					return (hdr + 1);
				}
			}
		}
	}
	return (NULL);
}

/*
 * Release any memory backing unused microcode blobs back to the system.
 * We copy the selected update and free the entire microcode file.
 */
static void
ucode_release(void *arg __unused)
{
	void *data;
	char *name, *type;
	caddr_t file;

	if (ucode_data == NULL)
		return;

	/* Use kmem_malloc() to guarantee 16 byte alignment. */
	data = (void *)kmem_malloc(kernel_arena, ucode_len, M_WAITOK | M_ZERO);
	memcpy(data, ucode_data, ucode_len);
	ucode_data = data;

restart:
	file = 0;
	for (;;) {
		file = preload_search_next_name(file);
		if (file == 0)
			break;
		type = (char *)preload_search_info(file, MODINFO_TYPE);
		if (type == NULL || strcmp(type, "cpu_microcode") != 0)
			continue;

		name = preload_search_info(file, MODINFO_NAME);
		preload_delete_name(name);
		goto restart;
	}
}
SYSINIT(ucode_release, SI_SUB_KMEM + 1, SI_ORDER_ANY, ucode_release, NULL);

void
ucode_load_ap(int cpu)
{

	KASSERT(cpu_info[cpu_apic_ids[cpu]].cpu_present,
	    ("cpu %d not present", cpu));

	if (ucode_data != NULL && !cpu_info[cpu_apic_ids[cpu]].cpu_hyperthread)
		(void)ucode_intel_load(ucode_data, false);
}

/*
 * Search for an applicable microcode update, and load it.  APs will load the
 * selected update once they come online.
 */
void
ucode_load_bsp(void)
{
	union {
		uint32_t regs[4];
		char vendor[13];
	} cpuid;
	struct ucode_ops *loader;
	uint8_t *addr, *data;
	char *type;
	caddr_t file;
	size_t len;
	int i;

	do_cpuid(0, cpuid.regs);
	cpuid.regs[0] = cpuid.regs[1];
	cpuid.regs[1] = cpuid.regs[3];
	cpuid.vendor[12] = '\0';
	for (i = 0, loader = NULL; i < nitems(loaders); i++)
		if (strcmp(cpuid.vendor, loaders[i].vendor) == 0) {
			loader = &loaders[i];
			break;
		}
	if (loader == NULL)
		return;

	file = 0;
	for (;;) {
		file = preload_search_next_name(file);
		if (file == 0)
			break;
		type = (char *)preload_search_info(file, MODINFO_TYPE);
		if (type == NULL || strcmp(type, "cpu_microcode") != 0)
			continue;

		addr = preload_fetch_addr(file);
		len = preload_fetch_size(file);
		data = loader->match(addr, &len);
		if (data != NULL) {
			ucode_data = data;
			ucode_len = len;
			break;
		}
	}
	if (ucode_data == NULL)
		log_err("no matching update found");
	else
		(void)loader->load(ucode_data, false);
}

/*
 * Reload microcode following an ACPI resume.
 */
void
ucode_reload(void)
{

	ucode_load_ap(PCPU_GET(cpuid));
}
