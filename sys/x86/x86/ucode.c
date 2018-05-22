/* XXX stas copyright */

#include <sys/param.h>

#include <sys/cpuset.h>
#include <sys/kernel.h>
#include <sys/linker.h>
#include <sys/malloc.h>
#include <sys/pcpu.h>
#include <sys/smp.h>
#include <sys/systm.h>

#include <machine/cpufunc.h>
#include <x86/ucode.h>

#include <vm/vm.h>
#include <vm/vm_extern.h>
#include <vm/vm_kern.h>

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
CTASSERT(sizeof(struct ucode_intel_header) == 48);

static void *ucode_data;

int
ucode_intel_load(void *data)
{
	uint64_t rev0, rev1;
	uint32_t cpuid[4];

	KASSERT((uintptr_t)data % 16 == 0, ("microcode data is unaligned"));

	rev0 = rdmsr(MSR_BIOS_SIGN);

	/*
	 * Perform update.  Flush caches first to work around seemingly
	 * undocumented errata applying to some Broadwell CPUs.
	 */
	wbinvd();
	wrmsr_safe(MSR_BIOS_UPDT_TRIG, (uint64_t)(uintptr_t)data);
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

int
ucode_intel_verify(uint32_t *data, size_t len)
{
	struct ucode_intel_header *hdr;
	uint32_t cksum, *p;

	if (len < sizeof(struct ucode_intel_header)) {
		printf("ucode_intel_verify: truncated mircocode file\n");
		return (1);
	}

	hdr = (struct ucode_intel_header *)data;

	cksum = 0;
	for (p = data; p != data + hdr->total_size / sizeof(uint32_t); p++)
		cksum += *p;
	if (cksum != 0) {
		printf("ucode_load_bsp: checksum failed\n");
		return (1);
	}
	return (0);
}

void
ucode_load_ap(void)
{

	if (CPU_ISSET(curcpu, &logical_cpus_mask))
		return;

	ucode_intel_load(ucode_data);
}

static void
ucode_intel_load_bsp(void *arg __unused)
{
	uint32_t *data;
	caddr_t file;
	size_t len;

	file = preload_search_by_type("cpu_ucode");
	if (file == 0)
		return;

	data = preload_fetch_addr(file);
	len = preload_fetch_size(file);

	/* Intel microcode must be 16-byte aligned. XXX bad wording */
	ucode_data = (void *)kmem_malloc(kernel_arena, len, M_WAITOK | M_ZERO);
	memcpy(ucode_data, data, len);

	if (ucode_intel_verify(ucode_data, len) != 0)
		goto out;

	ucode_intel_load(ucode_data);

out:
	kmem_free(kernel_arena, (uintptr_t)ucode_data, len);
	ucode_data = NULL;
}
SYSINIT(ucode_load, SI_SUB_KMEM + 1, SI_ORDER_ANY, ucode_intel_load_bsp, NULL);
