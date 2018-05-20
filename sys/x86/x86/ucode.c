#include <sys/kernel.h>
#include <sys/linker.h>

struct ucode_header {
	uint32_t	header_version;
	int32_t		update_revision;
	uint32_t	dat;
	uint32_t	processor_signature;
	uint32_t	checksum;
	uint32_t	loader_revision;
	uint32_t	processor_flags;
	uint32_t	data_size;
	uint32_t	total_size;
	uint32_t	reserved[3];
};
CTASSERT(sizeof(struct ucode_header) == 48);

void
ucode_update_intel(int cpu, uint8_t *data)
{

	/* XXX curthread must be bound, data must be 16-byte aligned */
}

void
ucode_load(int cpu)
{
	uint8_t *data;
	uint64_t rev0, rev1;
	uint32_t cpuid[4];
	caddr_t ucodefile;
	size_t len;

	ucodefile = preload_search_by_type("cpu_ucode");
	if (ucodefile == 0)
		return;

	data = preload_fetch_addr(ucodefile);
	len = preload_fetch_size(ucodefile);

	if ((uintptr_t)data % 16 != 0)
		/* XXX */
		printf("ucode data is unaligned\n");

	td = curthread;

	rdmsr(MSR_BIOS_SIGN, (uint64_t)(uintptr_t)&rev0);

	wrmsr(MSR_BIOS_UPDT_TRIG, (uint64_t)(uintptr_t)data);

	wrmsr(MSR_BIOS_SIGN, 0);
	do_cpuid(0, cpuid);
	rdmsr(MSR_BIOS_SIGN, (uint64_t)(uintptr_t)&rev1);
}

static void
ucode_load_bsp(void *arg __unused)
{

	KASSERT(curcpu == CPU_FIRST(), ("not running on BSP"));
}
SYSINIT(ucode_load, SI_SUB_KMEM + 1, SI_ORDER_ANY, ucode_load_bsp, NULL);
