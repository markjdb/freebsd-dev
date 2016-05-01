#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/queue.h>
#include <sys/sdt.h>

#include <sys/dtrace.h>

#include <machine/frame.h>

#include "sdt.h"

int
sdt_invop(uintptr_t addr, uintptr_t *stack, uintptr_t rval)
{

	return (DTRACE_INVOP_NOP);
}

void
sdt_probe_enable(struct sdt_probedesc *desc __unused)
{
}

void
sdt_probe_disable(struct sdt_probedesc *desc)
{
}
