#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/queue.h>
#include <sys/sdt.h>

#include <sys/dtrace.h>

#include <machine/frame.h>

#include "sdt.h"

#define	AMD64_BP	0xcc
#define	AMD64_NOP	0x90

int
sdt_invop(uintptr_t addr, uintptr_t *stack, uintptr_t rval)
{
	struct sdt_siterec *rec;
	struct trapframe *tf;

	rec = sdt_lookup_site(addr);
	if (rec == NULL)
		return (0);

	tf = (struct trapframe *)(stack + 1);
	dtrace_probe(rec->id, tf->tf_rdi, tf->tf_rsi, tf->tf_rdx, tf->tf_rcx,
	    tf->tf_r8);
	return (DTRACE_INVOP_NOP);
}

void
sdt_probe_enable(struct sdt_probedesc *desc)
{
	uint8_t *callsite;

	callsite = (uint8_t *)desc->spd_offset;
	callsite[0] = AMD64_BP;
}

void
sdt_probe_disable(struct sdt_probedesc *desc)
{
	uint8_t *callsite;

	callsite = (uint8_t *)desc->spd_offset;
	callsite[0] = AMD64_NOP;
}
