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
	struct sdt_invoprec *rec;
	struct trapframe *tf;

	rec = sdt_lookup_site(addr);
	if (rec == NULL)
		return (0);

	tf = (struct trapframe *)(stack + 1);
	dtrace_probe(rec->sr_id, tf->tf_rdi, tf->tf_rsi, tf->tf_rdx, tf->tf_rcx,
	    tf->tf_r8);
	return (DTRACE_INVOP_NOP);
}

void
sdt_probe_enable(struct sdt_probedesc *desc)
{
	struct sdt_probe *probe;
	uint8_t *callsite;

	if (desc->spd_offset == 0) {
		probe = desc->li.spd_probe;
		MPASS(strlen(probe->func) > 0);
		SLIST_FOREACH(desc, &probe->site_list, li.spd_entry) {
			callsite = (uint8_t *)desc->spd_offset;
			callsite[0] = AMD64_BP;
		}
	} else {
		callsite = (uint8_t *)desc->spd_offset;
		callsite[0] = AMD64_BP;
	}
}

void
sdt_probe_disable(struct sdt_probedesc *desc)
{
	struct sdt_probe *probe;
	uint8_t *callsite;

	if (desc->spd_offset == 0) {
		probe = desc->li.spd_probe;
		MPASS(strlen(probe->func) > 0);
		SLIST_FOREACH(desc, &probe->site_list, li.spd_entry) {
			callsite = (uint8_t *)desc->spd_offset;
			callsite[0] = AMD64_NOP;
		}
	} else {
		callsite = (uint8_t *)desc->spd_offset;
		callsite[0] = AMD64_NOP;
	}
}
