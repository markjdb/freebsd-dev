/*-
 * Copyright (c) 2017 Ruslan Bukin <br@bsdpad.com>
 * All rights reserved.
 *
 * This software was developed by BAE Systems, the University of Cambridge
 * Computer Laboratory, and Memorial University under DARPA/AFRL contract
 * FA8650-15-C-7558 ("CADETS"), as part of the DARPA Transparent Computing
 * (TC) research program.
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
#include <sys/event.h>
#include <sys/queue.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/time.h>
#include <sys/ttycom.h>
#include <sys/user.h>
#include <sys/wait.h>

#include <assert.h>
#include <curses.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <gelf.h>
#include <kvm.h>
#include <libgen.h>
#include <limits.h>
#include <math.h>
#include <pmc.h>
#include <pmclog.h>
#include <regex.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>
#include <gelf.h>
#include <inttypes.h>

#include <libpmcstat.h>

#include "pmctrace.h"
#include "pmctrace_pt.h"

#include <libipt/pt_cpu.h>
#include <libipt/pt_last_ip.h>
#include <libipt/pt_time.h>
#include <libipt/pt_compiler.h>
#include <libipt/intel-pt.h>

#define	PMCTRACE_PT_DEBUG
#undef	PMCTRACE_PT_DEBUG

#ifdef	PMCTRACE_PT_DEBUG
#define	dprintf(fmt, ...)	printf(fmt, ##__VA_ARGS__)
#else
#define	dprintf(fmt, ...)
#endif

static int ipt_flags;
#define	FLAG_BRANCH_TNT		(1 << 0)	/* Taken/Not Taken */

static struct pmcstat_symbol *
symbol_lookup(struct mtrace_data *mdata)
{
	struct pmcstat_image *image;
	struct pmcstat_symbol *sym;
	struct pmcstat_pcmap *map;
	uint64_t newpc;
	uint64_t ip;

	if (mdata->ip & (1UL << 47))
		ip = mdata->ip | 0xffffUL << 48;
	else
		ip = mdata->ip;

	map = pmcstat_process_find_map(mdata->pp, ip);
	if (map != NULL) {
		image = map->ppm_image;
		newpc = ip - (map->ppm_lowpc +
			(image->pi_vaddr - image->pi_start));
		sym = pmcstat_symbol_search(image, newpc);
		return (sym);
	} else
		dprintf("cpu%d: 0x%lx map not found\n", mdata->cpu, ip);

	return (NULL);
}

static int
print_tnt_payload(struct mtrace_data *mdata, uint64_t offset __unused,
    const struct pt_packet_tnt *packet)
{
	char payload[48];
	uint64_t tnt;
	uint8_t bits;
	char *begin;
	char *end;

	bits = packet->bit_size;
	tnt = packet->payload;
	begin = &payload[0];
	end = begin + bits;

	if (sizeof(payload) < bits)
		end = begin + sizeof(payload);

	for (; begin < end; ++begin, --bits)
		*begin = tnt & (1ull << (bits - 1)) ? '!' : '.';

	printf("cpu%d: TNT %s\n", mdata->cpu, payload);

	return (0);
}

static int
print_ip_payload(struct mtrace_data *mdata, uint64_t offset __unused,
    const struct pt_packet_ip *packet)
{
	struct pmcstat_symbol *sym;

	switch (packet->ipc) {
	case pt_ipc_suppressed:
		break;
	case pt_ipc_update_16:
		mdata->ip &= ~0xffffUL;
		mdata->ip |= (packet->ip & 0xffffUL);
		break;
	case pt_ipc_update_32:
		mdata->ip &= ~0xffffffffUL;
		mdata->ip |= (packet->ip & 0xffffffffUL);
		break;
	case pt_ipc_update_48:
		mdata->ip &= ~0xffffffffffffUL;
		mdata->ip |= (packet->ip & 0xffffffffffffUL);
		break;
	case pt_ipc_sext_48:
		mdata->ip &= ~0xffffffffffffUL;
		mdata->ip |= (packet->ip & 0xffffffffffffUL);
		symbol_lookup(mdata);
	case pt_ipc_full:
		mdata->ip = packet->ip;
		break;
	default:
		printf("unknown ipc: %d\n", packet->ipc);
		return (0);
	}

	sym = symbol_lookup(mdata);
	if (sym) {
		printf("cpu%d:  IP 0x%lx %s\n", mdata->cpu, mdata->ip,
		    pmcstat_string_unintern(sym->ps_name));
	} else
		dprintf("cpu%d: 0x%lx not found\n", mdata->cpu, mdata->ip);

	return (0);
}

static int
dump_packets(struct mtrace_data *mdata, struct pt_packet_decoder *decoder,
    const struct pt_config *config __unused)
{
	struct pt_packet packet;
	uint64_t offset;
	int error;

	dprintf("%s\n", __func__);

	while (1) {
		error = pt_pkt_get_offset(decoder, &offset);
		if (error < 0)
			errx(EX_SOFTWARE, "ERROR: can't get offset, err %d\n", error);

		error = pt_pkt_next(decoder, &packet, sizeof(packet));
		if (error < 0) {
			dprintf("%s: error %d\n", __func__, error);
			break;
		}

		switch (packet.type) {
		case ppt_invalid:
		case ppt_unknown:
		case ppt_pad:
		case ppt_psb:
		case ppt_psbend:
			break;
		case ppt_fup:
		case ppt_tip:
		case ppt_tip_pge:
		case ppt_tip_pgd:
			print_ip_payload(mdata, offset, &packet.payload.ip);
			break;
		case ppt_tnt_8:
		case ppt_tnt_64:
			if (ipt_flags & FLAG_BRANCH_TNT)
				print_tnt_payload(mdata, offset, &packet.payload.tnt);
			break;
		case ppt_mode:
		case ppt_pip:
		case ppt_vmcs:
		case ppt_cbr:
			break;
		case ppt_tsc:
			printf("cpu%d: TSC %ld\n", mdata->cpu, packet.payload.tsc.tsc);
			break;
		case ppt_tma:
			break;
		case ppt_mtc:
			printf("cpu%d: MTC %x\n", mdata->cpu, packet.payload.mtc.ctc);
			break;
		case ppt_cyc:
		case ppt_stop:
		case ppt_ovf:
		case ppt_mnt:
		case ppt_exstop:
		case ppt_mwait:
		case ppt_pwre:
		case ppt_pwrx:
		case ppt_ptw:
		default:
			break;
		}
	}

	return (0);
}

static int
ipt_process_chunk(struct mtrace_data *mdata, uint64_t base,
    uint64_t start, uint64_t end)
{
	struct pt_packet_decoder *decoder;
	struct pt_config config;
	int error;

	dprintf("%s\n", __func__);

	memset(&config, 0, sizeof(config));
	pt_config_init(&config);

	error = pt_cpu_read(&config.cpu);
	if (error < 0)
		errx(EX_SOFTWARE, "ERROR: pt_cpu_read failed, err %d\n", error);
	error = pt_cpu_errata(&config.errata, &config.cpu);
	if (error < 0)
		errx(EX_SOFTWARE, "ERROR: can't get errata, err %d\n", error);

	config.begin = (uint8_t *)(base + start);
	config.end = (uint8_t *)(base + end);

	dprintf("%s: begin %lx end %lx\n", __func__,
	    (uint64_t)config.begin, (uint64_t)config.end);

	decoder = pt_pkt_alloc_decoder(&config);
	if (decoder == NULL) {
		printf("Can't allocate decoder\n");
		return (-1);
	}

	error = pt_pkt_sync_set(decoder, 0ull);
	if (error < 0)
		errx(EX_SOFTWARE, "ERROR: sync_set failed, err %d\n", error);
	error = pt_pkt_sync_forward(decoder);
	if (error < 0 && error != -pte_eos)
		errx(EX_SOFTWARE, "ERROR: sync_forward failed, err %d\n", error);

	while (1) {
		error = dump_packets(mdata, decoder, &config);
		if (error == 0)
			break;

		error = pt_pkt_sync_forward(decoder);
		if (error < 0) {
			if (error == -pte_eos)
				return (0);
		}
	}

	return (0);
}

static int
ipt_process(struct trace_cpu *tc, struct pmcstat_process *pp,
    uint32_t cpu, uint32_t cycle, uint64_t offset)
{
	struct mtrace_data *mdata;

	mdata = &tc->mdata;
	mdata->pp = pp;

	dprintf("%s: cpu %d, cycle %d, offset %ld\n",
	    __func__, cpu, cycle, offset);

	if (offset == tc->offset)
		return (0);

	if (cycle == tc->cycle) {
		if (offset > tc->offset) {
			ipt_process_chunk(mdata, (uint64_t)tc->base, tc->offset, offset);
			tc->offset = offset;
		} else if (offset < tc->offset) {
			err(EXIT_FAILURE, "cpu%d: offset already processed %lx %lx",
			    cpu, offset, tc->offset);
		}
	} else if (cycle > tc->cycle) {
		if ((cycle - tc->cycle) > 1)
			err(EXIT_FAILURE, "cpu%d: trace buffers fills up faster than"
			    " we can process it (%d/%d). Consider setting trace filters",
			    cpu, cycle, tc->cycle);
		ipt_process_chunk(mdata, (uint64_t)tc->base, tc->offset, tc->bufsize);
		tc->offset = 0;
		tc->cycle += 1;
		ipt_process_chunk(mdata, (uint64_t)tc->base, tc->offset, offset);
		tc->offset = offset;
	}

	return (0);
}

static int
ipt_option(int option)
{

	switch (option) {
	case 't':
		/* Decode 'Taken/Not_Taken branch' packet. */
		ipt_flags |= FLAG_BRANCH_TNT;
		break;
	default:
		break;
	}

	return (0);
}

struct trace_dev_methods ipt_methods = {
	.process = ipt_process,
	.option = ipt_option,
};
