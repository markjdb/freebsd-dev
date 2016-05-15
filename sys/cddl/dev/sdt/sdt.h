/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 *
 * Copyright 2016 Mark Johnston <markj@FreeBSD.org>
 */

#ifndef _SDT_H_
#define	_SDT_H_

struct trapframe;
struct sdt_probedesc;

/*
 * An entry in the SDT hash table. These records exist one-to-one with SDT probe
 * descriptors, but are split into a separate struct to avoid bloat: descriptors
 * are created at compile-time and always reside in memory. Note that multiple
 * records may have the same id if the probe definition hard-codes a function
 * name or a probe has multiple sites within a function.
 */
struct sdt_invoprec {
	struct sdt_probedesc	*sr_desc;
	LIST_ENTRY(sdt_invoprec) sr_next;
	dtrace_id_t		sr_id;
};

struct sdt_invoprec *sdt_lookup_site(uint64_t);
int	sdt_invop(uintptr_t, struct trapframe *, uintptr_t);
void	sdt_probe_enable(struct sdt_probedesc *);
void	sdt_probe_disable(struct sdt_probedesc *);

#endif /* _SDT_H_ */
