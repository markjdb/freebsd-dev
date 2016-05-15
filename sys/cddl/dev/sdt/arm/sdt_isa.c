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

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/queue.h>
#include <sys/sdt.h>

#include <sys/dtrace.h>

#include <machine/frame.h>

#include "sdt.h"

int
sdt_invop(uintptr_t addr, struct trapframe *frame, uintptr_t rval)
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
