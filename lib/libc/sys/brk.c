/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2018 Mark Johnston <markj@FreeBSD.org>
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

#include <sys/types.h>
#include <sys/syscall.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>

void *__sys_break(char *nsize);

static const void *curbrk, *minbrk;
static int curbrk_initted;

static int
initbrk(void)
{

	if (!curbrk_initted) {
		curbrk = minbrk = __sys_break(NULL);
		if (curbrk == (void *)-1)
			return (-1);
		curbrk_initted = 1;
	}
	return (0);
}

static void *
mvbrk(const void *addr)
{
	void *newbrk;

	newbrk = __sys_break(__DECONST(void *, addr));
	if (newbrk == (void *)-1)
		return (newbrk);
	curbrk = addr;
	return (__DECONST(void *, curbrk));
}

int
brk(const void *addr)
{

	if (initbrk() == -1)
		return (-1);
	if ((uintptr_t)addr < (uintptr_t)minbrk)
		addr = minbrk;
	return (mvbrk(addr) == (void *)-1 ? -1 : 0);
}

int
_brk(const void *addr)
{

	if (initbrk() == -1)
		return (-1);
	if ((uintptr_t)addr < (uintptr_t)minbrk) {
		/* Emulate legacy error handling in the syscall. */
		errno = EINVAL;
		return (-1);
	}
	return (mvbrk(addr) == (void *)-1 ? -1 : 0);
}

void *
sbrk(intptr_t incr)
{

	if (initbrk() == -1)
		return ((void *)-1);
	if ((incr > 0 && (uintptr_t)curbrk + incr < (uintptr_t)curbrk) ||
	    (incr < 0 && (uintptr_t)curbrk + incr > (uintptr_t)curbrk)) {
		/* Emulate legacy error handling in the syscall. */
		errno = EINVAL;
		return ((void *)-1);
	}
	return (mvbrk((void *)((uintptr_t)curbrk + incr)));
}
