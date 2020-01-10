/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2020 The FreeBSD Foundation
 *
 * This software was developed by Mark Johnston under sponsorship from
 * the FreeBSD Foundation.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the distribution.
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
#include <sys/kernel.h>
#include <sys/stdint.h>

#include <machine/armreg.h>
#include <machine/ifunc.h>

static bool
lseimpl(void)
{
	uint64_t id_aa64isar0;

	id_aa64isar0 = READ_SPECIALREG(id_aa64isar0_el1);
	return (ID_AA64ISAR0_Atomic_VAL(id_aa64isar0) ==
	    ID_AA64ISAR0_Atomic_IMPL);
}

#define	_ATOMIC_FCMPSET_IMPL(w, q, bar, s, a, l)			\
static int								\
atomic_fcmpset_##bar##w##_llsc(volatile uint##w##_t *p,			\
    uint##w##_t *cmpval, uint##w##_t newval)				\
{									\
	int res;							\
	uint##w##_t _cmpval, tmp;					\
									\
	_cmpval = *cmpval;						\
	__asm __volatile(						\
	    "1: mov	%w1, #1\n"					\
	    "   ld"#a"xr"#s" %"#q"0, [%2]\n"				\
	    "   cmp	%"#q"0, %"#q"3\n"				\
	    "   b.ne	2f\n"						\
	    "	st"#l"xr"#s" %w1, %"#q"4, [%2]\n"			\
	    "2:"							\
	    : "=&r" (tmp), "=&r" (res)					\
	    : "r" (p), "r" (_cmpval), "r" (newval)			\
	    : "cc", "memory");						\
	*cmpval = tmp;							\
	return (!res);							\
}									\
									\
static int								\
atomic_fcmpset_##bar##w##_lse(volatile uint##w##_t *p,			\
    uint##w##_t *cmpval, uint##w##_t newval)				\
{									\
	int res;							\
	uint##w##_t _cmpval, tmp;					\
									\
	_cmpval = tmp = *cmpval;					\
	__asm __volatile(						\
	    ".arch_extension lse\n"					\
	    "cas"#a#l#s" %"#q"1, %"#q"4, [%3]\n"			\
	    "cmp	%"#q"1, %"#q"2\n"				\
	    "cset	%w0, eq\n"					\
	    ".arch_extension nolse\n"					\
	    : "=r" (res), "+&r" (tmp)					\
	    : "r" (_cmpval), "r" (p), "r" (newval)			\
	    : "cc", "memory");						\
	*cmpval = tmp;							\
	return (res);							\
}

#define	_ATOMIC_FCMPSET_IFUNC(w, bar)					\
DEFINE_IFUNC(, int, atomic_fcmpset_##bar##w,				\
    (volatile uint##w##_t *, uint##w##_t *, uint##w##_t))		\
{									\
	if (lseimpl())							\
		return (atomic_fcmpset_##bar##w##_lse);			\
	else								\
		return (atomic_fcmpset_##bar##w##_llsc);		\
}

#define	ATOMIC_FCMPSET(w, q, s)						\
	_ATOMIC_FCMPSET_IMPL(w, q, , s, ,)				\
	_ATOMIC_FCMPSET_IFUNC(w, )					\
	_ATOMIC_FCMPSET_IMPL(w, q, acq_, s, a,)				\
	_ATOMIC_FCMPSET_IFUNC(w, acq_)					\
	_ATOMIC_FCMPSET_IMPL(w, q, rel_, s, , l)			\
	_ATOMIC_FCMPSET_IFUNC(w, rel_)

ATOMIC_FCMPSET(8, w, b)
ATOMIC_FCMPSET(16, w, h)
ATOMIC_FCMPSET(32, w,)
ATOMIC_FCMPSET(64, ,)
