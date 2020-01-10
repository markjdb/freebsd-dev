/*-
 * Copyright (c) 2013 Andrew Turner <andrew@freebsd.org>
 * All rights reserved.
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
 *
 * $FreeBSD$
 */

#ifndef	_MACHINE_ATOMIC_H_
#define	_MACHINE_ATOMIC_H_

#define	isb()		__asm __volatile("isb" : : : "memory")

/*
 * Options for DMB and DSB:
 *	oshld	Outer Shareable, load
 *	oshst	Outer Shareable, store
 *	osh	Outer Shareable, all
 *	nshld	Non-shareable, load
 *	nshst	Non-shareable, store
 *	nsh	Non-shareable, all
 *	ishld	Inner Shareable, load
 *	ishst	Inner Shareable, store
 *	ish	Inner Shareable, all
 *	ld	Full system, load
 *	st	Full system, store
 *	sy	Full system, all
 */
#define	dsb(opt)	__asm __volatile("dsb " __STRING(opt) : : : "memory")
#define	dmb(opt)	__asm __volatile("dmb " __STRING(opt) : : : "memory")

#define	mb()	dmb(sy)	/* Full system memory barrier all */
#define	wmb()	dmb(st)	/* Full system memory barrier store */
#define	rmb()	dmb(ld)	/* Full system memory barrier load */

#if defined(KCSAN) && !defined(KCSAN_RUNTIME)
#include <sys/_cscan_atomic.h>
#else

#include <sys/atomic_common.h>

#define	ATOMIC_OP(op, asm_op, mv, bar, a, l)				\
static __inline void							\
atomic_##op##_##bar##8(volatile uint8_t *p, uint8_t val)		\
{									\
	uint8_t tmp;							\
									\
	__asm __volatile(						\
	    #mv " %w0, %w2                   \n"			\
	    "ld"#asm_op#a#l"b %w0, %w0, [%1] \n"			\
	    : "+&r"(tmp)							\
	    : "r" (p), "r" (val)					\
	    : "memory"							\
	);								\
}									\
									\
static __inline void							\
atomic_##op##_##bar##16(volatile uint16_t *p, uint16_t val)		\
{									\
	uint16_t tmp;							\
									\
	__asm __volatile(						\
	    #mv " %w0, %w2                   \n"			\
	    "ld"#asm_op#a#l"h %w0, %w0, [%1] \n"			\
	    : "+&r"(tmp)							\
	    : "r" (p), "r" (val)					\
	    : "memory"							\
	);								\
}									\
									\
static __inline void							\
atomic_##op##_##bar##32(volatile uint32_t *p, uint32_t val)		\
{									\
	uint32_t tmp;							\
									\
	__asm __volatile(						\
	    #mv " %w0, %w2                     \n"			\
	    "ld"#asm_op#a#l" %w0, %w0, [%1]    \n"			\
	    : "+&r"(tmp)							\
	    : "r" (p), "r" (val)					\
	    : "memory"							\
	);								\
}									\
									\
static __inline void							\
atomic_##op##_##bar##64(volatile uint64_t *p, uint64_t val)		\
{									\
	uint64_t tmp;							\
									\
	__asm __volatile(						\
	    #mv " %0, %2                   \n"				\
	    "ld"#asm_op#a#l" %0, %0, [%1] \n"				\
	    : "+&r"(tmp) 						\
	    : "r" (p), "r" (val)					\
	    : "memory"							\
	);								\
}

#define	ATOMIC(op, asm_op, mv)						\
    ATOMIC_OP(op, asm_op, mv,     ,  ,  )				\
    ATOMIC_OP(op, asm_op, mv, acq_, a,  )				\
    ATOMIC_OP(op, asm_op, mv, rel_,  , l)				\

ATOMIC(add,      add, mov)
ATOMIC(clear,    clr, mov)
ATOMIC(set,      set, mov)
ATOMIC(subtract, add, neg)

#define	ATOMIC_FCMPSET(w)						\
	int atomic_fcmpset_##w(volatile uint##w##_t *p,			\
	    uint##w##_t *cmpval, uint##w##_t newval);			\
	int atomic_fcmpset_acq_##w(volatile uint##w##_t *p,		\
	    uint##w##_t *cmpval, uint##w##_t newval);			\
	int atomic_fcmpset_rel_##w(volatile uint##w##_t *p,		\
	    uint##w##_t *cmpval, uint##w##_t newval)

ATOMIC_FCMPSET(8);
ATOMIC_FCMPSET(16);
ATOMIC_FCMPSET(32);
ATOMIC_FCMPSET(64);
#if 0
#define	ATOMIC_FCMPSET(bar, a, l)					\
static __inline int							\
atomic_fcmpset_##bar##8(volatile uint8_t *p, uint8_t *cmpval,		\
    uint8_t newval)		 					\
{									\
	uint8_t tmp = *cmpval;						\
	uint8_t _cmpval = *cmpval;					\
	int res;							\
									\
	__asm __volatile(						\
	    "cas"#a#l"b	%w1, %w4, [%3] \n"				\
	    "cmp 	%w1, %w2       \n"				\
	    "cset	%w0, eq	     \n"				\
	    : "=r"(res), "+&r" (tmp)					\
	    : "r"(_cmpval), "r" (p), "r" (newval)			\
	    : "cc", "memory"						\
	);								\
	*cmpval = tmp;							\
									\
	return (res);							\
}									\
									\
static __inline int							\
atomic_fcmpset_##bar##16(volatile uint16_t *p, uint16_t *cmpval,	\
    uint16_t newval)		 					\
{									\
	uint16_t tmp = *cmpval;						\
	uint16_t _cmpval = *cmpval;					\
	int res;							\
									\
	__asm __volatile(						\
	    "cas"#a#l"h	%w1, %w4, [%3] \n"				\
	    "cmp 	%w1, %w2       \n"				\
	    "cset	%w0, eq	     \n"				\
	    : "=r"(res), "+&r" (tmp)					\
	    : "r"(_cmpval), "r" (p), "r" (newval)			\
	    : "cc", "memory"						\
	);								\
	*cmpval = tmp;							\
									\
	return (res);							\
}									\
									\
static __inline int							\
atomic_fcmpset_##bar##32(volatile uint32_t *p, uint32_t *cmpval,	\
    uint32_t newval)		 					\
{									\
	uint32_t tmp = *cmpval;						\
	uint32_t _cmpval = *cmpval;					\
	int res = 0;							\
									\
	__asm __volatile(						\
	    "cas"#a#l"	%w1, %w4, [%3] \n"				\
	    "cmp 	%w1, %w2       \n"				\
	    "cset	%w0, eq	     \n"				\
	    : "=r"(res), "+&r" (tmp)					\
	    : "r"(_cmpval), "r" (p), "r" (newval)			\
	    : "cc", "memory"						\
	);								\
									\
	*cmpval = tmp;							\
									\
	return (res);							\
}									\
									\
static __inline int							\
atomic_fcmpset_##bar##64(volatile uint64_t *p, uint64_t *cmpval,	\
    uint64_t newval)							\
{									\
	uint64_t tmp = *cmpval;						\
	uint64_t _cmpval = *cmpval;					\
	int res = 0;							\
									\
	__asm __volatile(						\
	    "cas"#a#l"	%1, %4, [%3] \n"				\
	    "cmp 	%1, %2       \n"				\
	    "cset	%w0, eq	     \n"				\
	    : "=r"(res), "+&r" (tmp)					\
	    : "r"(_cmpval), "r" (p), "r" (newval)			\
	    : "cc", "memory"						\
	);								\
									\
	*cmpval = tmp;							\
									\
	return (res);							\
}

ATOMIC_FCMPSET(    ,  , )
ATOMIC_FCMPSET(acq_, a, )
ATOMIC_FCMPSET(rel_,  ,l)

#undef ATOMIC_FCMPSET
#endif

#define	ATOMIC_CMPSET(bar, a, l)					\
static __inline int							\
atomic_cmpset_##bar##8(volatile uint8_t *p, uint8_t cmpval,		\
    uint8_t newval)							\
{									\
	uint8_t oldval = cmpval;					\
	int res = 0;							\
									\
	__asm __volatile(						\
	    "cas"#a#l"b	%w1, %w4, [%3] \n"				\
	    "cmp 	%w1, %w2       \n"				\
	    "cset	%w0, eq	       \n"				\
	    : "=r"(res), "+&r" (cmpval)					\
	    : "r"(oldval), "r" (p), "r" (newval)			\
	    : "cc", "memory"						\
	);								\
									\
	return (res);							\
}									\
									\
static __inline int							\
atomic_cmpset_##bar##16(volatile uint16_t *p, uint16_t cmpval,		\
    uint16_t newval)							\
{									\
	uint16_t oldval = cmpval;					\
	int res = 0;							\
									\
	__asm __volatile(						\
	    "cas"#a#l"h	%w1, %w4, [%3] \n"				\
	    "cmp 	%w1, %w2       \n"				\
	    "cset	%w0, eq	       \n"				\
	    : "=r"(res), "+&r" (cmpval)					\
	    : "r"(oldval), "r" (p), "r" (newval)			\
	    : "cc", "memory"						\
	);								\
									\
	return (res);							\
}									\
									\
static __inline int							\
atomic_cmpset_##bar##32(volatile uint32_t *p, uint32_t cmpval,		\
    uint32_t newval)							\
{									\
	uint32_t oldval = cmpval;					\
	int res = 0;							\
									\
	__asm __volatile(						\
	    "cas"#a#l"	%w1, %w4, [%3] \n"				\
	    "cmp 	%w1, %w2       \n"				\
	    "cset	%w0, eq	       \n"				\
	    : "=r"(res), "+&r" (cmpval)					\
	    : "r"(oldval), "r" (p), "r" (newval)			\
	    : "cc", "memory"						\
	);								\
									\
	return (res);							\
}									\
									\
static __inline int							\
atomic_cmpset_##bar##64(volatile uint64_t *p, uint64_t cmpval,		\
    uint64_t newval)							\
{									\
	uint64_t oldval = cmpval;					\
	int res = 0;							\
									\
	__asm __volatile(						\
	    "cas"#a#l"	%1, %4, [%3] \n"				\
	    "cmp 	%1, %2       \n"				\
	    "cset	%w0, eq	     \n"				\
	    : "=r"(res), "+&r" (cmpval)					\
	    : "r"(oldval), "r" (p), "r" (newval)			\
	    : "cc", "memory"						\
	);								\
									\
	return (res);							\
}

ATOMIC_CMPSET(    ,  , )
ATOMIC_CMPSET(acq_,a, )
ATOMIC_CMPSET(rel_,  ,l)

static __inline uint32_t
atomic_fetchadd_32(volatile uint32_t *p, uint32_t val)
{
	uint32_t ret;

	__asm __volatile(
	    "ldadd	%w2, %w0, [%1]  \n"
	    : "=r"(ret)
	    : "r" (p), "r" (val)
	    : "memory"
	);

	return (ret);
}

static __inline uint64_t
atomic_fetchadd_64(volatile uint64_t *p, uint64_t val)
{
	uint64_t ret;

	__asm __volatile(
	    "ldadd	%2, %0, [%1]  \n"
	    : "=r"(ret)
	    : "r" (p), "r" (val)
	    : "memory"
	);

	return (ret);
}
static __inline uint32_t
atomic_swap_32(volatile uint32_t *p, uint32_t val)
{
	uint32_t ret;

	__asm __volatile(
	    "swp	%w2, %w0, [%1]  \n"
	    : "=r"(ret)
	    : "r" (p), "r" (val)
	    : "memory"
	);

	return (ret);
}

static __inline uint64_t
atomic_swap_64(volatile uint64_t *p, uint64_t val)
{
	uint64_t ret;

	__asm __volatile(
	    "swp	%2, %0, [%1]  \n"
	    : "=r"(ret)
	    : "r" (p), "r" (val)
	    : "memory"
	);

	return (ret);
}

static __inline uint32_t
atomic_readandclear_32(volatile uint32_t *p)
{
	return atomic_swap_32(p, 0);
}

static __inline uint64_t
atomic_readandclear_64(volatile uint64_t *p)
{
	return atomic_swap_64(p, 0);
}

static __inline uint8_t
atomic_load_acq_8(volatile uint8_t *p)
{
	uint8_t ret;

	__asm __volatile(
	    "ldarb	%w0, [%1] \n"
	    : "=&r" (ret)
	    : "r" (p)
	    : "memory");

	return (ret);
}

static __inline uint16_t
atomic_load_acq_16(volatile uint16_t *p)
{
	uint16_t ret;

	__asm __volatile(
	    "ldarh	%w0, [%1] \n"
	    : "=&r" (ret)
	    : "r" (p)
	    : "memory");

	return (ret);
}

static __inline uint32_t
atomic_load_acq_32(volatile uint32_t *p)
{
	uint32_t ret;

	__asm __volatile(
	    "ldar	%w0, [%1] \n"
	    : "=&r" (ret)
	    : "r" (p)
	    : "memory");

	return (ret);
}

static __inline uint64_t
atomic_load_acq_64(volatile uint64_t *p)
{
	uint64_t ret;

	__asm __volatile(
	    "ldar	%0, [%1] \n"
	    : "=&r" (ret)
	    : "r" (p)
	    : "memory");

	return (ret);
}

static __inline void
atomic_store_rel_8(volatile uint8_t *p, uint8_t val)
{

	__asm __volatile(
	    "stlrb	%w0, [%1] \n"
	    :
	    : "r" (val), "r" (p)
	    : "memory");
}

static __inline void
atomic_store_rel_16(volatile uint16_t *p, uint16_t val)
{

	__asm __volatile(
	    "stlrh	%w0, [%1] \n"
	    :
	    : "r" (val), "r" (p)
	    : "memory");
}

static __inline void
atomic_store_rel_32(volatile uint32_t *p, uint32_t val)
{

	__asm __volatile(
	    "stlr	%w0, [%1] \n"
	    :
	    : "r" (val), "r" (p)
	    : "memory");
}

static __inline void
atomic_store_rel_64(volatile uint64_t *p, uint64_t val)
{

	__asm __volatile(
	    "stlr	%0, [%1] \n"
	    :
	    : "r" (val), "r" (p)
	    : "memory");
}

static __inline int
atomic_testandclear_32(volatile uint32_t *p, u_int val)
{
	uint32_t mask, old, tmp;
	int res;

	mask = 1u << (val & 0x1f);
	__asm __volatile(
	    "1: ldxr	%w2, [%3]      \n"
	    "   bic	%w0, %w2, %w4  \n"
	    "   stxr	%w1, %w0, [%3] \n"
            "   cbnz	%w1, 1b        \n"
	    : "=&r"(tmp), "=&r"(res), "=&r"(old)
	    : "r" (p), "r" (mask)
	    : "memory"
	);

	return ((old & mask) != 0);
}

static __inline int
atomic_testandclear_64(volatile uint64_t *p, u_int val)
{
	uint64_t mask, old, tmp;
	int res;

	mask = 1ul << (val & 0x1f);
	__asm __volatile(
	    "1: ldxr	%2, [%3]       \n"
	    "   bic	%0, %2, %4     \n"
	    "   stxr	%w1, %0, [%3]  \n"
            "   cbnz	%w1, 1b        \n"
	    : "=&r"(tmp), "=&r"(res), "=&r"(old)
	    : "r" (p), "r" (mask)
	    : "memory"
	);

	return ((old & mask) != 0);
}

static __inline int
atomic_testandset_32(volatile uint32_t *p, u_int val)
{
	uint32_t mask, old, tmp;
	int res;

	mask = 1u << (val & 0x1f);
	__asm __volatile(
	    "1: ldxr	%w2, [%3]      \n"
	    "   orr	%w0, %w2, %w4  \n"
	    "   stxr	%w1, %w0, [%3] \n"
            "   cbnz	%w1, 1b        \n"
	    : "=&r"(tmp), "=&r"(res), "=&r"(old)
	    : "r" (p), "r" (mask)
	    : "memory"
	);

	return ((old & mask) != 0);
}

static __inline int
atomic_testandset_64(volatile uint64_t *p, u_int val)
{
	uint64_t mask, old, tmp;
	int res;

	mask = 1ul << (val & 0x1f);
	__asm __volatile(
	    "1: ldxr	%2, [%3]       \n"
	    "   orr	%0, %2, %4     \n"
	    "   stxr	%w1, %0, [%3]  \n"
            "   cbnz	%w1, 1b        \n"
	    : "=&r"(tmp), "=&r"(res), "=&r"(old)
	    : "r" (p), "r" (mask)
	    : "memory"
	);

	return ((old & mask) != 0);
}


#define	atomic_add_int			atomic_add_32
#define	atomic_fcmpset_int		atomic_fcmpset_32
#define	atomic_clear_int		atomic_clear_32
#define	atomic_cmpset_int		atomic_cmpset_32
#define	atomic_fetchadd_int		atomic_fetchadd_32
#define	atomic_readandclear_int		atomic_readandclear_32
#define	atomic_set_int			atomic_set_32
#define	atomic_swap_int			atomic_swap_32
#define	atomic_subtract_int		atomic_subtract_32
#define	atomic_testandclear_int		atomic_testandclear_32
#define	atomic_testandset_int		atomic_testandset_32

#define	atomic_add_acq_int		atomic_add_acq_32
#define	atomic_fcmpset_acq_int		atomic_fcmpset_acq_32
#define	atomic_clear_acq_int		atomic_clear_acq_32
#define	atomic_cmpset_acq_int		atomic_cmpset_acq_32
#define	atomic_load_acq_int		atomic_load_acq_32
#define	atomic_set_acq_int		atomic_set_acq_32
#define	atomic_subtract_acq_int		atomic_subtract_acq_32

#define	atomic_add_rel_int		atomic_add_rel_32
#define	atomic_fcmpset_rel_int		atomic_fcmpset_rel_32
#define	atomic_clear_rel_int		atomic_clear_rel_32
#define	atomic_cmpset_rel_int		atomic_cmpset_rel_32
#define	atomic_set_rel_int		atomic_set_rel_32
#define	atomic_subtract_rel_int		atomic_subtract_rel_32
#define	atomic_store_rel_int		atomic_store_rel_32

#define	atomic_add_long			atomic_add_64
#define	atomic_fcmpset_long		atomic_fcmpset_64
#define	atomic_clear_long		atomic_clear_64
#define	atomic_cmpset_long		atomic_cmpset_64
#define	atomic_fetchadd_long		atomic_fetchadd_64
#define	atomic_readandclear_long	atomic_readandclear_64
#define	atomic_set_long			atomic_set_64
#define	atomic_swap_long		atomic_swap_64
#define	atomic_subtract_long		atomic_subtract_64
#define	atomic_testandclear_long	atomic_testandclear_64
#define	atomic_testandset_long		atomic_testandset_64

#define	atomic_add_ptr			atomic_add_64
#define	atomic_fcmpset_ptr		atomic_fcmpset_64
#define	atomic_clear_ptr		atomic_clear_64
#define	atomic_cmpset_ptr		atomic_cmpset_64
#define	atomic_fetchadd_ptr		atomic_fetchadd_64
#define	atomic_readandclear_ptr		atomic_readandclear_64
#define	atomic_set_ptr			atomic_set_64
#define	atomic_swap_ptr			atomic_swap_64
#define	atomic_subtract_ptr		atomic_subtract_64

#define	atomic_add_acq_long		atomic_add_acq_64
#define	atomic_fcmpset_acq_long		atomic_fcmpset_acq_64
#define	atomic_clear_acq_long		atomic_clear_acq_64
#define	atomic_cmpset_acq_long		atomic_cmpset_acq_64
#define	atomic_load_acq_long		atomic_load_acq_64
#define	atomic_set_acq_long		atomic_set_acq_64
#define	atomic_subtract_acq_long	atomic_subtract_acq_64

#define	atomic_add_acq_ptr		atomic_add_acq_64
#define	atomic_fcmpset_acq_ptr		atomic_fcmpset_acq_64
#define	atomic_clear_acq_ptr		atomic_clear_acq_64
#define	atomic_cmpset_acq_ptr		atomic_cmpset_acq_64
#define	atomic_load_acq_ptr		atomic_load_acq_64
#define	atomic_set_acq_ptr		atomic_set_acq_64
#define	atomic_subtract_acq_ptr		atomic_subtract_acq_64

#define	atomic_add_rel_long		atomic_add_rel_64
#define	atomic_fcmpset_rel_long		atomic_fcmpset_rel_64
#define	atomic_clear_rel_long		atomic_clear_rel_64
#define	atomic_cmpset_rel_long		atomic_cmpset_rel_64
#define	atomic_set_rel_long		atomic_set_rel_64
#define	atomic_subtract_rel_long	atomic_subtract_rel_64
#define	atomic_store_rel_long		atomic_store_rel_64

#define	atomic_add_rel_ptr		atomic_add_rel_64
#define	atomic_fcmpset_rel_ptr		atomic_fcmpset_rel_64
#define	atomic_clear_rel_ptr		atomic_clear_rel_64
#define	atomic_cmpset_rel_ptr		atomic_cmpset_rel_64
#define	atomic_set_rel_ptr		atomic_set_rel_64
#define	atomic_subtract_rel_ptr		atomic_subtract_rel_64
#define	atomic_store_rel_ptr		atomic_store_rel_64

static __inline void
atomic_thread_fence_acq(void)
{

	dmb(ld);
}

static __inline void
atomic_thread_fence_rel(void)
{

	dmb(sy);
}

static __inline void
atomic_thread_fence_acq_rel(void)
{

	dmb(sy);
}

static __inline void
atomic_thread_fence_seq_cst(void)
{

	dmb(sy);
}

#endif /* KCSAN && !KCSAN_RUNTIME */

#endif /* _MACHINE_ATOMIC_H_ */

