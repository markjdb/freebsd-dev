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

#define	_ATOMIC_OP_IMPL(op, llsc_asmop, lse_asmop, mv, w, q, bar, s, a, l) \
static void								\
atomic_##op##_##bar##w##_llsc(volatile uint##w##_t *p, uint##w##_t val)	\
{									\
	uint##w##_t tmp;						\
	int res;							\
									\
	__asm __volatile(						\
	    "1: ld"#a"xr"#s"	%"#q"0, [%2]\n"				\
	    "  "#llsc_asmop"	%"#q"0, %"#q"0, %"#q"3\n"		\
	    "   st"#l"xr"#s"	%w1, %"#q"0, [%2]\n"			\
	    "   cbnz		%w1, 1b\n"				\
	    : "=&r" (tmp), "=&r" (res)					\
	    : "r" (p), "r" (val)					\
	    : "memory");						\
}									\
									\
static void								\
atomic_##op##_##bar##w##_lse(volatile uint##w##_t *p, uint##w##_t val)	\
{									\
	uint##w##_t tmp;						\
									\
	__asm __volatile(						\
	    ".arch_extension lse\n"					\
	    "  "#mv" %"#q"0, %"#q"2\n"					\
	    "   ld"#lse_asmop#a#l#s" %"#q"0, %"#q"0, [%1]\n"		\
	    ".arch_extension nolse\n"					\
	    : "+&r" (tmp)						\
	    : "r" (p), "r" (val)					\
	    : "memory");						\
}

#define	_ATOMIC_OP_IFUNC(op, w, bar)					\
DEFINE_IFUNC(, void, atomic_##op##_##bar##w,				\
    (volatile uint##w##_t *, uint##w##_t))				\
{									\
	if (lseimpl())							\
		return (atomic_##op##_##bar##w##_lse);			\
	else								\
		return (atomic_##op##_##bar##w##_llsc);			\
}

#define	ATOMIC_OP(op, llsc_asmop, lse_asmop, mv, w, q, s)		\
	_ATOMIC_OP_IMPL(op, llsc_asmop, lse_asmop, mv, w, q, , s, ,)	\
	_ATOMIC_OP_IFUNC(op, w,)					\
	_ATOMIC_OP_IMPL(op, llsc_asmop, lse_asmop, mv, w, q, acq_, s, a,) \
	_ATOMIC_OP_IFUNC(op, w, acq_)					\
	_ATOMIC_OP_IMPL(op, llsc_asmop, lse_asmop, mv, w, q, rel_, s, , l) \
	_ATOMIC_OP_IFUNC(op, w, rel_)

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

#define	_ATOMIC_CMPSET_IMPL(w, q, bar, s, a, l)			\
static int								\
atomic_cmpset_##bar##w##_llsc(volatile uint##w##_t *p,			\
    uint##w##_t cmpval, uint##w##_t newval)				\
{									\
	int res;							\
	uint##w##_t tmp;						\
									\
	__asm __volatile(						\
	    "1: mov	%w1, #1\n"					\
	    "   ld"#a"xr"#s" %"#q"0, [%2]\n"				\
	    "   cmp	%"#q"0, %"#q"3\n"				\
	    "   b.ne	2f\n"						\
	    "	st"#l"xr"#s" %w1, %"#q"4, [%2]\n"			\
	    "   cbnz	%w1, 1b\n"					\
	    "2:"							\
	    : "=&r" (tmp), "=&r" (res)					\
	    : "r" (p), "r" (cmpval), "r" (newval)			\
	    : "cc", "memory");						\
	return (!res);							\
}									\
									\
static int								\
atomic_cmpset_##bar##w##_lse(volatile uint##w##_t *p,			\
    uint##w##_t cmpval, uint##w##_t newval)				\
{									\
	int res;							\
	uint##w##_t oldval;						\
									\
	oldval = cmpval;						\
	__asm __volatile(						\
	    ".arch_extension lse\n"					\
	    "cas"#a#l#s" %"#q"1, %"#q"4, [%3]\n"			\
	    "cmp	%"#q"1, %"#q"2\n"				\
	    "cset	%w0, eq\n"					\
	    ".arch_extension nolse\n"					\
	    : "=r" (res), "+&r" (cmpval)					\
	    : "r" (oldval), "r" (p), "r" (newval)			\
	    : "cc", "memory");						\
	return (res);							\
}

#define	_ATOMIC_CMPSET_IFUNC(w, bar)					\
DEFINE_IFUNC(, int, atomic_cmpset_##bar##w,				\
    (volatile uint##w##_t *, uint##w##_t, uint##w##_t))			\
{									\
	if (lseimpl())							\
		return (atomic_cmpset_##bar##w##_lse);			\
	else								\
		return (atomic_cmpset_##bar##w##_llsc);			\
}

#define	ATOMIC_CMPSET(w, q, s)						\
	_ATOMIC_CMPSET_IMPL(w, q, , s, ,)				\
	_ATOMIC_CMPSET_IFUNC(w, )					\
	_ATOMIC_CMPSET_IMPL(w, q, acq_, s, a,)				\
	_ATOMIC_CMPSET_IFUNC(w, acq_)					\
	_ATOMIC_CMPSET_IMPL(w, q, rel_, s, , l)				\
	_ATOMIC_CMPSET_IFUNC(w, rel_)

#define	_ATOMIC_FETCHADD_IMPL(w, q)					\
static uint##w##_t							\
atomic_fetchadd_##w##_llsc(volatile uint##w##_t *p, uint##w##_t val)	\
{									\
	uint##w##_t ret, tmp;						\
	int res;							\
									\
	__asm __volatile(						\
	    "1: ldxr	%"#q"2, [%3]\n"					\
	    "   add	%"#q"0, %"#q"2, %"#q"4\n"			\
	    "   stxr	%w1, %"#q"0, [%3]\n"				\
	    "   cbnz	%w1, 1b\n"					\
	    : "=&r" (tmp), "=&r" (res), "=&r" (ret)			\
	    : "r" (p), "r" (val)					\
	    : "memory");						\
	return (ret);							\
}									\
									\
static uint##w##_t							\
atomic_fetchadd_##w##_lse(volatile uint##w##_t *p, uint##w##_t val)	\
{									\
	uint##w##_t ret;						\
									\
	__asm __volatile(						\
	    ".arch_extension lse\n"					\
	    "ldadd	%"#q"2, %"#q"0, [%1]\n"				\
	    ".arch_extension nolse\n"					\
	    : "=r" (ret)						\
	    : "r" (p), "r" (val)					\
	    : "memory");						\
	return (ret);							\
}

#define	_ATOMIC_FETCHADD_IFUNC(w)					\
DEFINE_IFUNC(, uint##w##_t, atomic_fetchadd_##w,			\
    (volatile uint##w##_t *, uint##w##_t))				\
{									\
	if (lseimpl())							\
		return (atomic_fetchadd_##w##_lse);			\
	else								\
		return (atomic_fetchadd_##w##_llsc);			\
}

#define	ATOMIC_FETCHADD(w, q)						\
	_ATOMIC_FETCHADD_IMPL(w, q)					\
	_ATOMIC_FETCHADD_IFUNC(w)

ATOMIC_FCMPSET(8, w, b)
ATOMIC_FCMPSET(16, w, h)
ATOMIC_FCMPSET(32, w,)
ATOMIC_FCMPSET(64, ,)

ATOMIC_CMPSET(8, w, b)
ATOMIC_CMPSET(16, w, h)
ATOMIC_CMPSET(32, w,)
ATOMIC_CMPSET(64, ,)

ATOMIC_FETCHADD(32, w)
ATOMIC_FETCHADD(64,)

ATOMIC_OP(add, add, add, mov, 8, w, b)
ATOMIC_OP(add, add, add, mov, 16, w, h)
ATOMIC_OP(add, add, add, mov, 32, w,)
ATOMIC_OP(add, add, add, mov, 64, ,)

ATOMIC_OP(clear, bic, clr, mov, 8, w, b)
ATOMIC_OP(clear, bic, clr, mov, 16, w, h)
ATOMIC_OP(clear, bic, clr, mov, 32, w,)
ATOMIC_OP(clear, bic, clr, mov, 64, ,)

ATOMIC_OP(set, orr, set, mov, 8, w, b)
ATOMIC_OP(set, orr, set, mov, 16, w, h)
ATOMIC_OP(set, orr, set, mov, 32, w,)
ATOMIC_OP(set, orr, set, mov, 64, ,)

ATOMIC_OP(subtract, add, add, neg, 8, w, b)
ATOMIC_OP(subtract, add, add, neg, 16, w, h)
ATOMIC_OP(subtract, add, add, neg, 32, w,)
ATOMIC_OP(subtract, add, add, neg, 64, ,)
