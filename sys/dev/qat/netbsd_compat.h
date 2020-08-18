#ifndef _NETBSD_COMPAT_H_
#define	_NETBSD_COMPAT_H_

#define	__MIN(a, b)	((/*CONSTCOND*/(a)<=(b))?(a):(b))
#define	__MAX(a, b)	((/*CONSTCOND*/(a)>(b))?(a):(b))

#define	__BIT(__n)						\
	(((uintmax_t)(__n) >= NBBY * sizeof(uintmax_t)) ? 0 :	\
	((uintmax_t)1 << (uintmax_t)((__n) & (NBBY * sizeof(uintmax_t) - 1))))
#define	__BITS(__m, __n)		\
	((__BIT(__MAX((__m), (__n)) + 1) - 1) ^ (__BIT(__MIN((__m), (__n))) - 1))
#define	__LOWEST_SET_BIT(__mask)	((((__mask) - 1) & (__mask)) ^ (__mask))
#define	__SHIFTIN(__x, __mask)		((__x) * __LOWEST_SET_BIT(__mask))

#endif
