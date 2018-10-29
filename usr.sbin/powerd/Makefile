# $FreeBSD$

PROG=	powerd
MAN=	powerd.8

LIBADD=	util

.include <src.opts.mk>

.if ${MK_CASPER} != "no"
CFLAGS+= -DWITH_CASPER
LIBADD+= casper cap_sysctl
.endif

.include <bsd.prog.mk>
