# $FreeBSD$

.include <src.opts.mk>

PROG=	moused
MAN=	moused.8

LIBADD=	m util

.if ${MK_CASPER} != "no"
LIBADD+=	casper
LIBADD+=	cap_fileargs
LIBADD+=	cap_syslog
CFLAGS+=	-DWITH_CASPER
.endif

#BINMODE=4555
#PRECIOUSPROG=

.include <bsd.prog.mk>
