# $FreeBSD$

SYSDIR?=	${SRCTOP}/sys

.PATH:		${SYSDIR}/cddl/dev/sdt

KMOD=		sdt
SRCS=		sdt.c sdt_isa.c
SRCS+=		vnode_if.h

.if ${MACHINE_CPUARCH} == "amd64" || ${MACHINE_CPUARCH} == "i386"
.PATH:		${SYSDIR}/cddl/dev/sdt/x86
.else
.PATH:		${SYSDIR}/cddl/dev/sdt/${MACHINE_CPUARCH}
.endif

CFLAGS+=	-I${SYSDIR}/cddl/dev/sdt \
		-I${SYSDIR}/cddl/compat/opensolaris \
		-I${SYSDIR}/cddl/contrib/opensolaris/uts/common \
		-I${SYSDIR}

.include <bsd.kmod.mk>

CFLAGS+=	-include ${SYSDIR}/cddl/compat/opensolaris/sys/debug_compat.h
