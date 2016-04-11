# $FreeBSD$

SYSDIR?=	${.CURDIR}/../../..

.PATH:		${SYSDIR}/cddl/dev/fbt
.PATH:		${SYSDIR}/cddl/dev/fbt/${MACHINE_CPUARCH}

KMOD=		fbt
SRCS=		fbt.c fbt_isa.c
SRCS+=		vnode_if.h

CFLAGS+=	-I${SYSDIR}/cddl/dev/fbt/${MACHINE_CPUARCH}

.if ${MACHINE_CPUARCH} == "amd64" || ${MACHINE_CPUARCH} == "i386"
SRCS+=		fbt_asm.S

SRCS+=		assym.s
SRCS+=		opt_compat.h opt_kstack_pages.h opt_nfs.h opt_hwpmc_hooks.h

fbt_asm.o:	assym.s

CFLAGS+=	-I${SYSDIR}/cddl/dev/fbt/x86
.PATH:		${SYSDIR}/cddl/dev/fbt/x86
.endif

CFLAGS+=	-I${SYSDIR}/cddl/dev/fbt \
		-I${SYSDIR}/cddl/compat/opensolaris \
		-I${SYSDIR}/cddl/contrib/opensolaris/uts/common \
		-I${SYSDIR}

.include <bsd.kmod.mk>

CFLAGS+=	-include ${SYSDIR}/cddl/compat/opensolaris/sys/debug_compat.h
