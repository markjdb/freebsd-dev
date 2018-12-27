#	@(#)Makefile	8.1 (Berkeley) 6/6/93
# $FreeBSD$

PROG_CXX=	pmctrace
SRCS=	pmctrace.c
MAN=

LIBADD= elf pmc pmcstat

.if ${MACHINE_CPUARCH} == "amd64"
SRCS+=	pmctrace_pt.c		\
	pmctrace_pt.h
LIBADD+= ipt
.endif

.if ${MACHINE_CPUARCH} == "aarch64"
SRCS+=	pmctrace_cs.c		\
	pmctrace_cs.h
LIBADD+= opencsd
.endif

.include <bsd.prog.mk>
