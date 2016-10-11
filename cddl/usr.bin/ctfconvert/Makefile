# $FreeBSD$

.PATH: ${.CURDIR}/../../../cddl/contrib/opensolaris/cmd/ctfconvert
.PATH: ${.CURDIR}/../../../cddl/contrib/opensolaris/tools/ctf/common
.PATH: ${.CURDIR}/../../../cddl/contrib/opensolaris/tools/ctf/cvt
.PATH: ${.CURDIR}/../../../sys/cddl/contrib/opensolaris/uts/common/os

PROG=		ctfconvert
SRCS=		ctfconvert.c

CFLAGS+=	-I${OPENSOLARIS_USR_DISTDIR} \
		-I${OPENSOLARIS_SYS_DISTDIR} \
		-I${OPENSOLARIS_USR_DISTDIR}/head \
		-I${OPENSOLARIS_USR_DISTDIR}/cmd/mdb/tools/common \
		-I${.CURDIR}/../../../sys/cddl/compat/opensolaris \
		-I${.CURDIR}/../../../cddl/compat/opensolaris/include \
		-I${OPENSOLARIS_USR_DISTDIR}/common/ctf \
		-I${OPENSOLARIS_USR_DISTDIR}/lib/libctf/common \
		-I${OPENSOLARIS_USR_DISTDIR}/tools/ctf/common \
		-I${OPENSOLARIS_SYS_DISTDIR}/uts/common

LIBADD=		ctf elf

MAN=		ctfconvert.1

.include <bsd.prog.mk>

CFLAGS+=	-Wno-unused-parameter
