# $FreeBSD$

.include <src.opts.mk>

PACKAGE=lib${LIB}
LIB=	ctf
MAN=

SRCS=	ctf_add.c	\
	ctf_errmsg.c	\
	ctf_model.c	\
	ctf_open.c	\
	ctf_specific.c	\
	libctf_dwarf.c

.PATH: ${SRCTOP}/contrib/elftoolchain/libelftc

#CFLAGS+= -O0

SRCS+=	elftc_string_table.c libelftc_hash.c
CFLAGS+= -I${SRCTOP}/contrib/elftoolchain/common

INCS=	libctf.h

LIBADD+= dwarf z

SHLIB_MAJOR=	1

.include <bsd.lib.mk>
