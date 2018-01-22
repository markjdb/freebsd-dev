# $FreeBSD$

PACKAGE=	tests

TESTSDIR=	${TESTSBASE}/sys/vm

ATF_TESTS_C+=	mmap_test	\
		vm_radix_test

.PATH:	${.CURDIR} ${SRCTOP}/sys/vm

CFLAGS.vm_radix_test+= -I${SRCTOP}/sys/vm
SRCS.vm_radix_test=	vm_radix_test.c	\
			vm_radix.c

.include <bsd.test.mk>
