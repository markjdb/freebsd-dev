# $FreeBSD$

SRCS+=	trivial-vdso_tc.c

MDASM=  Ovfork.S brk.S cerror.S syscall.S

# Don't generate default code for these syscalls:
NOASM+=	sbrk.o vfork.o
