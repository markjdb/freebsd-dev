#include <machine/asmacros.h>

/*
 * long lwref_acquire(lwref_t lwr)
 * {
 *	long ret;
 *
 *	ret = lwr->lwr_idx;
 *	counter_u64_add(lwr->lwr_counters[ret], 1);
 *	return (ret);
 * }
 */

ENTRY(lwref_acquire)
	mov	(%rdi),%rax
	mov	0x8(%rdi,%rax,8),%rcx
	mov	$__pcpu,%rdx
	sub	%rdx,%rcx
	mov	$100000,%r10
cycle:
	sub	$1,%r10
	cmpq	$0,%r10
	jne	cycle
	addq	$1,%gs:(%rcx)
.globl	lwref_acquire_ponr
lwref_acquire_ponr:
	ret
END(lwref_acquire)
