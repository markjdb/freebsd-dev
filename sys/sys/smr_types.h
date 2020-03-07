/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2019, 2020 Jeffrey Roberson <jeff@FreeBSD.org>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice unmodified, this list of conditions, and the following
 *    disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * $FreeBSD$
 */

#ifndef _SYS_SMR_TYPES_H_
#define	_SYS_SMR_TYPES_H_

#include <sys/_smr.h>

/*
 * SMR Accessors are meant to provide safe access to SMR protected
 * pointers and prevent misuse and accidental access.
 *
 * Accessors are grouped by type:
 * entered	- Use while in a read section (between smr_enter/smr_exit())
 * serialized 	- Use while holding a lock that serializes writers.   Updates
 *		  are synchronized with readers via included barriers.
 * unserialized	- Use after the memory is out of scope and not visible to
 *		  readers.
 *
 * All acceses include a parameter for an assert to verify the required
 * synchronization.  For example, a writer might use:
 *
 * smr_serialized_store(pointer, value, mtx_assert(&writelock, MA_OWNED));
 *
 * These are only enabled in INVARIANTS kernels.
 */

/* Type restricting pointer access to force smr accessors. */
#define	SMR_POINTER(type)						\
struct {								\
	type	__ptr;		/* Do not access directly */		\
}

/*
 * Read from an SMR protected pointer while in a read section.
 */
#define	smr_entered_load(p, smr) ({					\
	SMR_ASSERT(SMR_ENTERED((smr)), "smr_entered_load");		\
	(__typeof((p)->__ptr))atomic_load_acq_ptr((uintptr_t *)&(p)->__ptr); \
})

/*
 * Read from an SMR protected pointer while serialized by an
 * external mechanism.  'ex' should contain an assertion that the
 * external mechanism is held, e.g., mtx_assert().
 */
#define	smr_serialized_load(p, ex) ({					\
	SMR_ASSERT((ex), "smr_serialized_load");			\
	(__typeof((p)->__ptr))atomic_load_ptr(&(p)->__ptr);		\
})

/*
 * Store 'v' to an SMR protected pointer while serialized by an
 * external mechanism.  'ex' should contain an assertion that the
 * external mechanism is held, e.g., mtx_assert().
 *
 * Writers that are serialized with mutual exclusion or on a single
 * thread should use smr_serialized_store() rather than swap.
 */
#define	smr_serialized_store(p, v, ex) do {				\
	SMR_ASSERT((ex), "smr_serialized_store");			\
	__typeof((p)->__ptr) _v = (v);					\
	atomic_store_rel_ptr((uintptr_t *)&(p)->__ptr, (uintptr_t)_v);	\
} while (0)

/*
 * swap 'v' with an SMR protected pointer and return the old value
 * while serialized by an external mechanism.  'ex' should contain
 * an assertion that the external mechanism is provided, e.g., mtx_assert().
 *
 * Swap permits multiple writers to update a pointer concurrently.
 */
#define	smr_serialized_swap(p, v, ex) ({				\
	SMR_ASSERT((ex), "smr_serialized_swap");			\
	__typeof((p)->__ptr) _v = (v);					\
	/* Release barrier guarantees contents are visible to reader */ \
	atomic_thread_fence_rel();					\
	(__typeof((p)->__ptr))atomic_swap_ptr(				\
	    (uintptr_t *)&(p)->__ptr, (uintptr_t)_v);			\
})

/*
 * Read from an SMR protected pointer when no serialization is required
 * such as in the destructor callback or when the caller guarantees other
 * synchronization.
 */
#define	smr_unserialized_load(p, ex) ({					\
	SMR_ASSERT((ex), "smr_unserialized_load");			\
	(__typeof((p)->__ptr))atomic_load_ptr(&(p)->__ptr);		\
})

/*
 * Store to an SMR protected pointer when no serialiation is required
 * such as in the destructor callback or when the caller guarantees other
 * synchronization.
 */
#define	smr_unserialized_store(p, v, ex) do {				\
	SMR_ASSERT((ex), "smr_unserialized_store");			\
	__typeof((p)->__ptr) _v = (v);					\
	atomic_store_ptr((uintptr_t *)&(p)->__ptr, (uintptr_t)_v);	\
} while (0)

/*
 * Macros defining a queue.h-style doubly-linked list that permits
 * concurrent readers and serialized writers.
 */
#define	SMR_LIST_HEAD(name, type)					\
	struct name {							\
		struct type *smr_lh_first;				\
	}

#define	SMR_LIST_HEAD_INITIALIZER(head) { NULL }

#define	SMR_LIST_ENTRY(type)						\
	struct {							\
		struct type *smr_le_next;				\
		struct type **smr_le_prev;				\
	}

#define	SMR_LIST_INIT(head)						\
	atomic_store_rel_ptr(&(head)->smr_lh_first, NULL)

#define	SMR_LIST_FIRST(head)						\
	((__typeof((head)->smr_lh_first))atomic_load_acq_ptr(		\
	    (uintptr_t *)&(head)->smr_lh_first))

#define	SMR_LIST_EMPTY(head)						\
	(atomic_load_ptr(&(head)->smr_lh_first) == NULL)

#define	SMR_LIST_NEXT(elm, field)					\
	((__typeof(elm))atomic_load_acq_ptr(				\
	    (uintptr_t *)&(elm)->field.smr_le_next))

#define	SMR_LIST_INSERT_AFTER(listelm, elm, field) do {			\
	SMR_ASSERT((ex), "SMR_LIST_INSERT_AFTER");			\
	__typeof(elm) _next = (listelm)->field.smr_le_next;		\
	(elm)->field.smr_le_next = _next;				\
	(elm)->field.smr_le_prev = &(listelm)->field.smr_le_next;	\
	if (_next != NULL)						\
		_next->field.smr_le_prev = &(elm)->field.smr_le_next;	\
	atomic_store_rel_ptr((uintptr_t *)&(listelm)->field.smr_le_next,\
	    (uintptr_t)(elm));						\
} while (0)

#define	SMR_LIST_INSERT_BEFORE(listelm, elm, field, ex) do {		\
	SMR_ASSERT((ex), "SMR_LIST_INSERT_BEFORE");			\
	__typeof(elm) _prev = (listelm)->field.smr_le_prev;		\
	(elm)->field.smr_le_next = (listelm);				\
	(elm)->field.smr_le_prev = _prev;				\
	(listelm)->field.smr_le_prev = &(elm)->field.smr_le_next;	\
	atomic_store_rel_ptr((uintptr_t *)_prev, (uintptr_t)(elm));	\
} while (0)

#define	SMR_LIST_INSERT_HEAD(head, elm, field, ex) do {			\
	SMR_ASSERT((ex), "SMR_LIST_INSERT_HEAD");			\
	__typeof(elm) _next = (head)->smr_lh_first;			\
	(elm)->field.smr_le_next = _next;				\
	(elm)->field.smr_le_prev = &(head)->smr_lh_first;		\
	if (_next != NULL)						\
		_next->field.smr_le_prev = &(elm)->field.smr_le_next;	\
	atomic_store_rel_ptr((uintptr_t *)&(head)->smr_lh_first,	\
	    (uintptr_t)(elm));						\
} while (0)

#define	SMR_LIST_REMOVE(elm, field, ex) do {				\
	SMR_ASSERT((ex), "SMR_LIST_REMOVE");				\
	__typeof(elm) _next = (elm)->field.smr_le_next;			\
	if (_next != NULL)						\
		_next->field.smr_le_prev = (elm)->field.smr_le_prev;	\
	atomic_store_ptr((elm)->field.smr_le_prev, _next);		\
} while (0)

#define	SMR_LIST_FOREACH(var, head, field, ex)				\
	for (({SMR_ASSERT((ex), "SMR_LIST_FOREACH"); 1;}),		\
	    (var) = SMR_LIST_FIRST(head);				\
	    (var) != NULL;						\
	    (var) = SMR_LIST_NEXT((var), field))

#define	SMR_LIST_FOREACH_SAFE(var, head, field, tvar, ex)		\
	for (({SMR_ASSERT((ex), "SMR_LIST_FOREACH_SAFE"); 1;}),		\
	    (var) = SMR_LIST_FIRST(head);				\
	    (var) != NULL && ((tvar) = SMR_LIST_NEXT((var), field), 1);	\
	    (var) = (tvar))

#ifndef _KERNEL

/*
 * Load an SMR protected pointer when accessing kernel data structures through
 * libkvm.
 */
#define	smr_kvm_load(p) ((p)->__ptr)

#endif /* !_KERNEL */
#endif /* !_SYS_SMR_TYPES_H_ */
