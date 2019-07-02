/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2019 Mark Johnston <markj@FreeBSD.org>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef __LIBCTF_H_
#define	__LIBCTF_H_

#include <sys/param.h>
#include <sys/queue.h>
#include <sys/tree.h>

#include <assert.h>
#include <err.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <libelftc.h>

#include "libctf.h"

struct ctf_imtype;

struct _Ctf {
	STAILQ_HEAD(, ctf_imtype) ctf_dtypes;
	size_t		ctf_dtype_bsz;

	uint16_t	*objtab;
	size_t		objtabsz;

	Elftc_String_Table *ctf_strtab;

	int		ctf_error;

	char		*ctf_buf;
	size_t		ctf_bufsz;

	ctf_id_t	ctf_nextid;

	int		ctf_model;
	void		*ctf_specific;
};

/* Used internally to ensure that switch statements are fully cased. */
enum _ctf_kind {
	LIBCTF_K_UNKNOWN = CTF_K_UNKNOWN,
	LIBCTF_K_INTEGER = CTF_K_INTEGER,
	LIBCTF_K_FLOAT = CTF_K_FLOAT,
	LIBCTF_K_POINTER = CTF_K_POINTER,
	LIBCTF_K_ARRAY = CTF_K_ARRAY,
	LIBCTF_K_FUNCTION = CTF_K_FUNCTION,
	LIBCTF_K_STRUCT = CTF_K_STRUCT,
	LIBCTF_K_UNION = CTF_K_UNION,
	LIBCTF_K_ENUM = CTF_K_ENUM,
	LIBCTF_K_FORWARD = CTF_K_FORWARD,
	LIBCTF_K_TYPEDEF = CTF_K_TYPEDEF,
	LIBCTF_K_VOLATILE = CTF_K_VOLATILE,
	LIBCTF_K_CONST = CTF_K_CONST,
	LIBCTF_K_RESTRICT = CTF_K_RESTRICT,
};

struct ctf_imtelem {
	size_t		e_name;
	uint64_t	e_type; /* func, struct, union */
	union {
		int	e_val;	/* enum */
		uint64_t e_off;	/* struct, union */
	};
};

struct ctf_imtelem_list {
	struct ctf_imtelem	*el_list;
	int			el_count;	/* entries */
	int			el_size;	/* total space */
};

/*
 * In-memory representation of a C type.
 */
struct ctf_imtype {
	/* CTF attributes: */

	size_t		t_name;
	enum _ctf_kind	t_kind;

	union {
		struct {
			struct ctf_imtelem_list vals;
		} t_enum;

		struct {
			struct ctf_imtelem_list params;
			bool		variadic;
		} t_func;

		struct {
			uint32_t	enc;
		} t_num;

		struct {
			struct ctf_imtelem_list members;
			size_t bsz;
		} t_sou;

		struct {
			uint64_t	id;
			uint64_t	tindex;	/* array */
			int		count;	/* array */
		} t_ref;
	};

	/* Fields filled in when adding a dynamic type to a container: */

	uint64_t	t_id;		/* CTF type index */
	STAILQ_ENTRY(ctf_imtype) t_next; /* dynamic type list linkage */
};

#define	LIBCTF_SET_ERROR(errp, e) do {			\
	if ((errp) != NULL)				\
		*(errp) = (e);				\
} while (0)

static inline struct ctf_imtelem_list *
ctf_imtelem_list_init(struct ctf_imtelem_list *l, int n)
{

	l->el_list = malloc(n * sizeof(*l->el_list));
	assert(l != NULL);
	l->el_count = 0;
	l->el_size = n;
	return (l);
}

static inline void
ctf_imtelem_list_add(struct ctf_imtelem_list *l, struct ctf_imtelem *e)
{

	if (l->el_count == l->el_size) {
		l->el_size *= 2;
		l->el_list = realloc(l->el_list,
		    l->el_size * sizeof(*l->el_list));
	}
	l->el_list[l->el_count++] = *e;
}

void		libctf_add_objtab(Ctf *, uint16_t *, size_t);
ctf_id_t	libctf_add_type(Ctf *, struct ctf_imtype *);
Ctf		*libctf_create(size_t, int *);

#endif /* __LIBCTF_H_ */
