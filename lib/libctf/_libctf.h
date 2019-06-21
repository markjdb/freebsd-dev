#ifndef __LIBCTF_H_
#define	__LIBCTF_H_

#include <sys/param.h>
#include <sys/queue.h>
#include <sys/tree.h>

#include <assert.h>
#include <err.h>
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <libelftc.h>

#include "libctf.h"

struct ctf_imtype;

struct _Ctf {
	STAILQ_HEAD(, ctf_imtype) ctf_dtypes;
	size_t		ctf_dtype_bsz;

	Elftc_String_Table *ctf_strtab;

	int		ctf_error;

	char		*ctf_buf;
	size_t		ctf_bufsz;

	ctf_id_t	ctf_nextid;

	int		ctf_model;
	void		*ctf_specific;
};

struct ctf_imtelem {
	size_t		e_name;
	uint64_t	e_type; /* func, struct, union */
	union {
		int	e_val;	/* enum */
		int	e_off;	/* struct, union */
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
	size_t		t_name;
	int		t_kind;

	union {
		struct {
			uint64_t	tref;
			uint64_t	tindex;
			int		count;
		} t_array;

		struct {
			struct ctf_imtelem_list vals;
		} t_enum;

		struct {
			struct ctf_imtelem_list params;
			bool		variadic;
		} t_func;

		struct {
			uint32_t	enc;
		} t_integer; /* XXX should be t_num */

		struct {
			struct ctf_imtelem_list members;
		} t_sou;

		struct {
			uint64_t	ref;
		} t_ref;
	};

	uint64_t	t_id;		/* CTF type index */
	size_t		t_ctfsz;	/* byte size of CTF representation */
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

ctf_id_t	libctf_add_type(Ctf *, struct ctf_imtype *);
Ctf		*libctf_create(size_t, int *);

#endif /* __LIBCTF_H_ */
