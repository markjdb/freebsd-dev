#ifndef __LIBCTF_H_
#define	__LIBCTF_H_

#include "libctf.h"

struct _Ctf {
	ctf_id_t	*ctf_obj_scn;
	size_t		ctf_obj_scn_sz;
	ctf_id_t	*ctf_func_scn;
	size_t		ctf_func_scn_sz;

	int		ctf_error;

	int		ctf_model;
	void		*ctf_specific;
};

/*
 * In-memory representation of a C type.
 */
struct ctf_imtype {
	const char	*im_name;

	union {
		struct {
			uint32_t	enc;
		} im_number;	/* float or integer */
	}
};

#define	LIBCTF_SET_ERROR(errp, e) do {			\
	if ((errp) != NULL)				\
		*(errp) = (e);				\
} while (0)

struct ctf_imtype	*_libctf_add_type(Ctf *ctf, const char *name);

#endif /* __LIBCTF_H_ */
