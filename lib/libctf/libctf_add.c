#include "_libctf.h"

#include <stdio.h>

ctf_id_t
libctf_add_type(Ctf *ctf, struct ctf_imtype *t)
{
	size_t ctfsz;
	int count;

	switch (t->t_kind) {
	case CTF_K_ARRAY:
		ctfsz = sizeof(struct ctf_stype) + sizeof(struct ctf_array);
		break;
	case CTF_K_FLOAT:
	case CTF_K_INTEGER:
		ctfsz = sizeof(struct ctf_stype) + sizeof(uint32_t);
		break;
	case CTF_K_ENUM:
		count = t->t_enum.vals.el_count;
#if 0
		ctfsz = (count * sizeof(struct ctf_enum) > CTF_MAX_SIZE ?
		    sizeof(struct ctf_type) : sizeof(struct ctf_stype)) +
		    count * sizeof(struct ctf_enum);
#endif
		ctfsz = sizeof(struct ctf_stype) +
		    count * sizeof(struct ctf_enum);
		break;
	case CTF_K_FORWARD:
		ctfsz = sizeof(struct ctf_stype);
		break;
	case CTF_K_FUNCTION:
		count = t->t_func.params.el_count + t->t_func.variadic;
		ctfsz = sizeof(struct ctf_stype) + count * sizeof(uint16_t);
		break;
	case CTF_K_STRUCT:
	case CTF_K_UNION:
		errx(1, "unimplemented");
	case CTF_K_CONST:
	case CTF_K_POINTER:
	case CTF_K_RESTRICT:
	case CTF_K_TYPEDEF:
	case CTF_K_VOLATILE:
		ctfsz = sizeof(struct ctf_stype);
		break;
	default:
		return (-1);
	}

	t->t_id = ++ctf->ctf_nextid; /* XXX check overflow */
	t->t_ctfsz = ctfsz;
	ctf->ctf_dtype_bsz += ctfsz;
	printf("adding type %lu\n", t->t_id);

	STAILQ_INSERT_TAIL(&ctf->ctf_dtypes, t, t_next);

	return (t->t_id);
}
