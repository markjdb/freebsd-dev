#include "_libctf.h"

#include <stdio.h>

Ctf *
libctf_create(size_t strtabsz, int *errp)
{
	Ctf *ctf;

	ctf = calloc(1, sizeof(*ctf));
	if (ctf == NULL) {
		if (errp != NULL)
			*errp = CTF_E_RESOURCE;
		return (NULL);
	}

	STAILQ_INIT(&ctf->ctf_dtypes);

	ctf->ctf_strtab = elftc_string_table_create(strtabsz);
	if (ctf->ctf_strtab == NULL) {
		if (errp != NULL)
			*errp = CTF_E_RESOURCE;
		free(ctf);
		return (NULL);
	}

	return (ctf);
}

int
ctf_update(Ctf *ctf)
{
	struct ctf_enum enumval;
	struct ctf_header hdr;
	struct ctf_imtype *imt;
	struct ctf_imtelem *elem;
	struct ctf_stype st;
	struct ctf_type t __unused;
	const char *strtab;
	char *buf, *obuf;
	size_t bufsz, strtabsz;
	int count, i;

	strtab = elftc_string_table_image(ctf->ctf_strtab, &strtabsz);

	bufsz = sizeof(hdr) + ctf->ctf_dtype_bsz + strtabsz;
	buf = obuf = malloc(bufsz);
	if (buf == NULL) {
		ctf->ctf_error = errno;
		return (-1);
	}

	memset(&hdr, 0, sizeof(hdr));
	hdr.cth_magic = CTF_MAGIC;
	hdr.cth_version = CTF_VERSION;
	hdr.cth_flags = 0;
	hdr.cth_parlabel = 0;
	hdr.cth_parname = 0;
	hdr.cth_lbloff = 0;
	hdr.cth_objtoff = 0;
	hdr.cth_funcoff = 0;
	hdr.cth_typeoff = 0;
	hdr.cth_stroff = 0;
	hdr.cth_strlen = strtabsz;
	memcpy(buf, &hdr, sizeof(hdr));

	buf += sizeof(hdr);

	STAILQ_FOREACH(imt, &ctf->ctf_dtypes, t_next) {
		switch (imt->t_kind) {
		case CTF_K_ENUM:
			count = imt->t_enum.vals.el_count;
			if (count > 256)
				count = 256;
			memset(&st, 0, sizeof(st));
			st.cts_name = (uint32_t)imt->t_name;
			st.cts_info = (imt->t_kind << 11) |
			    (count & CTF_MAX_VLEN);
			st.cts_size = sizeof(uint32_t);
			memcpy(buf, &st, sizeof(st));
			buf += sizeof(st);
			for (i = 0; i < count; i++) {
				elem = &imt->t_enum.vals.el_list[i];
				memset(&enumval, 0, sizeof(enumval));
				enumval.cte_name = elem->e_name;
				enumval.cte_value = elem->e_val;
				memcpy(buf, &enumval, sizeof(enumval));
				buf += sizeof(enumval);
			}
			break;
		case CTF_K_FLOAT:
		case CTF_K_INTEGER:
			memset(&st, 0, sizeof(st));
			st.cts_name = (uint32_t)imt->t_name;
			st.cts_info = (imt->t_kind << 11) |
			    (sizeof(uint32_t) & CTF_MAX_VLEN);
			st.cts_size = CTF_INT_BITS(imt->t_integer.enc) / NBBY;
			memcpy(buf, &st, sizeof(st));
			buf += sizeof(st);
			memcpy(buf, &imt->t_integer.enc, sizeof(uint32_t));
			buf += sizeof(uint32_t);
			break;
		default:
			errx(1, "ctf_update: unimplemented kind %d",
			    imt->t_kind);
		}
	}

	memcpy(buf, strtab, strtabsz);
	ctf->ctf_buf = obuf;
	hdr.cth_stroff = buf - obuf - sizeof(hdr);
	memcpy(obuf, &hdr, sizeof(hdr));
	ctf->ctf_bufsz = buf - obuf + strtabsz;

	return (0);
}

int
ctf_write(Ctf *ctf, int fd)
{
	char *buf;
	size_t resid;
	ssize_t n;

	buf = ctf->ctf_buf;
	resid = ctf->ctf_bufsz;

	while (resid > 0 && (n = write(fd, buf, resid)) >= 0) {
		buf += n;
		resid -= n;
	}
	if (n < 0) {
		ctf->ctf_error = errno;
		return (-1);
	}
	return (0);
}
