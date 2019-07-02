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

#include "_libctf.h"

#include <printf.h>

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

struct ctf_buf {
	uint8_t		*base;
	size_t		sz;
	size_t		off;
};

static int
ctf_buf_init(struct ctf_buf *buf, size_t sz)
{

	buf->base = malloc(sz);
	if (buf->base == NULL)
		return (-1);
	buf->sz = sz;
	buf->off = 0;
	return (0);
}

static void
ctf_buf_cat(struct ctf_buf *buf, const void *data, size_t n)
{

	assert(buf->off + n <= buf->sz);
	memcpy(buf->base + buf->off, data, n);
	buf->off += n;
}

static void *
ctf_buf_image(struct ctf_buf *buf)
{

	return (buf->base);
}

static void
ctf_buf_padalign(struct ctf_buf *buf, size_t alignment)
{
	size_t n;

	n = alignment - (buf->off % alignment);
	assert(buf->off + n <= buf->sz);
	memset(buf->base + buf->off, 0, n);
	buf->off += n;
}

int
ctf_update(Ctf *ctf)
{
	struct ctf_array arrayval;
	struct ctf_buf buf;
	struct ctf_enum enumval;
	struct ctf_header hdr;
	struct ctf_imtype *imt;
	struct ctf_imtelem *elem;
	struct ctf_lmember lmember;
	struct ctf_member member;
	struct ctf_stype st;
	struct ctf_type t;
	const char *strtab;
	size_t bufsz, objtabsz, strtabsz;
	int count, i;
	uint16_t param;

	strtab = elftc_string_table_image(ctf->ctf_strtab, &strtabsz);

	objtabsz = roundup2(ctf->objtabsz, 4);

	bufsz = sizeof(hdr) + objtabsz + ctf->ctf_dtype_bsz + strtabsz;
	if (ctf_buf_init(&buf, bufsz) != 0) {
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
	hdr.cth_funcoff = objtabsz;
	hdr.cth_typeoff = objtabsz;
	hdr.cth_stroff = objtabsz + ctf->ctf_dtype_bsz;
	hdr.cth_strlen = strtabsz;
	ctf_buf_cat(&buf, &hdr, sizeof(hdr));

	ctf_buf_cat(&buf, ctf->objtab, ctf->objtabsz);
	ctf_buf_padalign(&buf, 4);

	STAILQ_FOREACH(imt, &ctf->ctf_dtypes, t_next) {
		switch (imt->t_kind) {
		case CTF_K_ENUM:
			count = imt->t_enum.vals.el_count;
			if (count > CTF_MAX_VLEN)
				/* XXX */
				count = CTF_MAX_VLEN;
			memset(&st, 0, sizeof(st));
			st.cts_name = (uint32_t)imt->t_name;
			st.cts_info = (imt->t_kind << 11) |
			    (count & CTF_MAX_VLEN);
			st.cts_size = sizeof(uint32_t);
			ctf_buf_cat(&buf, &st, sizeof(st));
			for (i = 0; i < count; i++) {
				elem = &imt->t_enum.vals.el_list[i];
				memset(&enumval, 0, sizeof(enumval));
				enumval.cte_name = elem->e_name;
				enumval.cte_value = elem->e_val;
				ctf_buf_cat(&buf, &enumval, sizeof(enumval));
			}
			break;
		case CTF_K_FLOAT:
		case CTF_K_INTEGER:
			memset(&st, 0, sizeof(st));
			st.cts_name = (uint32_t)imt->t_name;
			st.cts_info = (imt->t_kind << 11) |
			    (sizeof(uint32_t) & CTF_MAX_VLEN);
			st.cts_size = CTF_INT_BITS(imt->t_num.enc) / NBBY;
			ctf_buf_cat(&buf, &st, sizeof(st));
			ctf_buf_cat(&buf, &imt->t_num.enc, sizeof(uint32_t));
			break;
		case CTF_K_ARRAY:
			memset(&st, 0, sizeof(st));
			st.cts_name = imt->t_name;
			st.cts_info = (imt->t_kind << 11) |
			    (sizeof(arrayval) & CTF_MAX_VLEN);
			st.cts_size = 0;
			ctf_buf_cat(&buf, &st, sizeof(st));

			memset(&arrayval, 0, sizeof(arrayval));
			arrayval.cta_contents = imt->t_ref.id;
			arrayval.cta_index = 0; /* XXX */
			arrayval.cta_nelems = imt->t_ref.count;
			ctf_buf_cat(&buf, &arrayval, sizeof(arrayval));
			break;
		case CTF_K_STRUCT:
		case CTF_K_UNION:
			count = imt->t_sou.members.el_count;
			if (count > CTF_MAX_VLEN)
				/* XXX */
				count = CTF_MAX_VLEN;
			if (imt->t_sou.bsz > CTF_MAX_SIZE) {
				memset(&t, 0, sizeof(t));
				t.ctt_name = imt->t_name;
				t.ctt_info = (imt->t_kind << 11) |
				    (count & CTF_MAX_VLEN);
				t.ctt_size = CTF_LSIZE_SENT;
				t.ctt_lsizehi = imt->t_sou.bsz >> 32;
				t.ctt_lsizelo = imt->t_sou.bsz & 0xffffffffu;
				ctf_buf_cat(&buf, &t, sizeof(t));
			} else {
				memset(&st, 0, sizeof(st));
				st.cts_name = imt->t_name;
				st.cts_info = (imt->t_kind << 11) |
				    (count & CTF_MAX_VLEN);
				st.cts_size = imt->t_sou.bsz;
				ctf_buf_cat(&buf, &st, sizeof(st));
			}
			if (imt->t_sou.bsz > CTF_LSTRUCT_THRESH) {
				for (i = 0; i < count; i++) {
					elem = &imt->t_sou.members.el_list[i];
					memset(&lmember, 0, sizeof(lmember));
					lmember.ctlm_name = elem->e_name;
					lmember.ctlm_type = elem->e_type;
					lmember.ctlm_offsethi =
					    elem->e_off >> 32;
					lmember.ctlm_offsetlo =
					    elem->e_off & 0xffffffffu;
					ctf_buf_cat(&buf, &lmember,
					    sizeof(lmember));
				}
			} else {
				for (i = 0; i < count; i++) {
					elem = &imt->t_sou.members.el_list[i];
					memset(&member, 0, sizeof(member));
					member.ctm_name = elem->e_name;
					member.ctm_type = elem->e_type;
					member.ctm_offset = elem->e_off;
					ctf_buf_cat(&buf, &member,
					    sizeof(member));
				}
			}
			break;
		case CTF_K_FUNCTION:
			count = imt->t_func.params.el_count;
			if (imt->t_func.variadic)
				count++;
			if (count > CTF_MAX_VLEN)
				/* XXX */
				count = CTF_MAX_VLEN;
			memset(&st, 0, sizeof(st));
			st.cts_name = 0;
			st.cts_info = (imt->t_kind << 11) |
			    (count & CTF_MAX_VLEN);
			st.cts_type = imt->t_func.params.el_list[0].e_type;
			ctf_buf_cat(&buf, &st, sizeof(st));
			for (i = 0; i < count; i++) {
				elem = &imt->t_func.params.el_list[i];
				memset(&param, 0, sizeof(param));
				if (imt->t_func.variadic && i == count - 1)
					param = 0;
				else
					param = elem->e_type;
				ctf_buf_cat(&buf, &param, sizeof(param));
			}
			if (count % 2 != 0) {
				memset(&param, 0, sizeof(param));
				ctf_buf_cat(&buf, &param, sizeof(param));
			}
			break;
		case CTF_K_CONST:
		case CTF_K_POINTER:
		case CTF_K_RESTRICT:
		case CTF_K_TYPEDEF:
		case CTF_K_VOLATILE:
			memset(&st, 0, sizeof(st));
			st.cts_name = imt->t_name;
			st.cts_info = (imt->t_kind << 11);
			st.cts_type = imt->t_ref.id;
			ctf_buf_cat(&buf, &st, sizeof(st));
			break;
		default:
			errx(1, "ctf_update: unimplemented kind %d",
			    imt->t_kind);
		}
	}

	ctf_buf_cat(&buf, strtab, strtabsz);

	ctf->ctf_buf = ctf_buf_image(&buf);
	ctf->ctf_bufsz = bufsz;

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
