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
		if (count > CTF_MAX_VLEN)
			count = CTF_MAX_VLEN;
		ctfsz = sizeof(struct ctf_stype) +
		    count * sizeof(struct ctf_enum);
		break;
	case CTF_K_FORWARD:
		ctfsz = sizeof(struct ctf_stype);
		break;
	case CTF_K_FUNCTION:
		count = t->t_func.params.el_count + t->t_func.variadic;
		if (count > CTF_MAX_VLEN)
			count = CTF_MAX_VLEN;
		ctfsz = sizeof(struct ctf_stype) +
		    roundup2(count, 2) * sizeof(uint16_t);
		break;
	case CTF_K_STRUCT:
	case CTF_K_UNION:
		count = t->t_sou.members.el_count;
		if (count > CTF_MAX_VLEN)
			count = CTF_MAX_VLEN;
		if (t->t_sou.bsz > CTF_MAX_SIZE)
			ctfsz = sizeof(struct ctf_type);
		else
			ctfsz = sizeof(struct ctf_stype);
		if (t->t_sou.bsz > CTF_LSTRUCT_THRESH)
			ctfsz += count * sizeof(struct ctf_lmember);
		else
			ctfsz += count * sizeof(struct ctf_member);
		break;
	case CTF_K_CONST:
	case CTF_K_POINTER:
	case CTF_K_RESTRICT:
	case CTF_K_TYPEDEF:
	case CTF_K_VOLATILE:
		ctfsz = sizeof(struct ctf_stype);
		break;
	default:
		/* XXX should be an assert */
		return (-1);
	}

	t->t_id = ++ctf->ctf_nextid; /* XXX check overflow */
	STAILQ_INSERT_TAIL(&ctf->ctf_dtypes, t, t_next);

	ctf->ctf_dtype_bsz += ctfsz;

	return (t->t_id);
}

void
libctf_add_objtab(Ctf *ctf, uint16_t *objtab, size_t n)
{

	if (ctf->objtab != NULL)
		free(ctf->objtab);
	ctf->objtab = objtab;
	ctf->objtabsz = n * sizeof(uint16_t);
}
