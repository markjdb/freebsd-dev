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

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include <atf-c.h>
#include <gelf.h>
#include <libdwarf.h>
#include <libelf.h>
#include <libelftc.h>

struct inputf {
	Dwarf_P_Debug	dbg;
	int		fd;
};

#define	ELF_REQUIRE(cond)	ATF_REQUIRE_MSG((cond), "%s", elf_errmsg(-1))

static void
input_file_init(struct inputf *fp)
{
	Elf *elf;
	Elf64_Ehdr *ehdr;
	Elf_Scn *symtabscn;
	Elftc_String_Table *strtab;
	GElf_Shdr shdr;
	char filename[16];
	int fd;

	(void)snprintf(filename, sizeof(filename), "input.XXXXXX");
	fd = mkstemp(filename);
	ATF_REQUIRE_MSG(fd != -1, "mkstemp: %s", strerror(errno)); 

	strtab = elftc_string_table_create(0);
	ATF_REQUIRE(strtab != NULL);

	ELF_REQUIRE(elf_version(EV_CURRENT) != EV_NONE);

	elf = elf_begin(fd, ELF_C_WRITE, NULL);
	ELF_REQUIRE(elf != NULL);
	ehdr = elf64_newehdr(elf);
	ELF_REQUIRE(ehdr != NULL);
	ehdr->e_ident[EI_DATA] = ELFDATA2LSB;
	ehdr->e_type = ET_REL;

	symtabscn = elf_newscn(elf);
	ELF_REQUIRE(symtabscn != NULL);
	ELF_REQUIRE(gelf_getshdr(symtabscn, &shdr) != NULL);
	shdr.sh_name = elftc_string_table_insert(strtab, ".symtab");
	ATF_REQUIRE(shdr.sh_name != 0);
	shdr.sh_type = SHT_SYMTAB;
	shdr.sh_flags = 0;
	shdr.sh_addralign = 8;
	shdr.sh_entsize = sizeof(Elf64_Sym);
	ELF_REQUIRE(gelf_update_shdr(symtabscn, &shdr) != 0);

	fp->fd = fd;
}

ATF_TC(empty_cu);
ATF_TC_HEAD(empty_cu, tc)
{
	atf_tc_set_md_var(tc, "descr", "Make sure we handle an empty CU DIE");
}
ATF_TC_BODY(empty_cu, tc)
{
	struct inputf f;

	input_file_init(&f);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, empty_cu);

	return (atf_no_error());
}
