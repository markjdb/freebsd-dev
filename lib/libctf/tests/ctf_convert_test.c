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
#include <dwarf.h>
#include <gelf.h>
#include <libctf.h>
#include <libdwarf.h>
#include <libelf.h>
#include <libelftc.h>

struct inputf {
	Dwarf_P_Debug	dbg;
	Elf		*elf;
	Elf_Scn		*symtabscn;
	Elftc_String_Table *strtab;
	int		fd;
};

#define	DWARF_REQUIRE(cond)	ATF_REQUIRE_MSG(cond, "%s", dwarf_errmsg(derr))
#define	ELF_REQUIRE(cond)	ATF_REQUIRE_MSG(cond, "%s", elf_errmsg(-1))

static int
dwarf_producer_cb(char *name, int size, Dwarf_Unsigned type,
    Dwarf_Unsigned flags, Dwarf_Unsigned link, Dwarf_Unsigned info,
    Dwarf_Unsigned *index, int *error __unused, void *arg)
{
	Elf_Scn *scn;
	GElf_Shdr shdr;
	struct inputf *fp;

	fp = arg;

	scn = elf_newscn(fp->elf);
	ELF_REQUIRE(scn != NULL);
	ELF_REQUIRE(gelf_getshdr(scn, &shdr) != NULL);
	shdr.sh_name = elftc_string_table_insert(fp->strtab, name);
	ELF_REQUIRE(shdr.sh_name != 0);
	shdr.sh_size = size;
	shdr.sh_type = type;
	shdr.sh_flags = flags;
	shdr.sh_link = link;
	shdr.sh_info = info;
	ELF_REQUIRE(gelf_update_shdr(scn, &shdr) != 0);

	*index = elf_ndxscn(fp->symtabscn);
	return ((int)elf_ndxscn(scn));
}

static void
input_file_init(struct inputf *fp)
{
	Dwarf_Error derr;
	Dwarf_P_Debug dbg;
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
	ATF_REQUIRE_MSG(unlink(filename) == 0, "unlink: %s", strerror(errno));

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

	dbg = dwarf_producer_init_c(DW_DLC_WRITE | DW_DLC_SIZE_64,
	    dwarf_producer_cb, fp, NULL, NULL, &derr);
	DWARF_REQUIRE(dbg != DW_DLV_BADADDR);

	fp->dbg = dbg;
	fp->elf = elf;
	fp->fd = fd;
	fp->symtabscn = symtabscn;
	fp->strtab = strtab;
}

static int
input_file_finalize(struct inputf *fp)
{
	Dwarf_Error derr;
	Dwarf_P_Debug dbg;
	Dwarf_Ptr bytes;
	Dwarf_Signed count, i, ndx;
	Dwarf_Unsigned len;
	Elf *elf;
	Elf_Data *data, *strtabdata;
	Elf_Scn *scn, *shstrtabscn;
	Elftc_String_Table *strtab;
	GElf_Shdr shdr;
	size_t shstrtaboff;

	dbg = fp->dbg;
	elf = fp->elf;
	strtab = fp->strtab;

	shstrtaboff = elftc_string_table_insert(strtab, ".shstrtab");
	ATF_REQUIRE(shstrtaboff != 0);

	shstrtabscn = elf_newscn(elf);
	ELF_REQUIRE(shstrtabscn != NULL);
	strtabdata = elf_newdata(shstrtabscn);
	ELF_REQUIRE(strtabdata != NULL);
	strtabdata->d_buf = __DECONST(char *, elftc_string_table_image(strtab,
	    &strtabdata->d_size));
	ELF_REQUIRE(gelf_getshdr(shstrtabscn, &shdr) != NULL);
	shdr.sh_name = shstrtaboff;
	shdr.sh_type = SHT_STRTAB;
	shdr.sh_flags = SHF_ALLOC | SHF_STRINGS;
	shdr.sh_entsize = 0;
	ELF_REQUIRE(gelf_update_shdr(shstrtabscn, &shdr) != 0);
	ELF_REQUIRE(elf_setshstrndx(elf, elf_ndxscn(shstrtabscn)) != 0);

	count = dwarf_transform_to_disk_form(dbg, &derr);
	DWARF_REQUIRE(count != DW_DLV_NOCOUNT);

	for (i = 0; i < count; i++) {
		bytes = dwarf_get_section_bytes(dbg, i, &ndx, &len, &derr);
		DWARF_REQUIRE(bytes != NULL);
		scn = elf_getscn(elf, ndx);
		ELF_REQUIRE(scn != NULL);
		data = elf_newdata(scn);
		ELF_REQUIRE(data != NULL);
		data->d_buf = bytes;
		data->d_size = len;

		ELF_REQUIRE(gelf_getshdr(scn, &shdr) != NULL);
		shdr.sh_size = len;
		ELF_REQUIRE(gelf_update_shdr(scn, &shdr) != 0);
	}

	ELF_REQUIRE(elf_update(elf, ELF_C_WRITE) != -1);
	(void)elf_end(elf);
	(void)dwarf_producer_finish(dbg, &derr);
	elftc_string_table_destroy(strtab);

	return (fp->fd);
}

static void
add_die(struct inputf *fp, Dwarf_P_Die die)
{
	Dwarf_Error derr;

	DWARF_REQUIRE(dwarf_add_die_to_debug(fp->dbg, die, &derr) !=
	    (Dwarf_Unsigned)DW_DLV_NOCOUNT);
}

static Dwarf_P_Die
new_die(struct inputf *fp, Dwarf_Tag tag)
{
	Dwarf_Error derr;
	Dwarf_P_Die die;

	die = dwarf_new_die(fp->dbg, tag, NULL, NULL, NULL, NULL, &derr);
	DWARF_REQUIRE(die != DW_DLV_BADADDR);
	return (die);
}

static Dwarf_P_Die __unused
new_child_die(struct inputf *fp, Dwarf_Tag tag, Dwarf_P_Die parent)
{
	Dwarf_Error derr;
	Dwarf_P_Die die;

	die = dwarf_new_die(fp->dbg, tag, parent, NULL, NULL, NULL, &derr);
	DWARF_REQUIRE(die != DW_DLV_BADADDR);
	return (die);
}

ATF_TC(empty_cu);
ATF_TC_HEAD(empty_cu, tc)
{
	atf_tc_set_md_var(tc, "descr", "Make sure we handle an empty CU DIE");
}
ATF_TC_BODY(empty_cu, tc)
{
	Ctf *ctf;
	Dwarf_P_Die cu;
	struct inputf f;
	int fd;

	input_file_init(&f);
	cu = new_die(&f, DW_TAG_compile_unit);
	add_die(&f, cu);
	fd = input_file_finalize(&f);

	ctf = ctf_convert_dwarf(fd, NULL);
	ATF_REQUIRE(ctf != NULL);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, empty_cu);

	return (atf_no_error());
}
