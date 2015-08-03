/*-
 * Copyright (c) 2015 Mark Johnston <markj@FreeBSD.org>
 * All rights reserved.
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
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/queue.h>
#include <sys/sbuf.h>
#include <sys/sdt.h>

#include <assert.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <gelf.h>
#include <libelf.h>

#define	ELF_ERR()	(elf_errmsg(elf_errno()))
#define	LOG(...) do {					\
	if (g_verbose)					\
		warnx(__VA_ARGS__);			\
} while (0)

#define	AMD64_CALL	0xe8
#define	AMD64_JMP32	0xe9
#define	AMD64_NOP	0x90
#define	AMD64_RET	0xc3

#define	I386_CALL	0xe8
#define	I386_JMP	0xe9
#define	I386_NOP	0x90
#define	I386_RET	0xc3

/* XXX these should come from sdt.h. */
static const char probe_prefix[] = "__dtrace_sdt_";
static const char sdtobj_prefix[] = "sdt_";

static bool g_verbose = false;

struct probe_site {
	const char	*symname;
	const char	*funcname;
	uint64_t	offset;
	SLIST_ENTRY(probe_site) next;
};

SLIST_HEAD(probe_list, probe_site);

static void	emit_preamble(struct sbuf *);
static void	emit_site(struct sbuf *, struct probe_site *);
static const char *get_section_name(Elf *, Elf_Scn *);
static int	output_drain(void *, const char *, int);
static int	process_reloc(Elf *, GElf_Ehdr *, GElf_Shdr *, Elf_Scn *,
		    uint8_t *, GElf_Addr, GElf_Xword *, struct probe_list *);
static void	process_reloc_section(Elf *, GElf_Ehdr *, GElf_Shdr *,
		    Elf_Scn *, struct probe_list *);
static void	process_obj(const char *, struct sbuf *);
static int	symbol_by_offset(Elf_Scn *scn, uint64_t offset, GElf_Sym *sym,
		    uint64_t *ndx);
static void	symbol_by_index(Elf_Scn *, int, GElf_Sym *);
static void	usage(void);
static void	*xmalloc(size_t);

static void
emit_preamble(struct sbuf *s)
{

	sbuf_cat(s,
    "/* This is an automatically generated file. DO NOT EDIT IT! */\n\n");

	sbuf_cat(s, "#include <sys/cdefs.h>\n");
	sbuf_cat(s, "#include <sys/param.h>\n");
	sbuf_cat(s, "#include <sys/linker_set.h>\n");
	sbuf_cat(s, "#include <sys/queue.h>\n");
	sbuf_cat(s, "#include <sys/sdt.h>\n\n");

	sbuf_cat(s, "void\nsdt_probe_nop(void)\n{\n}\n\n");
}

static void
emit_site(struct sbuf *s, struct probe_site *site)
{
	const char *probe;
	static int uniquifier = 0;

	assert(strlen(probe_prefix) < strlen(site->symname));

	probe = site->symname + strlen(probe_prefix);
	sbuf_printf(s, "extern struct sdt_probe sdtp_%s;\n", probe);
	sbuf_printf(s, "static struct sdt_site sdts_%s%d = {\n", probe,
	    uniquifier);
	sbuf_printf(s, "\t.sdts_probe = &sdtp_%s,\n", probe);
	sbuf_printf(s, "\t.sdts_func = \"%s\",\n", site->funcname);
	sbuf_printf(s, "\t.sdts_offset = 0x%jx,\n", (uintmax_t)site->offset);
	sbuf_printf(s, "};\n");
	sbuf_printf(s, "DATA_SET(sdt_sites_set, sdts_%s%d);\n", probe,
	    uniquifier);

	/*
	 * Create a reference to the currently-undefined probe function. Do
	 * a little dance to ensure we don't define the same function multiple
	 * times.
	 */
	sbuf_printf(s, "#ifndef SDT_PROBE_DEFINED_%s\n", probe);
	sbuf_printf(s, "#define\tSDT_PROBE_DEFINED_%s\n", probe);
	sbuf_printf(s, "__strong_reference(sdt_probe_nop, %s%s);\n",
	    probe_prefix, probe);
	sbuf_printf(s, "#endif\n\n");

	uniquifier++;
}

/*
 * Write the sbuf buffer to the output file.
 */
static int
output_drain(void *arg, const char *data, int len)
{
	int fd;

	fd = *(int *)arg;
	return (write(fd, data, len));
}

/*
 * Return the name of the specified section.
 */
static const char *
get_section_name(Elf *e, Elf_Scn *scn)
{
	GElf_Shdr shdr;
	size_t ndx;

	if (gelf_getshdr(scn, &shdr) != &shdr)
		errx(1, "gelf_getshdr: %s", ELF_ERR());
	if (elf_getshdrstrndx(e, &ndx) != 0)
		errx(1, "elf_getshdrstrndx: %s", ELF_ERR());
	return (elf_strptr(e, ndx, shdr.sh_name));
}

/*
 * Do the work of patching a probe site and recording its location. We use
 * relocations against functions called __dtrace_sdt_* to identify probe sites;
 * other relocations are ignored.
 */
static int
process_reloc(Elf *e, GElf_Ehdr *ehdr, GElf_Shdr *symshdr, Elf_Scn *symscn,
    uint8_t *target, GElf_Addr off, GElf_Xword *info, struct probe_list *plist)
{
	GElf_Sym funcsym, sym;
	struct probe_site *siteinfo;
	const char *funcname, *symname;
	GElf_Xword nulreloc;
	GElf_Addr opcoff;
	uint64_t symndx;
	uint8_t opc;

	symbol_by_index(symscn, GELF_R_SYM(*info), &sym);

	symname = elf_strptr(e, symshdr->sh_link, sym.st_name);
	if (symname == NULL)
		errx(1, "couldn't find symbol name for relocation");

	if (strncmp(symname, probe_prefix, sizeof(probe_prefix) - 1) != 0)
		/* We're not interested in this relocation. */
		return (1);

	/* Sanity checks. */
	if (GELF_ST_TYPE(sym.st_info) != STT_NOTYPE)
		errx(1, "unexpected symbol type %d for %s",
		    GELF_ST_TYPE(sym.st_info), symname);
	if (GELF_ST_BIND(sym.st_info) != STB_GLOBAL)
		errx(1, "unexpected binding %d for %s",
		    GELF_ST_BIND(sym.st_info), symname);

	switch (ehdr->e_machine) {
	case EM_386:
		nulreloc = R_386_NONE;

		/* Sanity checks. */
		if (GELF_R_TYPE(*info) != R_386_32 &&
		    GELF_R_TYPE(*info) != R_386_PC32) {
			if (GELF_R_TYPE(*info) != R_386_NONE)
				errx(1,
			    "unexpected relocation type 0x%jx against %s",
				    (uintmax_t)GELF_R_TYPE(*info), symname);
			/* We've presumably already processed this file. */
			return (1);
		}

		opcoff = off - 1;
		opc = target[opcoff];
		if (opc != I386_CALL && opc != I386_JMP)
			errx(1, "unexpected opcode 0x%x for %s at offset 0x%jx",
			    opc, symname, (uintmax_t)off);
		/* XXX why does the compiler emit these numbers? */
		if (target[off + 0] != 0xfc ||
		    target[off + 1] != 0xff ||
		    target[off + 2] != 0xff ||
		    target[off + 3] != 0xff)
			errx(1, "unexpected addr for %s at offset 0x%jx",
			    symname, (uintmax_t)off);

		/* Overwrite the call site with NOPs. */
		memset(&target[opcoff], I386_NOP, 5);

		/* If this was a tail call, we need to return instead. */
		if (opc == I386_JMP)
			target[opcoff] = I386_RET;
		break;
	case EM_AMD64:
		nulreloc = R_X86_64_NONE;

		/* Sanity checks. */
		if (GELF_R_TYPE(*info) != R_X86_64_64 &&
		    GELF_R_TYPE(*info) != R_X86_64_PC32) {
			if (GELF_R_TYPE(*info) != R_X86_64_NONE)
				errx(1,
			    "unexpected relocation type 0x%jx against %s",
				    (uintmax_t)GELF_R_TYPE(*info), symname);
			/* We've presumably already processed this file. */
			return (1);
		}

		opcoff = off - 1;
		opc = target[opcoff];
		if (opc != AMD64_CALL && opc != AMD64_JMP32)
			errx(1, "unexpected opcode 0x%x for %s at offset 0x%jx",
			    opc, symname, (uintmax_t)off);
		if (target[off + 0] != 0 ||
		    target[off + 1] != 0 ||
		    target[off + 2] != 0 ||
		    target[off + 3] != 0)
			errx(1, "unexpected addr for %s at offset 0x%jx",
			    symname, (uintmax_t)off);

		/* Overwrite the call site with NOPs. */
		memset(&target[opcoff], AMD64_NOP, 5);

		/* If this was a tail call, we need to return instead. */
		if (opc == AMD64_JMP32)
			target[opcoff] = AMD64_RET;
		break;
	default:
		errx(1, "unhandled machine type 0x%x", ehdr->e_machine);
	}

	/* Make sure the linker ignores this relocation. */
	*info &= ~GELF_R_TYPE(*info);
	*info |= nulreloc;

	LOG("updated relocation for %s at 0x%jx", symname, (uintmax_t)opcoff);

	if (symbol_by_offset(symscn, off, &funcsym, &symndx) != 1)
		errx(1, "failed to look up function for probe %s", symname);
	funcname = elf_strptr(e, symshdr->sh_link, funcsym.st_name);
	if (funcname == NULL)
		errx(1, "failed to look up function name for probe %s",
		    symname);

	siteinfo = xmalloc(sizeof(*siteinfo));
	siteinfo->symname = symname;
	siteinfo->funcname = funcname;
	siteinfo->offset = off - funcsym.st_value;

	SLIST_INSERT_HEAD(plist, siteinfo, next);

	return (0);
}

/*
 * Look for relocations against DTrace probe stubs. Such relocations are used to
 * populate the probe instance list (plist) and then invalidated, since we
 * overwrite the call site with NOPs and no longer need the relocation operation.
 */
static void
process_reloc_section(Elf *e, GElf_Ehdr *ehdr, GElf_Shdr *shdr, Elf_Scn *scn,
    struct probe_list *plist)
{
	GElf_Shdr symshdr;
	GElf_Rel rel;
	GElf_Rela rela;
	Elf_Data *reldata, *targdata;
	Elf_Scn *symscn, *targscn;
	const char *name;
	u_int i;
	int ret;

	if ((targscn = elf_getscn(e, shdr->sh_info)) == NULL)
		errx(1, "failed to look up relocation section: %s", ELF_ERR());
	if ((targdata = elf_getdata(targscn, NULL)) == NULL)
		errx(1, "failed to look up target section data: %s", ELF_ERR());

	/* We only want to process relocations against the text section. */
	name = get_section_name(e, targscn);
	if (strcmp(name, ".text") != 0) {
		LOG("skipping relocation section for %s", name);
		return;
	}

	if ((symscn = elf_getscn(e, shdr->sh_link)) == NULL)
		errx(1, "failed to look up symbol table: %s", ELF_ERR());
	if (gelf_getshdr(symscn, &symshdr) == NULL)
		errx(1, "failed to look up symbol table header: %s", ELF_ERR());

	i = 0;
	for (reldata = NULL; (reldata = elf_getdata(scn, reldata)) != NULL; ) {
		for (; i < shdr->sh_size / shdr->sh_entsize; i++) {
			if (shdr->sh_type == SHT_REL) {
				if (gelf_getrel(reldata, i, &rel) == NULL)
					errx(1, "gelf_getrel: %s", ELF_ERR());
				ret = process_reloc(e, ehdr, &symshdr, symscn,
				    targdata->d_buf, rel.r_offset, &rel.r_info,
				    plist);
				if (ret == 0 &&
				    gelf_update_rel(reldata, i, &rel) == 0)
					errx(1, "gelf_update_rel: %s",
					    ELF_ERR());
			} else {
				assert(shdr->sh_type == SHT_RELA);
				if (gelf_getrela(reldata, i, &rela) == NULL)
					errx(1, "gelf_getrela: %s", ELF_ERR());
				ret = process_reloc(e, ehdr, &symshdr, symscn,
				    targdata->d_buf, rela.r_offset,
				    &rela.r_info, plist);
				if (ret == 0 &&
				    gelf_update_rela(reldata, i, &rela) == 0)
					errx(1, "gelf_update_rela: %s",
					    ELF_ERR());
			}

			/*
			 * We've updated the relocation and the corresponding
			 * text section.
			 */
			if (ret == 0) {
				if (elf_flagdata(targdata, ELF_C_SET,
				    ELF_F_DIRTY) == 0)
					errx(1, "elf_flagdata: %s", ELF_ERR());
				if (elf_flagdata(reldata, ELF_C_SET,
				    ELF_F_DIRTY) == 0)
					errx(1, "elf_flagdata: %s", ELF_ERR());
			}
		}
	}
}

/*
 * Process an input object file. This function choreographs the work done by
 * sdtpatch: it first processes all the relocations against the DTrace probe
 * stubs and uses the information from those relocations over write probe call
 * sites with NOPs, and to build up a list (plist) of probe sites. Then it
 * generates C code to define structs containing probe site information.
 */
static void
process_obj(const char *obj, struct sbuf *s)
{
	struct probe_list plist;
	struct probe_site *site;
	GElf_Ehdr ehdr;
	GElf_Shdr shdr;
	Elf_Scn *scn;
	Elf *e;
	int fd;

	LOG("processing %s", obj);

	if ((fd = open(obj, O_RDWR)) < 0)
		err(1, "failed to open %s", obj);

	if ((e = elf_begin(fd, ELF_C_RDWR, NULL)) == NULL)
		errx(1, "elf_begin: %s", ELF_ERR());

	if (gelf_getehdr(e, &ehdr) == NULL)
		errx(1, "gelf_getehdr: %s", ELF_ERR());
	if (ehdr.e_type != ET_REL) {
		warnx("invalid ELF type for '%s'", obj);
		return;
	}

	SLIST_INIT(&plist);

	/*
	 * Step 1:
	 *   Hijack relocations for DTrace probe stub calls.
	 */

	for (scn = NULL; (scn = elf_nextscn(e, scn)) != NULL; ) {
		if (gelf_getshdr(scn, &shdr) == NULL)
			errx(1, "gelf_getshdr: %s", ELF_ERR());

		if (shdr.sh_type == SHT_REL || shdr.sh_type == SHT_RELA)
			process_reloc_section(e, &ehdr, &shdr, scn, &plist);
	}

	if (SLIST_EMPTY(&plist)) {
		/* No probe instances in this object file, we're done. */
		LOG("no probes found in %s", obj);
		return;
	}

	/*
	 * Step 2:
	 *   Record all of the instance sites. Don't close the ELF file before
	 *   we've logged everything we need, since we hold references into its
	 *   string table.
	 */

	while ((site = SLIST_FIRST(&plist)) != NULL) {
		LOG("emitting site definition for %s:%s",
		    site->funcname, site->symname);
		SLIST_REMOVE_HEAD(&plist, next);
		emit_site(s, site);
		free(site);
	}

	/*
	 * Step 3:
	 *   Write out the modified ELF file.
	 */

	if (elf_update(e, ELF_C_WRITE) == -1)
		errx(1, "elf_update: %s", ELF_ERR());

	(void)elf_end(e);
	(void)close(fd);
}

/*
 * Look up a function symbol by offset. Return 1 if a matching symbol was found,
 * 0 otherwise.
 */
static int
symbol_by_offset(Elf_Scn *scn, uint64_t offset, GElf_Sym *sym, uint64_t *ndx)
{
	GElf_Shdr shdr;
	Elf_Data *data;
	u_int i;

	if (gelf_getshdr(scn, &shdr) != &shdr)
		errx(1, "gelf_getshdr: %s", ELF_ERR());

	*ndx = 0;
	for (data = NULL; (data = elf_getdata(scn, data)) != NULL; ) {
		for (i = 0; i * shdr.sh_entsize < data->d_size; i++, (*ndx)++) {
			if (gelf_getsym(data, i, sym) == NULL)
				errx(1, "gelf_getsym: %s", ELF_ERR());
			if (GELF_ST_TYPE(sym->st_info) == STT_FUNC &&
			    offset >= sym->st_value &&
			    offset < sym->st_value + sym->st_size)
				return (1); /* There's my chippy. */
		}
	}
	return (0);
}

/*
 * Retrieve the symbol at index ndx in the specified symbol table.
 */
static void
symbol_by_index(Elf_Scn *symtab, int ndx, GElf_Sym *sym)
{
	Elf_Data *symdata;

	if ((symdata = elf_getdata(symtab, NULL)) == NULL)
		errx(1, "couldn't find symbol table data: %s", ELF_ERR());
	if (gelf_getsym(symdata, ndx, sym) == NULL)
		errx(1, "couldn't read symbol at index %d: %s", ndx, ELF_ERR());
}

static void *
xmalloc(size_t n)
{
	void *ret;

	if ((ret = malloc(n)) == NULL)
		errx(1, "malloc");
	return (ret);
}

static void
usage(void)
{

	fprintf(stderr, "%s: [-o <outfile>] [-v] <obj> [<obj> ...]\n",
	    getprogname());
	exit(1);
}

int
main(int argc, char **argv)
{
	struct sbuf s;
	const char *outfile;
	int ch, i, fd;

	outfile = NULL;
	while ((ch = getopt(argc, argv, "o:v")) != -1) {
		switch (ch) {
		case 'o':
			outfile = optarg;
			break;
		case 'v':
			g_verbose = true;
			break;
		case '?':
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	if (argc < 1)
		usage();

	if (elf_version(EV_CURRENT) == EV_NONE)
		errx(1, "ELF library too old");

	if (outfile != NULL) {
		fd = open(outfile, O_WRONLY | O_TRUNC | O_CREAT, 0644);
		if (fd < 0)
			err(1, "opening %s", outfile);
	} else {
		fd = fileno(stdout);
	}

	if (sbuf_new(&s, NULL, 0, SBUF_AUTOEXTEND) == NULL)
		errx(1, "sbuf_new failed");
	sbuf_set_drain(&s, output_drain, &fd);

	emit_preamble(&s);
	for (i = 0; i < argc; i++)
		process_obj(argv[i], &s);

	if (sbuf_finish(&s) != 0)
		errx(1, "sbuf_finish failed");
	sbuf_delete(&s);

	if (outfile != NULL)
		close(fd);

	return (0);
}
