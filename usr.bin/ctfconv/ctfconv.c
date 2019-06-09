#include <sys/capsicum.h>
#include <sys/queue.h>
#include <sys/tree.h>

#include <assert.h>
#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <dwarf.h>
#include <libdwarf.h>

static unsigned int
strhash(const char *s)
{
	unsigned int hash;

	for (hash = 2166136261; *s != '\0'; s++)
		hash = (hash ^ *s) * 16777619;
	return (hash);
}

static int
namecmp(const char *n1, const char *n2)
{

	if (n1 == n2)
		return (0);
	if ((n1 == NULL && n2 != NULL) ||
	    (n1 != NULL && n2 == NULL))
		return (1);
	return (strcmp(n1, n2));
}

static void *
xcalloc(size_t n, size_t sz)
{
	void *ret;

	ret = calloc(n, sz);
	if (ret == NULL)
		err(1, "cmalloc");
	return (ret);
}

static void *
xmalloc(size_t sz)
{
	void *ret;

	ret = malloc(sz);
	if (ret == NULL)
		err(1, "malloc");
	return (ret);
}

#define	DIE_ATTRVAL_GETTER(f, t)					\
static bool								\
die_attrval_##f(Dwarf_Die die, Dwarf_Half tag, t *valp, bool req)	\
{									\
	Dwarf_Error derr;						\
	Dwarf_Off off;							\
	int ret;							\
									\
	ret = dwarf_attrval_##f(die, tag, valp, &derr);			\
	if (ret == DW_DLV_OK)						\
		return (true);						\
	if (ret == DW_DLV_NO_ENTRY && !req)				\
		return (false);						\
	off = -1;							\
	(void)dwarf_dieoffset(die, &off, NULL);				\
	errx(1, "%s(%u at %#lx): %s", __func__, tag, off, dwarf_errmsg(derr)); \
}
DIE_ATTRVAL_GETTER(signed, Dwarf_Signed);
DIE_ATTRVAL_GETTER(unsigned, Dwarf_Unsigned);
DIE_ATTRVAL_GETTER(flag, Dwarf_Bool);

static bool
die_hasattr(Dwarf_Die die, Dwarf_Half tag)
{
	Dwarf_Bool present;
	Dwarf_Error derr;

	if (dwarf_hasattr(die, tag, &present, &derr) != DW_DLV_OK)
		errx(1, "dwarf_hasattr: %s", dwarf_errmsg(derr));
	return (present);
}

static char *
die_name(Dwarf_Die die)
{
	Dwarf_Error derr;
	char *ret;
	int error;

	error = dwarf_diename(die, &ret, &derr);
	switch (error) {
	case DW_DLV_OK:
		return (ret);
	default:
		return (NULL);
	}
}

static Dwarf_Off
die_typeoff(Dwarf_Die die)
{
	Dwarf_Attribute attr;
	Dwarf_Error derr;
	Dwarf_Half form;
	Dwarf_Off off;

	if (dwarf_attr(die, DW_AT_type, &attr, &derr) != DW_DLV_OK)
		errx(1, "dwarf_attr: %s", dwarf_errmsg(derr));
	if (dwarf_whatform(attr, &form, &derr) != DW_DLV_OK)
		errx(1, "dwarf_whatform: %s", dwarf_errmsg(derr));
	if (dwarf_global_formref(attr, &off, &derr) != DW_DLV_OK)
		errx(1, "dwarf_global_formref: %s", dwarf_errmsg(derr));
	return (off);
}

struct tnode;
struct tmember;

/* XXX use chunks */
struct tmember {
	STAILQ_ENTRY(tmember) tm_next;
	const char	*tm_name;

	union {
		struct {
			Dwarf_Unsigned	cval;
		} tm_enum;

		struct {
			Dwarf_Off	off;
			bool		unspecified;
		} tm_compound;
	};
};
STAILQ_HEAD(tmember_list, tmember);

enum tnodekind {
	TERMINAL = 1,
	REFERENCE,
	COMPOUND,
};

struct tnode {
	Dwarf_Off	t_off;
	Dwarf_Half	t_tag;
	Dwarf_Unsigned	t_bsz;
	const char	*t_name;
	struct cuctx	*t_cuctx;
	int		t_doffrefs;
	enum tnodekind	t_kind;
	uint64_t	t_generation;
	bool		t_canonical;

	union {
		struct {
			Dwarf_Signed	enc;
		} t_base;

		struct {
			struct tmember_list members;
		} t_enum;

		struct {
			struct tnode	*type;
			Dwarf_Off	off;
			int		count;
		} t_ref;

		struct {
			struct tmember_list members;
		} t_sou;

		struct {
			struct tmember_list args;
		} t_subr;
	};

	/* Canonical references. */
	LIST_HEAD(, tnode) t_crefs;
	/* Resolved references. */
	LIST_HEAD(, tnode) t_refs;

	/* Per-tag lookup linkage. */
	union {
		STAILQ_ENTRY(tnode) t_stailq;
		TAILQ_ENTRY(tnode) t_tailq;
		LIST_ENTRY(tnode) t_list;
	};
};
STAILQ_HEAD(tnode_stailq, tnode);
TAILQ_HEAD(tnode_tailq, tnode);
LIST_HEAD(tnode_list, tnode);

#define	BASE_TYPE_HASHSZ	128
static struct tnode_stailq g_base_types[BASE_TYPE_HASHSZ];
#define	ENUM_TYPE_HASHSZ	1024
static struct tnode_stailq g_enum_types[ENUM_TYPE_HASHSZ];
#define	STRUCT_TYPE_HASHSZ	(16 * 1024)
#define	UNION_TYPE_HASHSZ	(16 * 1024)
static struct tnode_list g_struct_types[STRUCT_TYPE_HASHSZ];
static struct tnode_list g_union_types[UNION_TYPE_HASHSZ];

static struct tnode_tailq g_dangling;

struct doff {
	Dwarf_Off	d_off;
	struct tnode	*d_ref;
	RB_ENTRY(doff)	d_link;
};

static int
doffcmp(struct doff *a, struct doff *b)
{

	if (a->d_off < b->d_off)
		return (-1);
	return (a->d_off > b->d_off);
}
RB_HEAD(doffmap, doff);
RB_GENERATE_STATIC(doffmap, doff, d_link, doffcmp);

struct softc;

struct cuctx {
	struct softc	*cu_softc;
	Dwarf_Die	cu_die;
	struct doffmap	cu_types;
	SLIST_ENTRY(cuctx) cu_link;
};

struct softc {
	Dwarf_Debug		sc_dbg;
	struct tnode		sc_void;
	SLIST_HEAD(, cuctx)	sc_cus;
};

static void doffmap_add_ref(struct cuctx *cuctx, struct tnode *t,
    Dwarf_Off off);

static struct cuctx *
cuctx_new(struct softc *sc, Dwarf_Die cu)
{
	struct cuctx *cuctx;

	cuctx = xmalloc(sizeof(*cuctx));
	cuctx->cu_softc = sc;
	cuctx->cu_die = cu;
	RB_INIT(&cuctx->cu_types);
	SLIST_INSERT_HEAD(&sc->sc_cus, cuctx, cu_link);
	return (cuctx);
}

static void
doffmap_add_ref(struct cuctx *cuctx, struct tnode *t, Dwarf_Off off)
{
	struct doff *d;

	d = xmalloc(sizeof(*d));
	d->d_off = off;
	d->d_ref = t;
	RB_INSERT(doffmap, &cuctx->cu_types, d);
	t->t_doffrefs++;
}

static struct tnode *
doffmap_lookup(struct cuctx *cuctx, Dwarf_Off off)
{
	struct doff *d, key;

	key.d_off = off;
	d = RB_FIND(doffmap, &cuctx->cu_types, &key);
	return (d != NULL ? d->d_ref : NULL);
}

static void
doffmap_remap(struct tnode *t, struct tnode *ref)
{
	struct doff *d, key;

	key.d_off = t->t_off;
	d = RB_FIND(doffmap, &t->t_cuctx->cu_types, &key);

	assert(d != NULL);
	assert(d->d_ref == t);
	assert(!t->t_canonical);
	assert(t->t_doffrefs == 1);
	t->t_doffrefs--;
	d->d_ref = ref;
}

static void	dispatch_tag(struct cuctx *cuctx, Dwarf_Die die,
		    Dwarf_Half tag);

static bool
tnode_is_terminal(const struct tnode *t)
{

	return (t->t_kind == TERMINAL);
}

static bool
tnode_is_reference(const struct tnode *t)
{

	return (t->t_kind == REFERENCE);
}

static bool
tnode_is_canonical(const struct tnode *t)
{

	return (t->t_canonical);
}

static bool
tnode_is_compound(const struct tnode *t)
{

	return (t->t_kind == COMPOUND);
}

static struct tnode *
tnode_new(struct cuctx *cuctx, Dwarf_Half tag)
{
	struct tnode *t;

	t = xcalloc(1, sizeof(*t));
	t->t_tag = tag;
	LIST_INIT(&t->t_crefs);
	LIST_INIT(&t->t_refs);
	switch (tag) {
	case DW_TAG_base_type:
	case DW_TAG_enumeration_type:
		t->t_kind = TERMINAL;
		break;
	case DW_TAG_array_type:
	case DW_TAG_const_type:
	case DW_TAG_pointer_type:
	case DW_TAG_restrict_type:
	case DW_TAG_typedef:
	case DW_TAG_volatile_type:
		t->t_kind = REFERENCE;
		break;
	case DW_TAG_structure_type:
	case DW_TAG_union_type:
	case DW_TAG_subroutine_type:
		t->t_kind = COMPOUND;
		break;
	}
	assert(tnode_is_terminal(t) || tnode_is_reference(t) ||
	    tnode_is_compound(t));
	t->t_cuctx = cuctx;
	return (t);
}

static void
tnode_free(struct tnode *t)
{
	struct tmember *tm;

	assert(t->t_doffrefs == 0);
	assert(LIST_EMPTY(&t->t_refs));
	assert(LIST_EMPTY(&t->t_crefs));

	if (t->t_tag == DW_TAG_enumeration_type) {
		while ((tm = STAILQ_FIRST(&t->t_enum.members)) != NULL) {
			STAILQ_REMOVE_HEAD(&t->t_enum.members, tm_next);
			free(tm);
		}
	} else if (t->t_tag == DW_TAG_structure_type ||
	    t->t_tag == DW_TAG_union_type) {
		while ((tm = STAILQ_FIRST(&t->t_sou.members)) != NULL) {
			STAILQ_REMOVE_HEAD(&t->t_sou.members, tm_next);
			free(tm);
		}
	}
	free(t);
}

static struct tmember *
tmember_new(const char *name)
{
	struct tmember *m;

	m = xmalloc(sizeof(*m));
	m->tm_name = name;
	return (m);
}

static bool
tnode_reference_equiv(struct tnode *t, struct tnode *s)
{

	assert(tnode_is_reference(t));
	assert(tnode_is_reference(s));

	if (t->t_tag != s->t_tag)
		return (false);

	switch (t->t_tag) {
	case DW_TAG_array_type:
		return (t->t_ref.count == s->t_ref.count);
	case DW_TAG_typedef:
		return (strcmp(t->t_name, s->t_name) == 0);
	case DW_TAG_const_type:
	case DW_TAG_pointer_type:
	case DW_TAG_restrict_type:
	case DW_TAG_volatile_type:
		return (true);
	default:
		errx(1, "unhandled tag type %#x", t->t_tag);
	}
}

static struct tnode *
tnode_new_reference(struct cuctx *cuctx, Dwarf_Off toff, Dwarf_Off dieoff,
    Dwarf_Half tag, const char *name, int count)
{
	struct tnode *ref, *t;

	if (toff == 0)
		ref = &cuctx->cu_softc->sc_void;
	else
		ref = doffmap_lookup(cuctx, toff);
	if (ref != NULL) {
		if (tnode_is_canonical(ref)) {
			/* Look for an existing canonical reference. */
			LIST_FOREACH(t, &ref->t_crefs, t_list) {
				if (t->t_tag == tag && (tag != DW_TAG_typedef ||
				    strcmp(t->t_name, name) == 0) &&
				    (tag != DW_TAG_array_type ||
				    t->t_ref.count == count))
					break;
			}
			if (t == NULL) {
				t = tnode_new(cuctx, tag);
				t->t_name = name;
				t->t_off = dieoff;
				t->t_ref.type = ref;
				t->t_ref.off = toff;
				t->t_ref.count = count;
				t->t_canonical = true;
				LIST_INSERT_HEAD(&ref->t_crefs, t, t_list);
			}
		} else {
			t = tnode_new(cuctx, tag);
			t->t_name = name;
			t->t_off = dieoff;
			t->t_ref.type = ref;
			t->t_ref.off = toff;
			t->t_ref.count = count;
			t->t_canonical = false;
			LIST_INSERT_HEAD(&ref->t_refs, t, t_list);
		}
	} else {
		t = tnode_new(cuctx, tag);
		t->t_name = name;
		t->t_off = dieoff;
		t->t_ref.type = ref;
		t->t_ref.off = toff;
		t->t_ref.count = count;
		t->t_canonical = false;
		TAILQ_INSERT_HEAD(&g_dangling, t, t_tailq);
	}

	return (t);
}

static void
tnode_new_array_type(struct cuctx *cuctx, Dwarf_Die die)
{
	Dwarf_Die child;
	Dwarf_Error derr;
	Dwarf_Half tag;
	Dwarf_Off dieoff, toff;
	Dwarf_Unsigned u;
	struct tnode *t;
	int count;

	if (dwarf_dieoffset(die, &dieoff, &derr) != DW_DLV_OK)
		errx(1, "dwarf_dieoffset: %s", dwarf_errmsg(derr));

	if (dwarf_child(die, &child, &derr) != DW_DLV_OK)
		errx(1, "dwarf_child: %s", dwarf_errmsg(derr));
	if (dwarf_tag(child, &tag, &derr) != DW_DLV_OK)
		errx(1, "dwarf_tag: %s", dwarf_errmsg(derr));
	switch (tag) {
	case DW_TAG_subrange_type:
		if (die_attrval_unsigned(child, DW_AT_upper_bound, &u,
		    false)) {
			count = (int)u + 1;
			break;
		} else if (die_attrval_unsigned(child, DW_AT_count, &u,
		    false)) {
			count = (int)u;
			break;
		} else {
			count = 0;
			break;
		}
		/* FALLTHROUGH */
	default:
		errx(1, "tnode_new_array_type: unhandled array child DIE");
	}

	dwarf_dealloc(cuctx->cu_softc->sc_dbg, child, DW_DLA_DIE);

	toff = die_typeoff(die);
	t = tnode_new_reference(cuctx, toff, dieoff, DW_TAG_array_type, NULL,
	    count);
	doffmap_add_ref(cuctx, t, dieoff);
}

static void
tnode_new_base_type(struct cuctx *cuctx, Dwarf_Die die)
{
	Dwarf_Error derr;
	Dwarf_Signed enc;
	Dwarf_Off off;
	Dwarf_Unsigned bsz;
	struct tnode_stailq *l;
	struct tnode *t;
	char *name;

	die_attrval_unsigned(die, DW_AT_byte_size, &bsz, true);
	die_attrval_signed(die, DW_AT_encoding, &enc, true);

	if (dwarf_dieoffset(die, &off, &derr) != DW_DLV_OK)
		errx(1, "dwarf_dieoffset: %s", dwarf_errmsg(derr));

	name = die_name(die);
	l = &g_base_types[strhash(name) & (BASE_TYPE_HASHSZ - 1)];
	STAILQ_FOREACH(t, l, t_stailq) {
		if (strcmp(name, t->t_name) == 0 &&
		    t->t_bsz == bsz &&
		    t->t_base.enc == enc)
			break;
	}
	if (t == NULL) {
		t = tnode_new(cuctx, DW_TAG_base_type);
		t->t_name = name;
		t->t_bsz = bsz;
		t->t_off = off;
		t->t_canonical = true;
		t->t_base.enc = enc;

		STAILQ_INSERT_TAIL(l, t, t_stailq);
	}

	doffmap_add_ref(cuctx, t, off);
}

static void
tnode_new_const_type(struct cuctx *cuctx, Dwarf_Die die)
{
	Dwarf_Error derr;
	Dwarf_Off dieoff, toff;
	struct tnode *t;

	if (dwarf_dieoffset(die, &dieoff, &derr) != DW_DLV_OK)
		errx(1, "dwarf_dieoffset: %s", dwarf_errmsg(derr));

	if (die_hasattr(die, DW_AT_type))
		toff = die_typeoff(die);
	else
		toff = 0;
	t = tnode_new_reference(cuctx, toff, dieoff, DW_TAG_const_type, NULL, 0);
	doffmap_add_ref(cuctx, t, dieoff);
}

static void
tnode_new_enumeration_type(struct cuctx *cuctx, Dwarf_Die die)
{
	Dwarf_Debug dbg;
	Dwarf_Die child, child1;
	Dwarf_Error derr;
	Dwarf_Half tag;
	Dwarf_Off off;
	Dwarf_Unsigned bsz;
	struct tmember *m, *m1;
	struct tnode *t, *t1;
	struct tnode_stailq *l;
	const char *name;
	u_int hash;
	int ret;

	dbg = cuctx->cu_softc->sc_dbg;

	ret = dwarf_child(die, &child, &derr);
	assert(ret == DW_DLV_OK);

	die_attrval_unsigned(die, DW_AT_byte_size, &bsz, true);
	name = die_name(die);

	if (dwarf_dieoffset(die, &off, &derr) != DW_DLV_OK)
		errx(1, "dwarf_dieoffset: %s", dwarf_errmsg(derr));

	t = tnode_new(cuctx, DW_TAG_enumeration_type);
	t->t_name = name;
	t->t_bsz = bsz;
	t->t_canonical = true;

	if (name != NULL)
		hash = strhash(name);
	else
		hash = strhash(die_name(child));

	child1 = NULL;
	STAILQ_INIT(&t->t_enum.members);
	do {
		if (child1 != NULL) {
			dwarf_dealloc(dbg, child, DW_DLA_DIE);
			child = child1;
		}

		m = tmember_new(die_name(child));
		ret = dwarf_tag(child, &tag, &derr);
		assert(ret == DW_DLV_OK);
		assert(tag == DW_TAG_enumerator);

		/* XXX use getter */
		if (dwarf_attrval_unsigned(child, DW_AT_const_value,
		    &m->tm_enum.cval, NULL) != DW_DLV_OK)
			if (dwarf_attrval_signed(child, DW_AT_const_value,
			    (Dwarf_Signed *)&m->tm_enum.cval, NULL) !=
			    DW_DLV_OK)
				errx(1, "failed to find const value for enum");

		STAILQ_INSERT_TAIL(&t->t_enum.members, m, tm_next);
	} while ((ret = dwarf_siblingof(dbg, child, &child1, &derr)) ==
	    DW_DLV_OK);

	if (ret != DW_DLV_NO_ENTRY)
		errx(1, "dwarf_siblingof: %s", dwarf_errmsg(derr));
	dwarf_dealloc(dbg, child, DW_DLA_DIE);

	l = &g_enum_types[hash & (ENUM_TYPE_HASHSZ - 1)];
	STAILQ_FOREACH(t1, l, t_stailq) {
		assert(t1->t_tag == DW_TAG_enumeration_type);

		if (namecmp(name, t1->t_name) != 0)
			continue;
		if (t1->t_bsz != bsz)
			continue;

		for (m = STAILQ_FIRST(&t->t_enum.members),
		    m1 = STAILQ_FIRST(&t->t_enum.members);
		    m != NULL && m1 != NULL;
		    m = STAILQ_NEXT(m, tm_next),
		    m1 = STAILQ_NEXT(m1, tm_next)) {
			if (strcmp(m->tm_name, m1->tm_name) != 0)
				break;
			if (m->tm_enum.cval != m1->tm_enum.cval)
				break;
		}

		if (m == NULL && m1 == NULL)
			break;
	}
	if (t1 == NULL) {
		STAILQ_INSERT_TAIL(l, t, t_stailq);
	} else {
		tnode_free(t);
		t = t1;
	}
	doffmap_add_ref(cuctx, t, off);
}

static void
tnode_new_pointer_type(struct cuctx *cuctx, Dwarf_Die die)
{
	Dwarf_Error derr;
	Dwarf_Off dieoff, toff;
	struct tnode *t;

	if (dwarf_dieoffset(die, &dieoff, &derr) != DW_DLV_OK)
		errx(1, "dwarf_dieoffset: %s", dwarf_errmsg(derr));

	if (die_hasattr(die, DW_AT_type))
		toff = die_typeoff(die);
	else
		toff = 0;
	t = tnode_new_reference(cuctx, toff, dieoff, DW_TAG_pointer_type, NULL, 0);
	doffmap_add_ref(cuctx, t, dieoff);
}

static void
tnode_new_restrict_type(struct cuctx *cuctx, Dwarf_Die die)
{
	Dwarf_Error derr;
	Dwarf_Off dieoff, toff;
	struct tnode *t;

	if (dwarf_dieoffset(die, &dieoff, &derr) != DW_DLV_OK)
		errx(1, "dwarf_dieoffset: %s", dwarf_errmsg(derr));

	if (die_hasattr(die, DW_AT_type))
		toff = die_typeoff(die);
	else
		toff = 0;
	t = tnode_new_reference(cuctx, toff, dieoff, DW_TAG_restrict_type,
	    NULL, 0);
	doffmap_add_ref(cuctx, t, dieoff);
}

static void
tnode_new_structure_type(struct cuctx *cuctx, Dwarf_Die die)
{
	Dwarf_Bool decl;
	Dwarf_Debug dbg;
	Dwarf_Die child, child1;
	Dwarf_Error derr;
	Dwarf_Half tag;
	struct tmember *m;
	struct tnode *t;
	struct tnode_list *l;
	int ret;

	dbg = cuctx->cu_softc->sc_dbg;

	t = tnode_new(cuctx, DW_TAG_structure_type);
	if (dwarf_dieoffset(die, &t->t_off, &derr) != DW_DLV_OK)
		errx(1, "dwarf_dieoffset: %s", dwarf_errmsg(derr));
	t->t_name = die_name(die);

	if (!die_attrval_flag(die, DW_AT_declaration, &decl, false)) {
		die_attrval_unsigned(die, DW_AT_byte_size, &t->t_bsz, true);
	}

	/* XXX empty structure */
	ret = dwarf_child(die, &child, &derr);
	if (ret == DW_DLV_NO_ENTRY)
		goto done;
	if (ret != DW_DLV_OK)
		errx(1, "dwarf_child: %s", t->t_name, dwarf_errmsg(derr));

	child1 = NULL;
	STAILQ_INIT(&t->t_sou.members);
	do {
		if (child1 != NULL) {
			dwarf_dealloc(dbg, child, DW_DLA_DIE);
			child = child1;
		}

		m = tmember_new(die_name(child));

		ret = dwarf_tag(child, &tag, &derr);
		assert(ret == DW_DLV_OK);
		assert(tag == DW_TAG_member || tag == DW_TAG_structure_type ||
		    tag == DW_TAG_union_type || tag == DW_TAG_enumeration_type);
		if (tag != DW_TAG_member) {
			dispatch_tag(cuctx, child, tag);
		} else {
			m->tm_compound.off = die_typeoff(child);
			STAILQ_INSERT_TAIL(&t->t_sou.members, m, tm_next);
		}
	} while ((ret = dwarf_siblingof(dbg, child, &child1, &derr)) ==
	    DW_DLV_OK);
	if (ret != DW_DLV_NO_ENTRY)
		errx(1, "dwarf_siblingof: %s", dwarf_errmsg(derr));
	dwarf_dealloc(dbg, child, DW_DLA_DIE);

	if (t->t_name != NULL) {
		l = &g_struct_types[strhash(t->t_name) &
		    (STRUCT_TYPE_HASHSZ - 1)];
		LIST_INSERT_HEAD(l, t, t_list);
	}
done:
	doffmap_add_ref(cuctx, t, t->t_off);
}

static void
tnode_new_subroutine_type(struct cuctx *cuctx, Dwarf_Die die)
{
	Dwarf_Debug dbg;
	Dwarf_Die child, child1;
	Dwarf_Error derr;
	Dwarf_Half tag;
	struct tnode *t;
	struct tmember *m;
	int ret;

	dbg = cuctx->cu_softc->sc_dbg;

	t = tnode_new(cuctx, DW_TAG_subroutine_type);
	if (dwarf_dieoffset(die, &t->t_off, &derr) != DW_DLV_OK)
		errx(1, "dwarf_dieoffset: %s", dwarf_errmsg(derr));

	ret = dwarf_child(die, &child, &derr);
	if (ret == DW_DLV_NO_ENTRY)
		goto done;
	if (ret != DW_DLV_OK)
		errx(1, "dwarf_child: %s", dwarf_errmsg(derr));
	child1 = NULL;
	STAILQ_INIT(&t->t_subr.args);
	do {
		if (child1 != NULL) {
			dwarf_dealloc(dbg, child, DW_DLA_DIE);
			child = child1;
		}

		m = tmember_new(NULL);

		ret = dwarf_tag(child, &tag, &derr);
		assert(ret == DW_DLV_OK);
		assert(tag == DW_TAG_formal_parameter ||
		    tag == DW_TAG_unspecified_parameters);

		if (tag == DW_TAG_formal_parameter) {
			m->tm_compound.off = die_typeoff(child);
			assert(m->tm_compound.off != 0);
			m->tm_compound.unspecified = false;
		} else {
			m->tm_compound.off = 0;
			m->tm_compound.unspecified = true;
		}
		STAILQ_INSERT_TAIL(&t->t_subr.args, m, tm_next);
	} while ((ret = dwarf_siblingof(dbg, child, &child1, &derr)) ==
	    DW_DLV_OK);

	dwarf_dealloc(dbg, child, DW_DLA_DIE);

done:
	doffmap_add_ref(cuctx, t, t->t_off);
}

static void
tnode_new_typedef(struct cuctx *cuctx, Dwarf_Die die)
{
	Dwarf_Error derr;
	Dwarf_Off dieoff, toff;
	struct tnode *t;
	const char *name;

	if (dwarf_dieoffset(die, &dieoff, &derr) != DW_DLV_OK)
		errx(1, "dwarf_dieoffset: %s", dwarf_errmsg(derr));

	if (die_hasattr(die, DW_AT_type))
		toff = die_typeoff(die);
	else
		toff = 0;
	name = die_name(die);
	t = tnode_new_reference(cuctx, toff, dieoff, DW_TAG_typedef, name, 0);

	doffmap_add_ref(cuctx, t, dieoff);
}

static void
tnode_new_union_type(struct cuctx *cuctx, Dwarf_Die die)
{
	Dwarf_Bool decl;
	Dwarf_Debug dbg;
	Dwarf_Die child, child1;
	Dwarf_Error derr;
	Dwarf_Half tag;
	struct tmember *m;
	struct tnode *t;
	struct tnode_list *l;
	int ret;

	dbg = cuctx->cu_softc->sc_dbg;

	t = tnode_new(cuctx, DW_TAG_union_type);

	if (dwarf_dieoffset(die, &t->t_off, &derr) != DW_DLV_OK)
		errx(1, "dwarf_dieoffset: %s", dwarf_errmsg(derr));
	t->t_name = die_name(die);

	if (!die_attrval_flag(die, DW_AT_declaration, &decl, false)) {
		die_attrval_unsigned(die, DW_AT_byte_size, &t->t_bsz, true);
	}

	ret = dwarf_child(die, &child, &derr);
	if (ret == DW_DLV_NO_ENTRY)
		goto done;
	if (ret != DW_DLV_OK)
		errx(1, "dwarf_child: %s", t->t_name, dwarf_errmsg(derr));

	child1 = NULL;
	STAILQ_INIT(&t->t_sou.members);
	do {
		if (child1 != NULL) {
			dwarf_dealloc(dbg, child, DW_DLA_DIE);
			child = child1;
		}

		m = tmember_new(die_name(child));

		ret = dwarf_tag(child, &tag, &derr);
		assert(ret == DW_DLV_OK);
		assert(tag == DW_TAG_member || tag == DW_TAG_structure_type ||
		    tag == DW_TAG_union_type || tag == DW_TAG_enumeration_type);
		if (tag != DW_TAG_member) {
			dispatch_tag(cuctx, child, tag);
		} else {
			m->tm_compound.off = die_typeoff(child);
			STAILQ_INSERT_TAIL(&t->t_sou.members, m, tm_next);
		}
	} while ((ret = dwarf_siblingof(dbg, child, &child1, &derr)) ==
	    DW_DLV_OK);

	if (ret != DW_DLV_NO_ENTRY)
		errx(1, "dwarf_siblingof: %s", dwarf_errmsg(derr));
	dwarf_dealloc(dbg, child, DW_DLA_DIE);

	if (t->t_name != NULL) {
		l = &g_union_types[strhash(t->t_name) &
		    (STRUCT_TYPE_HASHSZ - 1)];
		LIST_INSERT_HEAD(l, t, t_list);
	}
done:
	doffmap_add_ref(cuctx, t, t->t_off);
}

static void
tnode_new_volatile_type(struct cuctx *cuctx, Dwarf_Die die)
{
	Dwarf_Error derr;
	Dwarf_Off dieoff, toff;
	struct tnode *t;

	if (dwarf_dieoffset(die, &dieoff, &derr) != DW_DLV_OK)
		errx(1, "dwarf_dieoffset: %s", dwarf_errmsg(derr));

	if (die_hasattr(die, DW_AT_type))
		toff = die_typeoff(die);
	else
		toff = 0;
	t = tnode_new_reference(cuctx, toff, dieoff, DW_TAG_volatile_type,
	    NULL, 0);
	doffmap_add_ref(cuctx, t, dieoff);
}

static void
dispatch_tag(struct cuctx *cuctx, Dwarf_Die die, Dwarf_Half tag)
{
	Dwarf_Debug dbg;
	Dwarf_Die child, child1;
	Dwarf_Error derr;
	Dwarf_Half tag1;
	int ret;

	dbg = cuctx->cu_softc->sc_dbg;

	switch (tag) {
	case DW_TAG_array_type:
		tnode_new_array_type(cuctx, die);
		break;
	case DW_TAG_base_type:
		tnode_new_base_type(cuctx, die);
		break;
	case DW_TAG_const_type:
		tnode_new_const_type(cuctx, die);
		break;
	case DW_TAG_enumeration_type:
		tnode_new_enumeration_type(cuctx, die);
		break;
	case DW_TAG_pointer_type:
		tnode_new_pointer_type(cuctx, die);
		break;
	case DW_TAG_restrict_type:
		tnode_new_restrict_type(cuctx, die);
		break;
	case DW_TAG_structure_type:
		tnode_new_structure_type(cuctx, die);
		break;
	case DW_TAG_subprogram:
		ret = dwarf_child(die, &child, &derr);
		if (ret == DW_DLV_NO_ENTRY)
			break;
		if (ret != DW_DLV_OK)
			errx(1, "dwarf_child: %s", dwarf_errmsg(derr));
		child1 = NULL;
		do {
			if (child1 != NULL) {
				dwarf_dealloc(dbg, child, DW_DLA_DIE);
				child = child1;
			}
			if (dwarf_tag(child, &tag1, &derr) != DW_DLV_OK)
				errx(1, "dwarf_tag: %s", dwarf_errmsg(derr));
			dispatch_tag(cuctx, child, tag1);
		} while (dwarf_siblingof(dbg, child, &child1, &derr) ==
		    DW_DLV_OK);
		dwarf_dealloc(dbg, child, DW_DLA_DIE);
		break;
	case DW_TAG_subroutine_type:
		tnode_new_subroutine_type(cuctx, die);
		break;
	case DW_TAG_typedef:
		tnode_new_typedef(cuctx, die);
		break;
	case DW_TAG_union_type:
		tnode_new_union_type(cuctx, die);
		break;
	case DW_TAG_volatile_type:
		tnode_new_volatile_type(cuctx, die);
		break;
	}
}

static void canonicalize_references(struct tnode *t);
static void remap_references(struct tnode *c, struct tnode *t);

static void
canonicalize_reference(struct tnode *t, struct tnode *ref)
{
	struct tnode *cref;

	assert(t->t_canonical);
	assert(!ref->t_canonical);
	assert(ref->t_ref.type == t);

	LIST_FOREACH(cref, &t->t_crefs, t_list) {
		assert(cref->t_ref.type == t);
		assert(tnode_is_canonical(cref));
		if (tnode_reference_equiv(ref, cref))
			break;
	}

	if (cref != NULL) {
		doffmap_remap(ref, cref);
		remap_references(cref, ref);
		tnode_free(ref);
	} else {
		ref->t_canonical = true;
		LIST_INSERT_HEAD(&t->t_crefs, ref, t_list);
		canonicalize_references(ref);
	}
}

static void
canonicalize_references(struct tnode *t)
{
	struct tnode *ref;

	assert(t->t_canonical);

	while ((ref = LIST_FIRST(&t->t_refs)) != NULL) {
		LIST_REMOVE(ref, t_list);
		assert(!ref->t_canonical);
		assert(ref->t_ref.type == t);
		canonicalize_reference(t, ref);
	}
}

static void
remap_references(struct tnode *c, struct tnode *t)
{
	struct tnode *ref;

	assert(c->t_canonical);

	while ((ref = LIST_FIRST(&t->t_refs)) != NULL) {
		LIST_REMOVE(ref, t_list);
		assert(!ref->t_canonical);
		assert(ref->t_ref.type == t);

		ref->t_ref.type = c;
		canonicalize_reference(c, ref);
	}
}

static void
process_cu(struct cuctx *cuctx)
{
	struct tnode *ref, *t;
	Dwarf_Debug dbg;
	Dwarf_Die die, die1;
	Dwarf_Error derr;
	Dwarf_Half tag;

	dbg = cuctx->cu_softc->sc_dbg;
	die = cuctx->cu_die;

	/*
	 * Pass 1: iterate over top-level DIEs and resolve as many as possible.
	 */
	if (dwarf_child(cuctx->cu_die, &die, &derr) == DW_DLV_NO_ENTRY)
		return;
	for (;;) {
		if (dwarf_tag(die, &tag, &derr) != DW_DLV_OK)
			errx(1, "dwarf_tag: %s", dwarf_errmsg(derr));
		dispatch_tag(cuctx, die, tag);
		if (dwarf_siblingof(dbg, die, &die1, &derr) == DW_DLV_NO_ENTRY)
			break;

		dwarf_dealloc(dbg, die, DW_DLA_DIE);
		die = die1;
	}
	dwarf_dealloc(dbg, die, DW_DLA_DIE);

	/*
	 * Pass 2: canonicalize references.
	 */
	while ((t = TAILQ_FIRST(&g_dangling)) != NULL) {
		TAILQ_REMOVE(&g_dangling, t, t_tailq);

		assert(tnode_is_reference(t));
		assert(!tnode_is_canonical(t));
		assert(t->t_ref.type == NULL);
		ref = doffmap_lookup(cuctx, t->t_ref.off);
		assert(ref != NULL);

		t->t_ref.type = ref;
		if (ref->t_canonical) {
			canonicalize_reference(ref, t);
		} else {
			LIST_INSERT_HEAD(&ref->t_refs, t, t_list);
		}
	}
}

static uint64_t gen = 1;
static uint64_t currgen = 1;

static bool
tnode_equiv(struct tnode *t, struct tnode *s)
{
	Dwarf_Off soff, toff;

	if (t == s)
		return (true);
	if (t->t_tag != s->t_tag)
		return (false);

	/* Terminal nodes are already deduplicated. */
	if (tnode_is_terminal(t)) {
		assert(t->t_canonical);
		return (s == t);
	}

	if (t->t_generation > gen && s->t_generation > gen)
		return (t->t_generation == s->t_generation);
	t->t_generation = s->t_generation = ++currgen;

	if (tnode_is_reference(t)) {
		/* Dangling references must be resolved. */
		assert(t->t_ref.type != NULL);
		assert(s->t_ref.type != NULL);

		switch (t->t_tag) {
		case DW_TAG_array_type:
			if (t->t_ref.count != s->t_ref.count) {
				return (false);
			}
			goto ref_equiv;
		case DW_TAG_typedef:
			if (strcmp(t->t_name, s->t_name) != 0)
				return (false);
			/* FALLTHROUGH */
		case DW_TAG_const_type:
		case DW_TAG_pointer_type:
		case DW_TAG_restrict_type:
		case DW_TAG_volatile_type:
ref_equiv:
			return (tnode_equiv(t->t_ref.type, s->t_ref.type));
		default:
			errx(1, "unhandled tag type %#x", t->t_tag);
		}
	} else {
		assert(tnode_is_compound(t));

		struct tnode *tmt, *smt;
		struct tmember *sm, *tm;

		if (namecmp(t->t_name, s->t_name) != 0)
			return (false);

		sm = STAILQ_FIRST(&s->t_sou.members);
		tm = STAILQ_FIRST(&t->t_sou.members);

		if (sm == NULL && tm == NULL)
			return (true);

		if ((t->t_tag == DW_TAG_structure_type ||
		    t->t_tag == DW_TAG_union_type) &&
		    (sm == NULL || tm == NULL))
			return (true);

		do {
			if (sm == NULL) {
				return (false);
			}

			soff = sm->tm_compound.off;
			toff = tm->tm_compound.off;
			if (soff == toff)
				goto next;

			if (t->t_tag == DW_TAG_subroutine_type &&
			    (soff == 0 || toff == 0)) {
				return (false);
			}

			if (namecmp(tm->tm_name, sm->tm_name) != 0)
				return (false);

			smt = doffmap_lookup(s->t_cuctx, soff);
			assert(smt != NULL);
			tmt = doffmap_lookup(t->t_cuctx, toff);
			assert(tmt != NULL);

			if (!tnode_equiv(smt, tmt)) {
				return (false);
			}

next:
			sm = STAILQ_NEXT(sm, tm_next);
			tm = STAILQ_NEXT(tm, tm_next);
		} while (tm != NULL);

		if (sm != NULL) {
			return (false);
		}

		return (true);
	}
}

int
main(int argc, char **argv)
{
	struct softc sc;
	struct cuctx *cuctx;
	struct tnode *t, *t1, *ttmp;
	struct tnode_list *l;
	Dwarf_Debug dbg;
	Dwarf_Die cu;
	Dwarf_Error derr;
	Dwarf_Half tag;
	int fd, i;

	if (argc != 2)
		errx(1, "usage: %s <file>", getprogname());

	fd = open(argv[1], O_RDONLY);
	if (fd < 0)
		err(1, "open(%s)", argv[1]);

	if (cap_enter() != 0)
		err(1, "cap_enter");

	for (i = 0; i < BASE_TYPE_HASHSZ; i++)
		STAILQ_INIT(&g_base_types[i]);
	for (i = 0; i < ENUM_TYPE_HASHSZ; i++)
		STAILQ_INIT(&g_enum_types[i]);
	for (i = 0; i < STRUCT_TYPE_HASHSZ; i++)
		LIST_INIT(&g_struct_types[i]);
	for (i = 0; i < UNION_TYPE_HASHSZ; i++)
		LIST_INIT(&g_union_types[i]);

	TAILQ_INIT(&g_dangling);
	if (dwarf_init(fd, DW_DLC_READ, NULL, NULL, &dbg, &derr) != DW_DLV_OK)
		errx(1, "dwarf_init: %s", dwarf_errmsg(derr));

	sc.sc_dbg = dbg;
	SLIST_INIT(&sc.sc_cus);

	sc.sc_void.t_off = 0;
	sc.sc_void.t_tag = DW_TAG_base_type;
	sc.sc_void.t_name = "void";
	sc.sc_void.t_bsz = 0;
	sc.sc_void.t_canonical = true;
	sc.sc_void.t_base.enc = 0;
	STAILQ_INSERT_HEAD(&g_base_types[strhash(sc.sc_void.t_name) &
	    (BASE_TYPE_HASHSZ - 1)], &sc.sc_void, t_stailq);

	while (dwarf_next_cu_header_b(dbg, NULL, NULL, NULL, NULL, NULL, NULL,
	    NULL, &derr) == DW_DLV_OK) {
		cu = NULL;
		if (dwarf_siblingof(dbg, cu, &cu, &derr) != DW_DLV_OK)
			errx(1, "dwarf_siblingof: %s", dwarf_errmsg(derr));

		if (dwarf_tag(cu, &tag, &derr) != DW_DLV_OK)
			errx(1, "dwarf_tag: %s", dwarf_errmsg(derr));
		if (tag != DW_TAG_compile_unit)
			errx(1, "top-level DIE isn't a CU");

		cuctx = cuctx_new(&sc, cu);
		process_cu(cuctx);
		cuctx->cu_die = NULL;
		dwarf_dealloc(dbg, cu, DW_DLA_DIE);
	}

	printf("phase 1 done\n");

	struct tnode_list canonical;
	LIST_INIT(&canonical);
	int count = 0;

	for (i = 0; i < STRUCT_TYPE_HASHSZ; i++) {
		l = &g_struct_types[i];
		while ((t = LIST_FIRST(l)) != NULL) {
			LIST_REMOVE(t, t_list);
			assert(!tnode_is_canonical(t));
			t->t_canonical = true;
			canonicalize_references(t);

			LIST_FOREACH_SAFE(t1, l, t_list, ttmp) {
				if (tnode_equiv(t, t1)) {
					LIST_REMOVE(t1, t_list);

					remap_references(t, t1);
					doffmap_remap(t1, t);
					tnode_free(t1);
				}
				gen = currgen + 1;
			}

			LIST_INSERT_HEAD(&canonical, t, t_list);
			count++;
		}
	}

	printf("%d canonical structures\n", count);
#if 0
	LIST_FOREACH(t, &canonical, t_list)
		printf("%s\n", t->t_name);
#endif
	count = 0;

	for (i = 0; i < UNION_TYPE_HASHSZ; i++) {
		l = &g_union_types[i];
		while ((t = LIST_FIRST(l)) != NULL) {
			LIST_REMOVE(t, t_list);
			assert(!tnode_is_canonical(t));
			t->t_canonical = true;
			canonicalize_references(t);

			LIST_FOREACH_SAFE(t1, l, t_list, ttmp) {
				if (tnode_equiv(t, t1)) {
					LIST_REMOVE(t1, t_list);

					remap_references(t, t1);
					doffmap_remap(t1, t);
					tnode_free(t1);
				}
				gen = currgen + 1;
			}

			LIST_INSERT_HEAD(&canonical, t, t_list);
			count++;
		}
	}
	printf("%d canonical unions\n", count);
	return (0);
}
