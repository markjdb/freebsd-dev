#include <sys/param.h>
#include <sys/queue.h>

#include <stdio.h>
#include <stdlib.h>
#include <atf-c.h>

struct vm_page {
	vm_pindex_t pindex;	/* must be first */
	SLIST_ENTRY(vm_page) next;
#define	COOKIEVAL	0xd007d007
	uint32_t cookie;
};

#include "vm.h"
#define	_WANT_VM_RADIX_IFACE
#include "vm_radix.h"

static SLIST_HEAD(, vm_page) pages;

static vm_page_t
page_alloc(vm_pindex_t pindex)
{
	vm_page_t m;

	m = malloc(sizeof(*m));
	m->pindex = pindex;
	m->cookie = COOKIEVAL;
	SLIST_INSERT_HEAD(&pages, m, next);
	return (m);
}

static void
vrt_assert_present(struct vm_radix *root, vm_pindex_t pindex)
{
	vm_page_t m;

	m = vm_radix_lookup(root, pindex);
	ATF_REQUIRE(m != NULL);
	ATF_REQUIRE(m->pindex == pindex);
	ATF_REQUIRE(m->cookie == COOKIEVAL);
	ATF_REQUIRE(m == vm_radix_lookup(root, pindex));
}

static void
vrt_assert_not_present(struct vm_radix *root, vm_pindex_t pindex)
{

	ATF_REQUIRE_MSG(vm_radix_lookup(root, pindex) == NULL,
	    "didn't expect pindex 0x%lx", pindex);
}

static void
vrt_init(struct vm_radix *root)
{

	vm_radix_init(root);
}

static void
vrt_insert(struct vm_radix *root, vm_pindex_t pindex)
{

	ATF_REQUIRE(vm_radix_insert(root, page_alloc(pindex)) == 0);
}

static void
vrt_reclaim(struct vm_radix *root)
{
	vm_page_t m;

	vm_radix_reclaim_allnodes(root);
	ATF_REQUIRE(vm_radix_is_empty(root));

	while ((m = SLIST_FIRST(&pages)) != NULL) {
		SLIST_REMOVE_HEAD(&pages, next);
		free(m);
	}
}

void panic(const char *, ...);

void
panic(const char *fmt __unused, ...)
{

	ATF_REQUIRE(1 == 0); /* XXX can't use va_args with ATF? */
}

ATF_TC_WITHOUT_HEAD(single_bit_lookup);
ATF_TC_BODY(single_bit_lookup, tc)
{
	struct vm_radix r;
	vm_pindex_t p;

	vrt_init(&r);

	for (u_int i = 0, p = 1; i < NBBY * sizeof(p); i++, p <<= 1) {
		vrt_insert(&r, p);
		vrt_assert_present(&r, p);
		vrt_assert_not_present(&r, p + 1);
		vrt_assert_not_present(&r, p << 1);
		vrt_assert_not_present(&r, ~p);
	}

	vrt_reclaim(&r);
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, single_bit_lookup);

	return (atf_no_error());
}
