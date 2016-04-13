#ifndef _SDT_H_
#define	_SDT_H_

struct sdt_probedesc;

/*
 * An entry in the SDT hash table. These records exist one-to-one with SDT probe
 * descriptors, but are split into a separate struct to avoid bloat: descriptors
 * are created at compile-time and always reside in memory. Note that multiple
 * records may have the same id if the probe definition hard-codes a function
 * name or a probe has multiple sites within a function.
 */
struct sdt_invoprec {
	struct sdt_probedesc	*sr_desc;
	LIST_ENTRY(sdt_invoprec) sr_next;
	dtrace_id_t		sr_id;
};

struct sdt_invoprec *sdt_lookup_site(uint64_t);
int	sdt_invop(uintptr_t, uintptr_t *, uintptr_t);
void	sdt_probe_enable(struct sdt_probedesc *);
void	sdt_probe_disable(struct sdt_probedesc *);

#endif /* _SDT_H_ */
