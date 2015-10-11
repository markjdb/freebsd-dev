#ifndef _SDT_H_
#define	_SDT_H_

struct sdt_probedesc;

struct sdt_siterec {
	struct sdt_probedesc	*desc;
	LIST_ENTRY(sdt_siterec) next;
	dtrace_id_t		id;
};

struct sdt_siterec *sdt_lookup_site(uint64_t);
int	sdt_invop(uintptr_t, uintptr_t *, uintptr_t);
void	sdt_probe_enable(struct sdt_probedesc *);
void	sdt_probe_disable(struct sdt_probedesc *);

#endif /* _SDT_H_ */
