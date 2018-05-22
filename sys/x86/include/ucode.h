#ifndef _MACHINE_UCODE_H_
#define	_MACHINE_UCODE_H_

int	ucode_intel_load(void *);
int	ucode_intel_verify(uint32_t *data, size_t len);
void	ucode_load_ap(void);

#endif /* _MACHINE_UCODE_H_ */
