# $FreeBSD$

cat <<__EOF__
extern void __dtrace_sdt_probe(void);

void
__dtrace_sdt_probe()
{
}
__EOF__

${NM} -u $@ | \
    ${AWK} '/^[[:space:]]*U[[:space:]]+__dtrace_sdt_[A-Za-z0-9_]+$/{print $2}' | \
    sort -u | ${AWK} '{print "#pragma weak", $1, "= __dtrace_sdt_probe"}'
