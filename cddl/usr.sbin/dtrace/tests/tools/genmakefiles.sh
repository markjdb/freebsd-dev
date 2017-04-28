# $FreeBSD$

usage()
{
    cat <<__EOF__ >&2
usage: $(basename $0)

This script regenerates the DTrace test suite makefiles. It should be run
whenever \$srcdir/cddl/contrib/opensolaris/cmd/dtrace/test/tst is modified.
__EOF__
    exit 1
}

# Format a file list for use in a make(1) variable assignment: take the
# basename of each input file and append " \" to it.
fmtflist()
{
    awk 'function bn(f) {
        sub(".*/", "", f)
        return f
    }
    {print "    ", bn($1), " \\"}'
}

genmakefile()
{
    local basedir=$(basename $1)
    local basetestdir=$(basename $(dirname $1))

    local testdir=${CONTRIB_TESTDIR}/${basetestdir}/${basedir}
    local tfiles=$(find $testdir -type f -a \
        \( -name \*.d -o -name \*.ksh -o -name \*.out \) | sort | fmtflist)
    local tcfiles=$(find $testdir -type f -a -name \*.c | sort | fmtflist)
    local tasmfiles=$(find $testdir -type f -a -name \*.S | sort | fmtflist)
    local texes=$(find $testdir -type f -a -name \*.exe | sort | fmtflist)

    # One-off variable definitions.
    local special
    case "$basedir" in
    proc)
        special="
LIBADD.tst.sigwait.exe+= rt
"
        ;;
    raise)
	special="
TEST_METADATA.t_dtrace_contrib+=	required_memory=\"4g\"
"
        ;;
    safety)
	special="
TEST_METADATA.t_dtrace_contrib+=	required_memory=\"4g\"
"
        ;;
    uctf)
        special="
WITH_CTF=YES
"
        ;;
    esac

    local makefile=$(mktemp)
    cat <<__EOF__ > $makefile
# \$FreeBSD$

#
# This Makefile was generated by \$srcdir${ORIGINDIR#${TOPDIR}}/genmakefiles.sh.
#

PACKAGE=	tests

\${PACKAGE}FILES= \\
$tfiles

TESTEXES= \\
$texes

CFILES= \\
$tcfiles

ASMFILES= \\
$tasmfiles

$special
.include "../../dtrace.test.mk"
__EOF__

    mv -f $makefile ${ORIGINDIR}/../${basetestdir}/${basedir}/Makefile
}

set -e

if [ $# -ne 0 ]; then
    usage
fi

export LC_ALL=C

readonly ORIGINDIR=$(realpath $(dirname $0))
readonly TOPDIR=$(realpath ${ORIGINDIR}/../../../../..)
readonly CONTRIB_TESTDIR=${TOPDIR}/cddl/contrib/opensolaris/cmd/dtrace/test/tst
readonly TEST_SUBDIRS="common i386"

# Generate a Makefile for each test group.
for testdir in ${TEST_SUBDIRS}; do
    for dir in $(find ${CONTRIB_TESTDIR}/$testdir -mindepth 1 -maxdepth 1 -type d); do
        genmakefile $dir
    done
done
