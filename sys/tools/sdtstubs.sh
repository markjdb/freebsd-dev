#!/bin/sh
#
# Copyright (c) 2015 Mark Johnston <markj@FreeBSD.org>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
#
# $FreeBSD$
#

#
# Generate SDT probe stubs and record stub relocation info.
#

obj=$1
if [ ! -f "$obj" -o $# -ne 1 ]; then
    echo "usage: $(basename $0) <objfile>" >&2
    exit 1
fi

set -e

class=$(readelf --file-header "$obj" | ${AWK} '/Class: /{print $2}')
case $class in
ELF32)
    directive=long ;;
ELF64)
    directive=quad ;;
*)
    echo "$(basename $0): unknown ELF class $class" >&2
    exit 1
    ;;
esac

# Emit the preamble.
cat <<__EOF__
/*
 * This is a machine-generated file - do not edit it!
 */
#include <sys/cdefs.h>

void	_sdt_probe_stub(void);

/*
 * A no-op stub used as an alias for all SDT probe site stubs.
 */
void
_sdt_probe_stub(void)
{
}

__EOF__

# Make each probe stub an alias of _sdt_probe_stub().
${NM} -u "$obj" | \
    ${AWK} '
/^[[:space:]]*U __dtrace_sdt_[_[:alpha:]]+[_[:alnum:]]*$/ {
    printf "__strong_reference(_sdt_probe_stub, %s);\n", $2;
}'

# Emit a linker set containing a struct sdt_probedesc for each relocation
# against an SDT probe stub.
${OBJDUMP} -r -j .text "$obj" | \
    ${AWK} -v directive=$directive '
function create_set(set)
{
    printf "    \".pushsection set_%s_set, \\\"a\\\"\\n\"\n", set;
    printf "    \".align 8\\n\"\n";
    printf "    \".global __start_set_%s_set\\n\"\n", set;
    printf "    \".global __stop_set_%s_set\\n\"\n", set;
    printf "    \".popsection\\n\"\n";
}

function emit_item(set, symname, addr)
{
    printf "    \".pushsection set_%s_set, \\\"a\\\"\\n\"\n", set;
    printf "    \".%s %s\\n\"\n", directive, symname;
    printf "    \".%s 0x%s\\n\"\n", directive, addr;
    printf "    \".popsection\\n\"\n";
}

BEGIN {
    print "__asm__(";

    create_set("sdt_probe_site");
    create_set("sdt_anon_probe_site");
}

$3 ~ /^__dtrace_sdt_[_[:alpha:]]+[_[:alnum:]]*\+?/ {
    match($3, /sdt_[_[:alpha:]]+[_[:alnum:]]*/);
    symname = substr($3, 10, RLENGTH); # 10 is strlen("__dtrace_") + 1.
    if (substr(symname, 0, 8) == "sdt_sdt_") {
        printf "    \"1:\\n\"\n";
        printf "    \".string \\\"%s\\\"\\n\"\n", symname;
        emit_item("sdt_anon_probe_site", "1b", $1);
    } else {
        printf "    \".global %s\\n\"\n", symname;
        emit_item("sdt_probe_site", symname, $1);
    }
}

END {
    print ");";
}'
