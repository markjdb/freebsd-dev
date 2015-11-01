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

case $(elfdump -e "$obj" | ${AWK} '/e_machine: /{print $2}') in
EM_386)
    extype=long
    ;;
EM_X86_64)
    extype=quad
    ;;
*)
    echo "$(basename $0): unknown machine type" >&2
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

# Generate aliases for each probe stub so that relocations against them
# can be resolved in the final link. These symbols will be removed by
# sdtstrip.sh after linking.
${NM} -u "$obj" | \
    ${AWK} '/^[[:space:]]*U __dtrace_sdt_[_[:alpha:]]+[_[:alnum:]]*$/ {
                printf "__strong_reference(_sdt_probe_stub, %s);\n", $2;
            }'

# Emit a linker set containing a struct sdt_probedesc for each relocation
# against an SDT probe stub.
${OBJDUMP} -r -j .text "$obj" | \
    ${AWK} 'BEGIN {
                print "__asm__(";
                print "    \".pushsection set_sdt_probe_site_set, \\\"a\\\"\\n\"";
                print "    \".align 8\\n\"";
                print "    \".globl __start_set_sdt_probe_site_set\\n\"";
                print "    \".globl __stop_set_sdt_probe_site_set\\n\"";
            }

            $3 ~ /^__dtrace_sdt_[_[:alpha:]]+[_[:alnum:]]*\+?/ {
                match($3, /sdt_[_[:alpha:]]+[_[:alnum:]]*/);
                symname = substr($3, 10, RLENGTH);
                directive = "'${extype}'";
                printf "    \".globl %s\\n\"\n", symname;
                printf "    \".%s %s\\n\"\n    \".%s 0x%s\\n\"\n",
                    directive, symname, directive, $1;
            }

            END {
                print "    \".popsection\");";
            }'
