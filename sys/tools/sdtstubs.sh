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

obj=$1
if [ ! -f "$obj" ]; then
    echo "usage: $(basename $0) <objfile>" >&2
    exit 1
fi

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

${NM} -u "$obj" | \
    ${AWK} '/^[[:space:]]*U __dtrace_sdt_[_[:alpha:]]+[_[:alnum:]]*$/ \
            {printf "__strong_reference(_sdt_probe_stub, %s);\n", $2;}'

cat <<__EOF__
__asm__(
    ".pushsection set_sdt_probe_site_set, \"a\"\n"
    ".align 8\n"
    ".globl __start_set_sdt_probe_site_set\n"
    ".globl __stop_set_sdt_probe_site_set\n"
__EOF__

${OBJDUMP} -r -j .text "$obj" | \
    ${AWK} '$3 ~ /^__dtrace_sdt_[_[:alpha:]]+[_[:alnum:]]*\+?/ \
            {match($3, /sdt_[_[:alpha:]]+[_[:alnum:]]*/); \
             printf "    \".quad %s\\n\"\n    \".quad 0x%s\\n\"\n", \
                 substr($3, 10, RLENGTH), $1;}'

cat <<__EOF__
    ".popsection\n");
__EOF__
