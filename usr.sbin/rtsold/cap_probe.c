/*	$KAME: probe.c,v 1.17 2003/10/05 00:09:36 itojun Exp $	*/

/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (C) 1998 WIDE Project.
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 */

#include <sys/param.h>
#include <sys/capsicum.h>
#include <sys/socket.h>
#include <sys/sysctl.h>

#include <net/if.h>
#include <net/if_dl.h>

#include <netinet/in.h>
#include <netinet6/in6_var.h>
#include <netinet/icmp6.h>
#include <netinet6/nd6.h>

#include <arpa/inet.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <libcasper.h>
#include <libcasper_service.h>

#include "rtsold.h"

static int
getsocket(int *sockp)
{
	static int probesock = -1;
	cap_rights_t rights;
	int error, sock;

	if (probesock >= 0) {
		*sockp = probesock;
		return (0);
	}

	if ((sock = socket(AF_INET6, SOCK_RAW, IPPROTO_NONE)) < 0) {
		error = errno;
		warnmsg(LOG_ERR, __func__, "socket: %s", strerror(errno));
		return (error);
	}
	cap_rights_init(&rights, CAP_CONNECT, CAP_SEND);
	if (cap_rights_limit(sock, &rights) != 0) {
		error = errno;
		warnmsg(LOG_ERR, __func__, "cap_rights_limit(): %s",
		    strerror(errno));
		return (error);
	}
	*sockp = probesock = sock;

	return (0);
}

static void
sendprobe(int sock, struct in6_addr *addr, uint32_t ifindex, uint32_t linkid)
{
	uint8_t cmsg[CMSG_SPACE(sizeof(struct in6_pktinfo)) +
	    CMSG_SPACE(sizeof(int))];
	struct msghdr hdr;
	struct iovec iov;
	u_char ntopbuf[INET6_ADDRSTRLEN], ifnamebuf[IFNAMSIZ];
	struct sockaddr_in6 sa6_probe;
	struct in6_pktinfo *pi;
	struct cmsghdr *cm;
	ssize_t n;
	int error, hoplimit;

	memset(&sa6_probe, 0, sizeof(sa6_probe));
	sa6_probe.sin6_family = AF_INET6;
	sa6_probe.sin6_len = sizeof(sa6_probe);
	sa6_probe.sin6_addr = *addr;
	sa6_probe.sin6_scope_id = linkid;

	memset(&hdr, 0, sizeof(hdr));
	hdr.msg_name = (caddr_t)&sa6_probe;
	hdr.msg_namelen = sizeof(sa6_probe);
	hdr.msg_iov = &iov;
	hdr.msg_iovlen = 1;
	hdr.msg_control = cmsg;
	hdr.msg_controllen = sizeof(cmsg);

	iov.iov_base = NULL;
	iov.iov_len = 0;

	/* Specify the outbound interface. */
	cm = CMSG_FIRSTHDR(&hdr);
	cm->cmsg_level = IPPROTO_IPV6;
	cm->cmsg_type = IPV6_PKTINFO;
	cm->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
	pi = (struct in6_pktinfo *)(void *)CMSG_DATA(cm);
	memset(&pi->ipi6_addr, 0, sizeof(pi->ipi6_addr));	/*XXX*/
	pi->ipi6_ifindex = ifindex;

	/* Specify the hop limit of the packet for safety. */
	hoplimit = 1;
	cm = CMSG_NXTHDR(&hdr, cm);
	cm->cmsg_level = IPPROTO_IPV6;
	cm->cmsg_type = IPV6_HOPLIMIT;
	cm->cmsg_len = CMSG_LEN(sizeof(int));
	memcpy(CMSG_DATA(cm), &hoplimit, sizeof(int));

	warnmsg(LOG_DEBUG, __func__, "probe a router %s on %s",
	    inet_ntop(AF_INET6, addr, ntopbuf, INET6_ADDRSTRLEN),
	    if_indextoname(ifindex, ifnamebuf));

	n = sendmsg(sock, &hdr, 0);
	if (n != 0) {
		error = errno;
		warnmsg(LOG_ERR, __func__, "sendmsg on %s: %s",
		    if_indextoname(ifindex, ifnamebuf), strerror(error));
	}
}

int
cap_probe_defrouters(cap_channel_t *cap, struct ifinfo *ifinfo)
{
	nvlist_t *nvl;
	int error;

	nvl = nvlist_create(0);
	nvlist_add_string(nvl, "cmd", "probe_defrouters");
	nvlist_add_number(nvl, "ifindex", ifinfo->sdl->sdl_index);
	nvlist_add_number(nvl, "linkid", ifinfo->linkid);

	nvl = cap_xfer_nvlist(cap, nvl);
	if (nvl == NULL)
		return (errno);

	error = 0;
	if (nvlist_exists_number(nvl, "error"))
		error = (int)nvlist_get_number(nvl, "error");
	nvlist_destroy(nvl);

	return (error);
}

static int
probe_command(const char *cmd, const nvlist_t *limits __unused, nvlist_t *nvlin,
    nvlist_t *nvlout __unused)
{
	struct in6_defrouter *p, *ep;
	char *buf;
	int error, mib[4], sock;
	size_t len;
	uint32_t ifindex, linkid;

	if (strcmp(cmd, "probe_defrouters") != 0)
		return (EINVAL);

	ifindex = (uint32_t)nvlist_get_number(nvlin, "ifindex");
	linkid = (uint32_t)nvlist_get_number(nvlin, "linkid");
	if (ifindex == 0)
		return (EINVAL);

	error = getsocket(&sock);
	if (error != 0)
		return (error);

	mib[0] = CTL_NET;
	mib[1] = PF_INET6;
	mib[2] = IPPROTO_ICMPV6;
	mib[3] = ICMPV6CTL_ND6_DRLIST;
	if (sysctl(mib, nitems(mib), NULL, &len, NULL, 0) < 0)
		return (errno);
	if (len == 0)
		return (0);

	buf = malloc(len);
	if (buf == NULL)
		return (errno);
	if (sysctl(mib, nitems(mib), buf, &len, NULL, 0) < 0)
		return (errno);
	ep = (struct in6_defrouter *)(void *)(buf + len);
	for (p = (struct in6_defrouter *)(void *)buf; p < ep; p++) {
		if (ifindex != p->if_index)
			continue;
		if (!IN6_IS_ADDR_LINKLOCAL(&p->rtaddr.sin6_addr))
			continue;
		sendprobe(sock, &p->rtaddr.sin6_addr, ifindex, linkid);
	}
	free(buf);

	return (0);
}

static int
probe_limit(const nvlist_t *oldlimits __unused,
    const nvlist_t *newlimits __unused)
{

	return (0);
}

CREATE_SERVICE("rtsold.defrouter_probe", probe_limit, probe_command, 0);
