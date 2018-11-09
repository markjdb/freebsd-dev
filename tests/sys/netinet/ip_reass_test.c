/*-
 * Copyright (c) 2018 The FreeBSD Foundation
 *
 * This software was developed by Mark Johnston under sponsorship from
 * the FreeBSD Foundation.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/sysctl.h>

#include <net/bpf.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_var.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

#include <atf-c.h>

struct lopacket {
	u_int		family;
	struct ip	hdr;
	char		payload[];
};

static void
update_cksum(struct ip *ip)
{
	size_t i;
	uint32_t cksum;
	uint16_t *cksump;

	ip->ip_sum = 0;
	cksump = (uint16_t *)ip;
	for (cksum = 0, i = 0; i < sizeof(*ip) / sizeof(*cksump); cksump++, i++)
		cksum += ntohs(*cksump);
	cksum = (cksum >> 16) + (cksum & 0xffff);
	cksum = ~(cksum + (cksum >> 16));
	ip->ip_sum = htons(cksum);
}

static struct lopacket *
alloc_lopacket(size_t payloadlen)
{
	struct ip *ip;
	struct lopacket *packet;
	size_t pktlen;

	pktlen = sizeof(*packet) + payloadlen;
	packet = malloc(pktlen);
	ATF_REQUIRE(packet != NULL);

	memset(packet, 0, pktlen);
	packet->family = AF_INET;

	ip = &packet->hdr;
	ip->ip_hl = sizeof(struct ip) >> 2;
	ip->ip_v = 4;
	ip->ip_tos = 0;
	ip->ip_len = htons(payloadlen + sizeof(*ip));
	ip->ip_id = 0;
	ip->ip_off = 0;
	ip->ip_ttl = 1;
	ip->ip_p = IPPROTO_IP;
	ip->ip_sum = 0;
	ip->ip_src.s_addr = htonl(INADDR_LOOPBACK);
	ip->ip_dst.s_addr = htonl(INADDR_LOOPBACK);
	update_cksum(ip);

	return (packet);
}

static void
free_lopacket(struct lopacket *packet)
{

	free(packet);
}

static void
write_lopacket(int bpffd, struct lopacket *packet)
{
	ssize_t n;
	size_t len;

	len = sizeof(packet->family) + ntohs(packet->hdr.ip_len);
	n = write(bpffd, packet, len);
	ATF_REQUIRE_MSG(n >= 0, "packet write failed: %s", strerror(errno));
	ATF_REQUIRE_MSG((size_t)n == len, "wrote %zd bytes instead of %zu",
	    n, len);
}

static int
open_lobpf(void)
{
	struct ifreq ifr;
	int error, fd;

	fd = open("/dev/bpf0", O_RDWR);
	ATF_REQUIRE_MSG(fd >= 0, "open(/dev/bpf0): %s", strerror(errno));

	/* XXX this needs to be more generic. */
	memset(&ifr, 0, sizeof(ifr));
	strlcpy(ifr.ifr_name, "lo0", IFNAMSIZ);
	error = ioctl(fd, BIOCSETIF, &ifr);
	ATF_REQUIRE_MSG(error == 0, "ioctl(BIOCSETIF): %s", strerror(errno));

	return (fd);
}

static void
get_ipstat(struct ipstat *stat)
{
	size_t len;
	int error;

	memset(stat, 0, sizeof(*stat));
	len = sizeof(*stat);
	error = sysctlbyname("net.inet.ip.stats", stat, &len, NULL, 0);
	ATF_REQUIRE_MSG(error == 0, "sysctl(net.inet.ip.stats) failed: %s",
	    strerror(errno));
	ATF_REQUIRE(len == sizeof(*stat));
}

ATF_TC(ip_reass__large_fragment);
ATF_TC_HEAD(ip_reass__large_fragment, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}
ATF_TC_BODY(ip_reass__large_fragment, tc)
{
	struct ipstat old, new;
	struct ip *ip;
	struct lopacket *packet;
	int error, fd;

	fd = open_lobpf();

	/* 16 + (0x1fff << 3) > IP_MAXPACKET */
	packet = alloc_lopacket(16);
	ip = &packet->hdr;
	ip->ip_id = htons(12345);
	ip->ip_off = htons(IP_MF | 0x1fff);
	update_cksum(ip);

	get_ipstat(&old);
	write_lopacket(fd, packet);
	get_ipstat(&new);

	ATF_REQUIRE_MSG(old.ips_toolong < new.ips_toolong,
	    "ips_toolong wasn't incremented (%ju vs. %ju)",
	    (uintmax_t)old.ips_toolong, (uintmax_t)new.ips_toolong);

	free_lopacket(packet);
	error = close(fd);
	ATF_REQUIRE(error == 0);
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, ip_reass__large_fragment);

	return (atf_no_error());
}
