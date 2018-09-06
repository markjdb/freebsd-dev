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
#include <sys/fcntl.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include <netinet/in.h>

#include <err.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

#include <atf-c.h>

/*
 * Given an array of listening sockets configured in a LB group for "addr",
 * fork a child to connect to "addr" the specified number of times.  Count the
 * number of connections accepted on each listening socket and verify that they
 * are roughly balanced.
 */
static void
lb_simple_accept_loop(int domain, struct sockaddr *addr, int sds[],
    size_t sdcnt, int nconns)
{
	size_t bytes, i;
	socklen_t slen;
	pid_t child, pid;
	int *acceptcnt;
	int error, excnt, sd, status;
	char b;

	child = fork();
	ATF_REQUIRE_MSG(child != 1, "fork() failed: %s", strerror(errno));
	if (child == 0) {
		status = 0;
		while (nconns-- > 0) {
			sd = socket(domain, SOCK_STREAM, 0);
			if (sd < 0) {
				warn("socket");
				status = 1;
				break;
			}

			error = connect(sd, addr, addr->sa_len);
			if (error != 0) {
				warn("connect");
				status = 1;
				break;
			}

			if (read(sd, &b, sizeof(b)) != sizeof(b)) {
				warn("read");
				status = 1;
				break;
			}

			error = close(sd);
			if (error != 0) {
				warn("close");
				status = 1;
				break;
			}
		}
		_exit(status);
	}

	/* We need to perform non-blocking accept()s. */
	for (i = 0; i < sdcnt; i++) {
		error = fcntl(sds[i], F_SETFL, O_NONBLOCK);
		ATF_REQUIRE_MSG(error == 0, "fcntl(O_NONBLOCK) failed: %s",
		    strerror(errno));
	}

	acceptcnt = calloc(sdcnt, sizeof(*acceptcnt));
	excnt = nconns / sdcnt / 8;
	while (nconns > 0) {
		pid = waitpid(child, &status, WNOHANG);
		ATF_REQUIRE_MSG(pid == 0, "waitpid() returned %d (%d)", pid,
		    WEXITSTATUS(status));
		for (i = 0; i < sdcnt; i++) {
			slen = addr->sa_len;
			sd = accept(sds[i], addr, &slen);
			if (sd < 0) {
				ATF_REQUIRE_MSG(errno == EWOULDBLOCK ||
				    errno == EAGAIN, "accept() failed: %s",
				    strerror(errno));
				continue;
			}

			b = 1;
			bytes = write(sd, &b, sizeof(b));
			ATF_REQUIRE_MSG(bytes == sizeof(b),
			    "write() failed: %s", strerror(errno));
			error = close(sd);
			ATF_REQUIRE_MSG(error == 0, "close() failed: %s",
			    strerror(errno));

			acceptcnt[i]++;
			nconns--;
			break;
		}
	}
	for (i = 0; i < nitems(acceptcnt); i++)
		ATF_REQUIRE_MSG(acceptcnt[i] > excnt, "uneven balancing");

	pid = wait(&status);
	ATF_REQUIRE_MSG(pid == child, "wait() failed: %s", strerror(errno));
	ATF_REQUIRE_MSG(WEXITSTATUS(status) == 0, "child exited with status %d",
	    WEXITSTATUS(status));
}

static int
lb_listen_socket(int domain)
{
	size_t one;
	int error, sd;

	sd = socket(domain, SOCK_STREAM, 0);
	ATF_REQUIRE_MSG(sd >= 0, "socket() failed: %s", strerror(errno));

	one = 1;
	error = setsockopt(sd, SOL_SOCKET, SO_REUSEPORT_LB, &one, sizeof(one));
	ATF_REQUIRE_MSG(error == 0, "setsockopt(SO_REUSEPORT_LB) failed: %s",
	    strerror(errno));

	return (sd);
}

ATF_TC_WITHOUT_HEAD(basic_ipv4);
ATF_TC_BODY(basic_ipv4, tc)
{
	struct sockaddr_in addr;
	socklen_t slen;
	size_t i;
	int error, sds[16];
	uint16_t port;

	sds[0] = lb_listen_socket(PF_INET);

	memset(&addr, 0, sizeof(addr));
	addr.sin_len = sizeof(addr);
	addr.sin_family = AF_INET;
	addr.sin_port = htons(0);
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	error = bind(sds[0], (const struct sockaddr *)&addr, sizeof(addr));
	ATF_REQUIRE(error == 0, "bind() failed: %s", strerror(errno));
	error = listen(sds[0], 1);
	ATF_REQUIRE_MSG(error == 0, "listen() failed: %s", strerror(errno));

	slen = sizeof(addr);
	error = getsockname(sds[0], (struct sockaddr *)&addr, &slen);
	ATF_REQUIRE_MSG(error == 0, "getsockname() failed: %s",
	    strerror(errno));
	ATF_REQUIRE_MSG(slen == sizeof(addr), "sockaddr size changed");
	port = addr.sin_port;

	memset(&addr, 0, sizeof(addr));
	addr.sin_len = sizeof(addr);
	addr.sin_family = AF_INET;
	addr.sin_port = port;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	for (i = 1; i < nitems(sds); i++) {
		sds[i] = lb_listen_socket(PF_INET);

		error = bind(sds[i], (const struct sockaddr *)&addr,
		    sizeof(addr));
		ATF_REQUIRE_MSG(error == 0, "bind() failed: %s",
		    strerror(errno));
		error = listen(sds[i], 1);
		ATF_REQUIRE_MSG(error == 0, "listen() failed: %s",
		    strerror(errno));
	}

	lb_simple_accept_loop(PF_INET, (struct sockaddr *)&addr, sds,
	    nitems(sds), 16384);
	for (i = 0; i < nitems(sds); i++) {
		error = close(sds[i]);
		ATF_REQUIRE_MSG(error == 0, "close() failed: %s",
		    strerror(errno));
	}
}

ATF_TC_WITHOUT_HEAD(basic_ipv6);
ATF_TC_BODY(basic_ipv6, tc)
{
	const struct in6_addr loopback6 = IN6ADDR_LOOPBACK_INIT;
	struct sockaddr_in6 addr;
	socklen_t slen;
	size_t i;
	int error, sds[16];
	uint16_t port;

	sds[0] = lb_listen_socket(PF_INET6);

	memset(&addr, 0, sizeof(addr));
	addr.sin6_len = sizeof(addr);
	addr.sin6_family = AF_INET6;
	addr.sin6_port = htons(0);
	addr.sin6_addr = loopback6;
	error = bind(sds[0], (const struct sockaddr *)&addr, sizeof(addr));
	ATF_REQUIRE(error == 0, "bind() failed: %s", strerror(errno));
	error = listen(sds[0], 1);
	ATF_REQUIRE_MSG(error == 0, "listen() failed: %s", strerror(errno));

	slen = sizeof(addr);
	error = getsockname(sds[0], (struct sockaddr *)&addr, &slen);
	ATF_REQUIRE_MSG(error == 0, "getsockname() failed: %s",
	    strerror(errno));
	ATF_REQUIRE_MSG(slen == sizeof(addr), "sockaddr size changed");
	port = addr.sin6_port;

	memset(&addr, 0, sizeof(addr));
	addr.sin6_len = sizeof(addr);
	addr.sin6_family = AF_INET6;
	addr.sin6_port = port;
	addr.sin6_addr = loopback6;
	for (i = 1; i < nitems(sds); i++) {
		sds[i] = lb_listen_socket(PF_INET6);

		error = bind(sds[i], (const struct sockaddr *)&addr,
		    sizeof(addr));
		ATF_REQUIRE_MSG(error == 0, "bind() failed: %s",
		    strerror(errno));
		error = listen(sds[i], 1);
		ATF_REQUIRE_MSG(error == 0, "listen() failed: %s",
		    strerror(errno));
	}

	lb_simple_accept_loop(PF_INET6, (struct sockaddr *)&addr, sds,
	    nitems(sds), 16384);
	for (i = 0; i < nitems(sds); i++) {
		error = close(sds[i]);
		ATF_REQUIRE_MSG(error == 0, "close() failed: %s",
		    strerror(errno));
	}
}

ATF_TP_ADD_TCS(tp)
{
	ATF_TP_ADD_TC(tp, basic_ipv4);
	ATF_TP_ADD_TC(tp, basic_ipv6);

	return (atf_no_error());
}
