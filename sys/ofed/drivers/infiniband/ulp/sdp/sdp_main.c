/*-
 * Copyright (c) 1982, 1986, 1988, 1990, 1993, 1995
 *      The Regents of the University of California.  All rights reserved.
 * Copyright (c) 2004 The FreeBSD Foundation.  All rights reserved.
 * Copyright (c) 2004-2008 Robert N. M. Watson.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * Excerpts taken from tcp_subr.c, tcp_usrreq.c, uipc_socket.c
 */

/*
 *
 * Copyright (c) 2010 Isilon Systems, Inc.
 * Copyright (c) 2010 iX Systems, Inc.
 * Copyright (c) 2010 Panasas, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice unmodified, this list of conditions, and the following
 *    disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/sockbuf.h>
#include <sys/sysctl.h>

#include "sdp.h"

uma_zone_t	sdp_zone;
struct rwlock	sdp_lock;
LIST_HEAD(, sdp_sock) sdp_list;

struct workqueue_struct *rx_comp_wq;

RW_SYSINIT(sdplockinit, &sdp_lock, "SDP lock");
#define	SDP_LIST_WLOCK()	rw_wlock(&sdp_lock)
#define	SDP_LIST_RLOCK()	rw_rlock(&sdp_lock)
#define	SDP_LIST_WUNLOCK()	rw_wunlock(&sdp_lock)
#define	SDP_LIST_RUNLOCK()	rw_runlock(&sdp_lock)
#define	SDP_LIST_WLOCK_ASSERT()	rw_assert(&sdp_lock, RW_WLOCKED)
#define	SDP_LIST_RLOCK_ASSERT()	rw_assert(&sdp_lock, RW_RLOCKED)
#define	SDP_LIST_LOCK_ASSERT()	rw_assert(&sdp_lock, RW_LOCKED)

MALLOC_DEFINE(M_SDP, "sdp", "Sockets Direct Protocol");

static void sdp_stop_keepalive_timer(struct socket *so);

/*
 * SDP protocol interface to socket abstraction.
 */
/*
 * sdp_sendspace and sdp_recvspace are the default send and receive window
 * sizes, respectively.
 */
u_long	sdp_sendspace = 1024*32;
u_long	sdp_recvspace = 1024*64;

static int sdp_count;

SYSCTL_NODE(_net_inet, OID_AUTO, sdp, CTLFLAG_RD, 0, "sockets direct protocol");

static int	sdp_pcblist(SYSCTL_HANDLER_ARGS);
SYSCTL_PROC(_net_inet_sdp, OID_AUTO, pcblist,
    CTLFLAG_RD | CTLTYPE_STRUCT, 0, 0, sdp_pcblist, "S,xtcpcb",
    "List of active SDP connections");

/*
 * Disable async. CMA events for sockets which are being torn down.
 */
static void
sdp_destroy_cma(struct sdp_sock *ssk)
{

	if (ssk->id == NULL)
		return;
	rdma_destroy_id(ssk->id);
	ssk->id = NULL;
}

static int
sdp_pcbbind(struct sdp_sock *ssk, struct sockaddr *nam, struct ucred *cred)
{
	struct sockaddr_in *sin;
	struct sockaddr_in null;
	int error;

	SDP_WLOCK_ASSERT(ssk);

	if (ssk->lport != 0 || ssk->laddr != INADDR_ANY)
		return (EINVAL);
	/* rdma_bind_addr handles bind races.  */
	SDP_WUNLOCK(ssk);
	if (ssk->id == NULL)
		ssk->id = rdma_create_id(sdp_cma_handler, ssk, RDMA_PS_SDP, IB_QPT_RC);
	if (ssk->id == NULL) {
		SDP_WLOCK(ssk);
		return (ENOMEM);
	}
	if (nam == NULL) {
		null.sin_family = AF_INET;
		null.sin_len = sizeof(null);
		null.sin_addr.s_addr = INADDR_ANY;
		null.sin_port = 0;
		bzero(&null.sin_zero, sizeof(null.sin_zero));
		nam = (struct sockaddr *)&null;
	}
	error = -rdma_bind_addr(ssk->id, nam);
	SDP_WLOCK(ssk);
	if (error == 0) {
		sin = (struct sockaddr_in *)&ssk->id->route.addr.src_addr;
		ssk->laddr = sin->sin_addr.s_addr;
		ssk->lport = sin->sin_port;
	} else
		sdp_destroy_cma(ssk);
	return (error);
}

static void
sdp_pcbfree(struct sdp_sock *ssk)
{

	KASSERT(ssk->socket == NULL, ("ssk %p socket still attached", ssk));
	KASSERT((ssk->flags & SDP_DESTROY) == 0,
	    ("ssk %p already destroyed", ssk));

	sdp_dbg(ssk->socket, "Freeing pcb");
	SDP_WLOCK_ASSERT(ssk);
	ssk->flags |= SDP_DESTROY;
	ssk->flags &= ~SDP_QPACTIVE;
	SDP_WUNLOCK(ssk);
	SDP_LIST_WLOCK();
	sdp_count--;
	LIST_REMOVE(ssk, list);
	SDP_LIST_WUNLOCK();
	crfree(ssk->cred);
	if (ssk->qp != NULL) {
		ib_destroy_qp(ssk->qp);
		ssk->qp = NULL;
	}
	sdp_tx_ring_destroy(ssk);
	sdp_rx_ring_destroy(ssk);
	sdp_destroy_cma(ssk);
	rw_destroy(&ssk->rx_ring.destroyed_lock);
	rw_destroy(&ssk->lock);
	uma_zfree(sdp_zone, ssk);
}

/*
 * Common routines to return a socket address.
 */
static struct sockaddr *
sdp_sockaddr(in_port_t port, struct in_addr *addr_p)
{
	struct sockaddr_in *sin;

	sin = malloc(sizeof(*sin), M_SONAME, M_WAITOK | M_ZERO);
	sin->sin_family = AF_INET;
	sin->sin_len = sizeof(*sin);
	sin->sin_addr = *addr_p;
	sin->sin_port = port;
	return ((struct sockaddr *)sin);
}

static int
sdp_getsockaddr(struct socket *so, struct sockaddr **nam)
{
	struct sdp_sock *ssk;
	struct in_addr addr;
	in_port_t port;

	ssk = sdp_sk(so);
	SDP_RLOCK(ssk);
	port = ssk->lport;
	addr.s_addr = ssk->laddr;
	SDP_RUNLOCK(ssk);

	*nam = sdp_sockaddr(port, &addr);
	return (0);
}

static int
sdp_getpeeraddr(struct socket *so, struct sockaddr **nam)
{
	struct sdp_sock *ssk;
	struct in_addr addr;
	in_port_t port;

	ssk = sdp_sk(so);
	SDP_RLOCK(ssk);
	port = ssk->fport;
	addr.s_addr = ssk->faddr;
	SDP_RUNLOCK(ssk);

	*nam = sdp_sockaddr(port, &addr);
	return (0);
}

static void
sdp_pcbnotifyall(struct in_addr faddr, int errno,
    struct sdp_sock *(*notify)(struct sdp_sock *, int))
{
	struct sdp_sock *ssk, *ssk_temp;

	SDP_LIST_WLOCK();
	LIST_FOREACH_SAFE(ssk, &sdp_list, list, ssk_temp) {
		SDP_WLOCK(ssk);
		if (ssk->faddr != faddr.s_addr || ssk->socket == NULL) {
			SDP_WUNLOCK(ssk);
			continue;
		}
		if ((ssk->flags & SDP_DESTROY) == 0)
			if ((*notify)(ssk, errno))
				SDP_WUNLOCK(ssk);
	}
	SDP_LIST_WUNLOCK();
}

static void
sdp_output_reset(struct sdp_sock *ssk)
{
	struct rdma_cm_id *id;

	SDP_WLOCK_ASSERT(ssk);
	if (ssk->id) {
		id = ssk->id;
		ssk->flags &= ~SDP_QPACTIVE;
		SDP_WUNLOCK(ssk);
		rdma_disconnect(id);
		SDP_WLOCK(ssk);
	}
	ssk->state = TCPS_CLOSED;
}

/*
 * Attempt to close a SDP socket, marking it as dropped, and freeing
 * the socket if we hold the only reference.
 */
static struct sdp_sock *
sdp_closed(struct sdp_sock *ssk)
{
	struct socket *so;

	SDP_WLOCK_ASSERT(ssk);

	ssk->flags |= SDP_DROPPED;
	so = ssk->socket;
	soisdisconnected(so);
	if (ssk->flags & SDP_SOCKREF) {
		KASSERT(so->so_state & SS_PROTOREF,
		    ("sdp_closed: !SS_PROTOREF"));
		ssk->flags &= ~SDP_SOCKREF;
		SDP_WUNLOCK(ssk);
		ACCEPT_LOCK();
		SOCK_LOCK(so);
		so->so_state &= ~SS_PROTOREF;
		sofree(so);
		return (NULL);
	}
	return (ssk);
}

/*
 * Perform timer based shutdowns which can not operate in
 * callout context.
 */
static void
sdp_shutdown_task(void *data, int pending)
{
	struct sdp_sock *ssk;

	ssk = data;
	SDP_WLOCK(ssk);
	/*
	 * I don't think this can race with another call to pcbfree()
	 * because SDP_TIMEWAIT protects it.  SDP_DESTROY may be redundant.
	 */
	if (ssk->flags & SDP_DESTROY)
		panic("sdp_shutdown_task: Racing with pcbfree for ssk %p",
		    ssk);
	if (ssk->flags & SDP_DISCON)
		sdp_output_reset(ssk);
	/* We have to clear this so sdp_detach() will call pcbfree(). */
	ssk->flags &= ~(SDP_TIMEWAIT | SDP_DREQWAIT);
	if ((ssk->flags & SDP_DROPPED) == 0 &&
	    sdp_closed(ssk) == NULL)
		return;
	if (ssk->socket == NULL) {
		sdp_pcbfree(ssk);
		return;
	}
	SDP_WUNLOCK(ssk);
}

/*
 * 2msl has expired, schedule the shutdown task.
 */
static void
sdp_2msl_timeout(void *data)
{
	struct sdp_sock *ssk;

	ssk = data;
	/* Callout canceled. */
        if (!callout_active(&ssk->keep2msl))
		goto out;
        callout_deactivate(&ssk->keep2msl);
	/* Should be impossible, defensive programming. */
	if ((ssk->flags & SDP_TIMEWAIT) == 0)
		goto out;
	taskqueue_enqueue(taskqueue_thread, &ssk->shutdown_task);
out:
	SDP_WUNLOCK(ssk);
	return;
}

/*
 * Schedule the 2msl wait timer.
 */
static void
sdp_2msl_wait(struct sdp_sock *ssk)
{

	SDP_WLOCK_ASSERT(ssk);
	ssk->flags |= SDP_TIMEWAIT;
	ssk->state = TCPS_TIME_WAIT;
	soisdisconnected(ssk->socket);
	callout_reset(&ssk->keep2msl, TCPTV_MSL, sdp_2msl_timeout, ssk);
}

/*
 * Timed out waiting for the final fin/ack from rdma_disconnect().
 */
static void
sdp_dreq_timeout(void *data)
{
	struct sdp_sock *ssk;

	ssk = data;
	/* Callout canceled. */
        if (!callout_active(&ssk->keep2msl))
		goto out;
	/* Callout rescheduled, probably as a different timer. */
	if (callout_pending(&ssk->keep2msl))
		goto out;
        callout_deactivate(&ssk->keep2msl);
	if (ssk->state != TCPS_FIN_WAIT_1 && ssk->state != TCPS_LAST_ACK)
		goto out;
	if ((ssk->flags & SDP_DREQWAIT) == 0)
		goto out;
	ssk->flags &= ~SDP_DREQWAIT;
	ssk->flags |= SDP_DISCON;
	sdp_2msl_wait(ssk);
	ssk->flags &= ~SDP_QPACTIVE;
out:
	SDP_WUNLOCK(ssk);
}

/*
 * Received the final fin/ack.  Cancel the 2msl.
 */
void
sdp_cancel_dreq_wait_timeout(struct sdp_sock *ssk)
{
	sdp_dbg(ssk->socket, "cancelling dreq wait timeout\n");
	ssk->flags &= ~SDP_DREQWAIT;
	sdp_2msl_wait(ssk);
}

static int
sdp_init_sock(struct socket *sk)
{
	struct sdp_sock *ssk = sdp_sk(sk);

	sdp_dbg(sk, "%s\n", __func__);

	callout_init_rw(&ssk->keep2msl, &ssk->lock, CALLOUT_RETURNUNLOCKED);
	TASK_INIT(&ssk->shutdown_task, 0, sdp_shutdown_task, ssk);
	atomic_set(&ssk->mseq_ack, 0);
	sdp_rx_ring_init(ssk);
	ssk->tx_ring.buffer = NULL;
	return (0);
}

/*
 * Allocate an sdp_sock for the socket and reserve socket buffer space.
 */
static int
sdp_attach(struct socket *so, int proto, struct thread *td)
{
	struct sdp_sock *ssk;
	int error;

	ssk = sdp_sk(so);
	KASSERT(ssk == NULL, ("sdp_attach: ssk already set on so %p", so));
	if (so->so_snd.sb_hiwat == 0 || so->so_rcv.sb_hiwat == 0) {
		error = soreserve(so, sdp_sendspace, sdp_recvspace);
		if (error)
			return (error);
	}
	so->so_rcv.sb_flags |= SB_AUTOSIZE;
	so->so_snd.sb_flags |= SB_AUTOSIZE;
	ssk = uma_zalloc(sdp_zone, M_NOWAIT | M_ZERO);
	if (ssk == NULL)
		return (ENOBUFS);
	rw_init(&ssk->lock, "sdpsock");
	ssk->socket = so;
	ssk->cred = crhold(so->so_cred);
	so->so_pcb = (caddr_t)ssk;
	sdp_init_sock(so);
	ssk->flags = 0;
	ssk->state = TCPS_CLOSED;
	mbufq_init(&ssk->rxctlq, INT_MAX);
	SDP_LIST_WLOCK();
	LIST_INSERT_HEAD(&sdp_list, ssk, list);
	sdp_count++;
	SDP_LIST_WUNLOCK();
	if ((so->so_options & SO_LINGER) && so->so_linger == 0)
		so->so_linger = TCP_LINGERTIME;

	return (0);
}

/*
 * Detach SDP from the socket, potentially leaving it around for the
 * timewait to expire.
 */
static void
sdp_detach(struct socket *so)
{
	struct sdp_sock *ssk;

	ssk = sdp_sk(so);
	SDP_WLOCK(ssk);
	KASSERT(ssk->socket != NULL, ("sdp_detach: socket is NULL"));
	ssk->socket->so_pcb = NULL;
	ssk->socket = NULL;
	if (ssk->flags & (SDP_TIMEWAIT | SDP_DREQWAIT))
		SDP_WUNLOCK(ssk);
	else if (ssk->flags & SDP_DROPPED || ssk->state < TCPS_SYN_SENT)
		sdp_pcbfree(ssk);
	else
		panic("sdp_detach: Unexpected state, ssk %p.\n", ssk);
}

/*
 * Allocate a local address for the socket.
 */
static int
sdp_bind(struct socket *so, struct sockaddr *nam, struct thread *td)
{
	int error = 0;
	struct sdp_sock *ssk;
	struct sockaddr_in *sin;

	sin = (struct sockaddr_in *)nam;
	if (nam->sa_len != sizeof (*sin))
		return (EINVAL);
	if (sin->sin_family != AF_INET)
		return (EINVAL);
	if (IN_MULTICAST(ntohl(sin->sin_addr.s_addr)))
		return (EAFNOSUPPORT);

	ssk = sdp_sk(so);
	SDP_WLOCK(ssk);
	if (ssk->flags & (SDP_TIMEWAIT | SDP_DROPPED)) {
		error = EINVAL;
		goto out;
	}
	error = sdp_pcbbind(ssk, nam, td->td_ucred);
out:
	SDP_WUNLOCK(ssk);

	return (error);
}

/*
 * Prepare to accept connections.
 */
static int
sdp_listen(struct socket *so, int backlog, struct thread *td)
{
	int error = 0;
	struct sdp_sock *ssk;

	ssk = sdp_sk(so);
	SDP_WLOCK(ssk);
	if (ssk->flags & (SDP_TIMEWAIT | SDP_DROPPED)) {
		error = EINVAL;
		goto out;
	}
	if (error == 0 && ssk->lport == 0)
		error = sdp_pcbbind(ssk, (struct sockaddr *)0, td->td_ucred);
	SOCK_LOCK(so);
	if (error == 0)
		error = solisten_proto_check(so);
	if (error == 0) {
		solisten_proto(so, backlog);
		ssk->state = TCPS_LISTEN;
	}
	SOCK_UNLOCK(so);

out:
	SDP_WUNLOCK(ssk);
	if (error == 0)
		error = -rdma_listen(ssk->id, backlog);
	return (error);
}

/*
 * Initiate a SDP connection to nam.
 */
static int
sdp_start_connect(struct sdp_sock *ssk, struct sockaddr *nam, struct thread *td)
{
	struct sockaddr_in src;
	struct socket *so;
	int error;

	so = ssk->socket;

	SDP_WLOCK_ASSERT(ssk);
	if (ssk->lport == 0) {
		error = sdp_pcbbind(ssk, (struct sockaddr *)0, td->td_ucred);
		if (error)
			return error;
	}
	src.sin_family = AF_INET;
	src.sin_len = sizeof(src);
	bzero(&src.sin_zero, sizeof(src.sin_zero));
	src.sin_port = ssk->lport;
	src.sin_addr.s_addr = ssk->laddr;
	soisconnecting(so);
	SDP_WUNLOCK(ssk);
	error = -rdma_resolve_addr(ssk->id, (struct sockaddr *)&src, nam,
	    SDP_RESOLVE_TIMEOUT);
	SDP_WLOCK(ssk);
	if (error == 0)
		ssk->state = TCPS_SYN_SENT;

	return 0;
}

/*
 * Initiate SDP connection.
 */
static int
sdp_connect(struct socket *so, struct sockaddr *nam, struct thread *td)
{
	int error = 0;
	struct sdp_sock *ssk;
	struct sockaddr_in *sin;

	sin = (struct sockaddr_in *)nam;
	if (nam->sa_len != sizeof (*sin))
		return (EINVAL);
	if (sin->sin_family != AF_INET)
		return (EINVAL);
	if (IN_MULTICAST(ntohl(sin->sin_addr.s_addr)))
		return (EAFNOSUPPORT);
	if ((error = prison_remote_ip4(td->td_ucred, &sin->sin_addr)) != 0)
		return (error);
	ssk = sdp_sk(so);
	SDP_WLOCK(ssk);
	if (ssk->flags & (SDP_TIMEWAIT | SDP_DROPPED))
		error = EINVAL;
	else
		error = sdp_start_connect(ssk, nam, td);
	SDP_WUNLOCK(ssk);
	return (error);
}

/*
 * Drop a SDP socket, reporting
 * the specified error.  If connection is synchronized,
 * then send a RST to peer.
 */
static struct sdp_sock *
sdp_drop(struct sdp_sock *ssk, int errno)
{
	struct socket *so;

	SDP_WLOCK_ASSERT(ssk);
	so = ssk->socket;
	if (TCPS_HAVERCVDSYN(ssk->state))
		sdp_output_reset(ssk);
	if (errno == ETIMEDOUT && ssk->softerror)
		errno = ssk->softerror;
	so->so_error = errno;
	return (sdp_closed(ssk));
}

/*
 * User issued close, and wish to trail through shutdown states:
 * if never received SYN, just forget it.  If got a SYN from peer,
 * but haven't sent FIN, then go to FIN_WAIT_1 state to send peer a FIN.
 * If already got a FIN from peer, then almost done; go to LAST_ACK
 * state.  In all other cases, have already sent FIN to peer (e.g.
 * after PRU_SHUTDOWN), and just have to play tedious game waiting
 * for peer to send FIN or not respond to keep-alives, etc.
 * We can let the user exit from the close as soon as the FIN is acked.
 */
static void
sdp_usrclosed(struct sdp_sock *ssk)
{

	SDP_WLOCK_ASSERT(ssk);

	switch (ssk->state) {
	case TCPS_LISTEN:
		ssk->state = TCPS_CLOSED;
		SDP_WUNLOCK(ssk);
		sdp_destroy_cma(ssk);
		SDP_WLOCK(ssk);
		/* FALLTHROUGH */
	case TCPS_CLOSED:
		ssk = sdp_closed(ssk);
		/*
		 * sdp_closed() should never return NULL here as the socket is
		 * still open.
		 */
		KASSERT(ssk != NULL,
		    ("sdp_usrclosed: sdp_closed() returned NULL"));
		break;

	case TCPS_SYN_SENT:
		/* FALLTHROUGH */
	case TCPS_SYN_RECEIVED:
		ssk->flags |= SDP_NEEDFIN;
		break;

	case TCPS_ESTABLISHED:
		ssk->flags |= SDP_NEEDFIN;
		ssk->state = TCPS_FIN_WAIT_1;
		break;

	case TCPS_CLOSE_WAIT:
		ssk->state = TCPS_LAST_ACK;
		break;
	}
	if (ssk->state >= TCPS_FIN_WAIT_2) {
		/* Prevent the connection hanging in FIN_WAIT_2 forever. */
		if (ssk->state == TCPS_FIN_WAIT_2)
			sdp_2msl_wait(ssk);
		else
			soisdisconnected(ssk->socket);
	}
}

static void
sdp_output_disconnect(struct sdp_sock *ssk)
{

	SDP_WLOCK_ASSERT(ssk);
	callout_reset(&ssk->keep2msl, SDP_FIN_WAIT_TIMEOUT,
	    sdp_dreq_timeout, ssk);
	ssk->flags |= SDP_NEEDFIN | SDP_DREQWAIT;
	sdp_post_sends(ssk, M_NOWAIT);
}

/*
 * Initiate or continue a disconnect.
 * If embryonic state, just send reset (once).
 * If in ``let data drain'' option and linger null, just drop.
 * Otherwise (hard), mark socket disconnecting and drop
 * current input data; switch states based on user close, and
 * send segment to peer (with FIN).
 */
static void
sdp_start_disconnect(struct sdp_sock *ssk)
{
	struct socket *so;
	int unread;

	so = ssk->socket;
	SDP_WLOCK_ASSERT(ssk);
	sdp_stop_keepalive_timer(so);
	/*
	 * Neither sdp_closed() nor sdp_drop() should return NULL, as the
	 * socket is still open.
	 */
	if (ssk->state < TCPS_ESTABLISHED) {
		ssk = sdp_closed(ssk);
		KASSERT(ssk != NULL,
		    ("sdp_start_disconnect: sdp_close() returned NULL"));
	} else if ((so->so_options & SO_LINGER) && so->so_linger == 0) {
		ssk = sdp_drop(ssk, 0);
		KASSERT(ssk != NULL,
		    ("sdp_start_disconnect: sdp_drop() returned NULL"));
	} else {
		soisdisconnecting(so);
		unread = sbused(&so->so_rcv);
		sbflush(&so->so_rcv);
		sdp_usrclosed(ssk);
		if (!(ssk->flags & SDP_DROPPED)) {
			if (unread)
				sdp_output_reset(ssk);
			else
				sdp_output_disconnect(ssk);
		}
	}
}

/*
 * User initiated disconnect.
 */
static int
sdp_disconnect(struct socket *so)
{
	struct sdp_sock *ssk;
	int error = 0;

	ssk = sdp_sk(so);
	SDP_WLOCK(ssk);
	if (ssk->flags & (SDP_TIMEWAIT | SDP_DROPPED)) {
		error = ECONNRESET;
		goto out;
	}
	sdp_start_disconnect(ssk);
out:
	SDP_WUNLOCK(ssk);
	return (error);
}

/*
 * Accept a connection.  Essentially all the work is done at higher levels;
 * just return the address of the peer, storing through addr.
 *
 *
 * XXX This is broken XXX
 * 
 * The rationale for acquiring the sdp lock here is somewhat complicated,
 * and is described in detail in the commit log entry for r175612.  Acquiring
 * it delays an accept(2) racing with sonewconn(), which inserts the socket
 * before the address/port fields are initialized.  A better fix would
 * prevent the socket from being placed in the listen queue until all fields
 * are fully initialized.
 */
static int
sdp_accept(struct socket *so, struct sockaddr **nam)
{
	struct sdp_sock *ssk = NULL;
	struct in_addr addr;
	in_port_t port;
	int error;

	if (so->so_state & SS_ISDISCONNECTED)
		return (ECONNABORTED);

	port = 0;
	addr.s_addr = 0;
	error = 0;
	ssk = sdp_sk(so);
	SDP_WLOCK(ssk);
	if (ssk->flags & (SDP_TIMEWAIT | SDP_DROPPED)) {
		error = ECONNABORTED;
		goto out;
	}
	port = ssk->fport;
	addr.s_addr = ssk->faddr;
out:
	SDP_WUNLOCK(ssk);
	if (error == 0)
		*nam = sdp_sockaddr(port, &addr);
	return error;
}

/*
 * Mark the connection as being incapable of further output.
 */
static int
sdp_shutdown(struct socket *so)
{
	int error = 0;
	struct sdp_sock *ssk;

	ssk = sdp_sk(so);
	SDP_WLOCK(ssk);
	if (ssk->flags & (SDP_TIMEWAIT | SDP_DROPPED)) {
		error = ECONNRESET;
		goto out;
	}
	socantsendmore(so);
	sdp_usrclosed(ssk);
	if (!(ssk->flags & SDP_DROPPED))
		sdp_output_disconnect(ssk);

out:
	SDP_WUNLOCK(ssk);

	return (error);
}

/*
 * Do a send by putting data in output queue and updating urgent
 * marker if URG set.  Possibly send more data.  Unlike the other
 * pru_*() routines, the mbuf chains are our responsibility.  We
 * must either enqueue them or free them.  The other pru_* routines
 * generally are caller-frees.
 */
static int
sdp_send(struct socket *so, int flags, struct mbuf *m,
    struct sockaddr *nam, struct mbuf *control, struct thread *td)
{
	struct sdp_sock *ssk;
	struct mbuf *n;
	int error;
	int cnt;

	error = 0;
	ssk = sdp_sk(so);
	if (m != NULL) {
		KASSERT(m->m_flags & M_PKTHDR,
		    ("sdp_send: %p no packet header", m));
		M_PREPEND(m, SDP_HEAD_SIZE, M_WAITOK);
		mtod(m, struct sdp_bsdh *)->mid = SDP_MID_DATA;
		for (n = m, cnt = 0; n->m_next; n = n->m_next)
			cnt++;
		if (cnt > SDP_MAX_SEND_SGES) {
			n = m_collapse(m, M_WAITOK, SDP_MAX_SEND_SGES);
			if (n == NULL) {
				m_freem(m);
				return (EMSGSIZE);
			}
			m = n;
		}
	}
	SDP_WLOCK(ssk);
	if (ssk->flags & (SDP_TIMEWAIT | SDP_DROPPED)) {
		m_freem(control);
		m_freem(m);
		error = ECONNRESET;
		goto out;
	}
	if (control != NULL) {
		/* SDP doesn't support control messages. */
		if (control->m_len) {
			m_freem(control);
			m_freem(m);
			error = EINVAL;
			goto out;
		}
		m_freem(control);	/* empty control, just free it */
	}
	if ((flags & PRUS_OOB) == 0) {
		sbappendstream(&so->so_snd, m, 0);
		if (nam && ssk->state < TCPS_SYN_SENT) {
			/*
			 * Do implied connect if not yet connected.
			 */
			error = sdp_start_connect(ssk, nam, td);
			if (error)
				goto out;
		}
		if (flags & PRUS_EOF) {
			/*
			 * Close the send side of the connection after
			 * the data is sent.
			 */
			socantsendmore(so);
			sdp_usrclosed(ssk);
			if (!(ssk->flags & SDP_DROPPED))
				sdp_output_disconnect(ssk);
		} else if (!(ssk->flags & SDP_DROPPED) &&
		    !(flags & PRUS_MORETOCOME))
			sdp_post_sends(ssk, M_NOWAIT);
		SDP_WUNLOCK(ssk);
		return (0);
	} else {
		SOCKBUF_LOCK(&so->so_snd);
		if (sbspace(&so->so_snd) < -512) {
			SOCKBUF_UNLOCK(&so->so_snd);
			m_freem(m);
			error = ENOBUFS;
			goto out;
		}
		/*
		 * According to RFC961 (Assigned Protocols),
		 * the urgent pointer points to the last octet
		 * of urgent data.  We continue, however,
		 * to consider it to indicate the first octet
		 * of data past the urgent section.
		 * Otherwise, snd_up should be one lower.
		 */
		if (m != NULL)
			m->m_flags |= M_URG | M_PUSH;
		sbappendstream_locked(&so->so_snd, m, 0);
		SOCKBUF_UNLOCK(&so->so_snd);
		if (nam && ssk->state < TCPS_SYN_SENT) {
			/*
			 * Do implied connect if not yet connected.
			 */
			error = sdp_start_connect(ssk, nam, td);
			if (error)
				goto out;
		}
		sdp_post_sends(ssk, M_NOWAIT);
		SDP_WUNLOCK(ssk);
		return (0);
	}
out:
	SDP_WUNLOCK(ssk);
	return (error);
}

static int
sdp_rcvd(struct socket *so, int flags)
{
	struct sdp_sock *ssk;

	ssk = sdp_sk(so);
	SDP_WLOCK(ssk);
	sdp_do_posts(ssk);
	SDP_WUNLOCK(ssk);
	return (0);
}

/*
 * Abort is used to teardown a connection typically while sitting in
 * the accept queue.
 */
void
sdp_abort(struct socket *so)
{
	struct sdp_sock *ssk;

	ssk = sdp_sk(so);
	SDP_WLOCK(ssk);
	/*
	 * If we have not yet dropped, do it now.
	 */
	if (!(ssk->flags & SDP_TIMEWAIT) &&
	    !(ssk->flags & SDP_DROPPED))
		sdp_drop(ssk, ECONNABORTED);
	KASSERT(ssk->flags & SDP_DROPPED, ("sdp_abort: %p not dropped 0x%X",
	    ssk, ssk->flags));
	ssk->flags &= ~SDP_QPACTIVE;
	SDP_WUNLOCK(ssk);
}

/*
 * Close a SDP socket and initiate a friendly disconnect.
 */
static void
sdp_close(struct socket *so)
{
	struct sdp_sock *ssk;

	ssk = sdp_sk(so);
	SDP_WLOCK(ssk);
	/*
	 * If we have not yet dropped, do it now.
	 */
	if (!(ssk->flags & SDP_TIMEWAIT) &&
	    !(ssk->flags & SDP_DROPPED)) 
		sdp_start_disconnect(ssk);

	/*
	 * If we've still not dropped let the socket layer know we're
	 * holding on to the socket and pcb for a while.
	 */
	if (!(ssk->flags & SDP_DROPPED)) {
		SOCK_LOCK(so);
		so->so_state |= SS_PROTOREF;
		SOCK_UNLOCK(so);
		ssk->flags |= SDP_SOCKREF;
	}
	SDP_WUNLOCK(ssk);
}

/*
 * User requests out-of-band data.
 */
static int
sdp_rcvoob(struct socket *so, struct mbuf *m, int flags)
{
	int error = 0;
	struct sdp_sock *ssk;

	ssk = sdp_sk(so);
	SDP_WLOCK(ssk);
	if (!rx_ring_trylock(&ssk->rx_ring)) {
		SDP_WUNLOCK(ssk);
		return (ECONNRESET);
	}
	if (ssk->flags & (SDP_TIMEWAIT | SDP_DROPPED)) {
		error = ECONNRESET;
		goto out;
	}
	if ((so->so_oobmark == 0 &&
	     (so->so_rcv.sb_state & SBS_RCVATMARK) == 0) ||
	    so->so_options & SO_OOBINLINE ||
	    ssk->oobflags & SDP_HADOOB) {
		error = EINVAL;
		goto out;
	}
	if ((ssk->oobflags & SDP_HAVEOOB) == 0) {
		error = EWOULDBLOCK;
		goto out;
	}
	m->m_len = 1;
	*mtod(m, caddr_t) = ssk->iobc;
	if ((flags & MSG_PEEK) == 0)
		ssk->oobflags ^= (SDP_HAVEOOB | SDP_HADOOB);
out:
	rx_ring_unlock(&ssk->rx_ring);
	SDP_WUNLOCK(ssk);
	return (error);
}

void
sdp_urg(struct sdp_sock *ssk, struct mbuf *mb)
{
	struct mbuf *m;
	struct socket *so;

	so = ssk->socket;
	if (so == NULL)
		return;

	so->so_oobmark = sbused(&so->so_rcv) + mb->m_pkthdr.len - 1;
	sohasoutofband(so);
	ssk->oobflags &= ~(SDP_HAVEOOB | SDP_HADOOB);
	if (!(so->so_options & SO_OOBINLINE)) {
		for (m = mb; m->m_next != NULL; m = m->m_next);
		ssk->iobc = *(mtod(m, char *) + m->m_len - 1);
		ssk->oobflags |= SDP_HAVEOOB;
		m->m_len--;
		mb->m_pkthdr.len--;
	}
}

/*
 * Notify a sdp socket of an asynchronous error.
 *
 * Do not wake up user since there currently is no mechanism for
 * reporting soft errors (yet - a kqueue filter may be added).
 */
struct sdp_sock *
sdp_notify(struct sdp_sock *ssk, int error)
{

	SDP_WLOCK_ASSERT(ssk);

	if ((ssk->flags & SDP_TIMEWAIT) ||
	    (ssk->flags & SDP_DROPPED))
		return (ssk);

	/*
	 * Ignore some errors if we are hooked up.
	 */
	if (ssk->state == TCPS_ESTABLISHED &&
	    (error == EHOSTUNREACH || error == ENETUNREACH ||
	     error == EHOSTDOWN))
		return (ssk);
	ssk->softerror = error;
	return sdp_drop(ssk, error);
}

static void
sdp_ctlinput(int cmd, struct sockaddr *sa, void *vip)
{
	struct in_addr faddr;

	faddr = ((struct sockaddr_in *)sa)->sin_addr;
	if (sa->sa_family != AF_INET || faddr.s_addr == INADDR_ANY)
		return;

	sdp_pcbnotifyall(faddr, inetctlerrmap[cmd], sdp_notify);
}

static int
sdp_control(struct socket *so, u_long cmd, caddr_t data, struct ifnet *ifp,
    struct thread *td)
{
	return (EOPNOTSUPP);
}

static void
sdp_keepalive_timeout(void *data)
{
	struct sdp_sock *ssk;

	ssk = data;
	/* Callout canceled. */
        if (!callout_active(&ssk->keep2msl))
                return;
	/* Callout rescheduled as a different kind of timer. */
	if (callout_pending(&ssk->keep2msl))
		goto out;
        callout_deactivate(&ssk->keep2msl);
	if (ssk->flags & SDP_DROPPED ||
	    (ssk->socket->so_options & SO_KEEPALIVE) == 0)
		goto out;
	sdp_post_keepalive(ssk);
	callout_reset(&ssk->keep2msl, SDP_KEEPALIVE_TIME,
	    sdp_keepalive_timeout, ssk);
out:
	SDP_WUNLOCK(ssk);
}


void
sdp_start_keepalive_timer(struct socket *so)
{
	struct sdp_sock *ssk;

	ssk = sdp_sk(so);
	if (!callout_pending(&ssk->keep2msl))
                callout_reset(&ssk->keep2msl, SDP_KEEPALIVE_TIME,
                    sdp_keepalive_timeout, ssk);
}

static void
sdp_stop_keepalive_timer(struct socket *so)
{
	struct sdp_sock *ssk;

	ssk = sdp_sk(so);
	callout_stop(&ssk->keep2msl);
}

/*
 * sdp_ctloutput() must drop the inpcb lock before performing copyin on
 * socket option arguments.  When it re-acquires the lock after the copy, it
 * has to revalidate that the connection is still valid for the socket
 * option.
 */
#define SDP_WLOCK_RECHECK(inp) do {					\
	SDP_WLOCK(ssk);							\
	if (ssk->flags & (SDP_TIMEWAIT | SDP_DROPPED)) {		\
		SDP_WUNLOCK(ssk);					\
		return (ECONNRESET);					\
	}								\
} while(0)

static int
sdp_ctloutput(struct socket *so, struct sockopt *sopt)
{
	int	error, opt, optval;
	struct sdp_sock *ssk;

	error = 0;
	ssk = sdp_sk(so);
	if (sopt->sopt_level == SOL_SOCKET && sopt->sopt_name == SO_KEEPALIVE) {
		SDP_WLOCK(ssk);
		if (so->so_options & SO_KEEPALIVE)
			sdp_start_keepalive_timer(so);
		else
			sdp_stop_keepalive_timer(so);
		SDP_WUNLOCK(ssk);
	}
	if (sopt->sopt_level != IPPROTO_TCP)
		return (error);

	SDP_WLOCK(ssk);
	if (ssk->flags & (SDP_TIMEWAIT | SDP_DROPPED)) {
		SDP_WUNLOCK(ssk);
		return (ECONNRESET);
	}

	switch (sopt->sopt_dir) {
	case SOPT_SET:
		switch (sopt->sopt_name) {
		case TCP_NODELAY:
			SDP_WUNLOCK(ssk);
			error = sooptcopyin(sopt, &optval, sizeof optval,
			    sizeof optval);
			if (error)
				return (error);

			SDP_WLOCK_RECHECK(ssk);
			opt = SDP_NODELAY;
			if (optval)
				ssk->flags |= opt;
			else
				ssk->flags &= ~opt;
			sdp_do_posts(ssk);
			SDP_WUNLOCK(ssk);
			break;

		default:
			SDP_WUNLOCK(ssk);
			error = ENOPROTOOPT;
			break;
		}
		break;

	case SOPT_GET:
		switch (sopt->sopt_name) {
		case TCP_NODELAY:
			optval = ssk->flags & SDP_NODELAY;
			SDP_WUNLOCK(ssk);
			error = sooptcopyout(sopt, &optval, sizeof optval);
			break;
		default:
			SDP_WUNLOCK(ssk);
			error = ENOPROTOOPT;
			break;
		}
		break;
	}
	return (error);
}
#undef SDP_WLOCK_RECHECK

int sdp_mod_count = 0;
int sdp_mod_usec = 0;

void
sdp_set_default_moderation(struct sdp_sock *ssk)
{
	struct ib_cq_attr attr;
	if (sdp_mod_count <= 0 || sdp_mod_usec <= 0)
		return;
	memset(&attr, 0, sizeof(attr));
	attr.moderation.cq_count = sdp_mod_count;
	attr.moderation.cq_period = sdp_mod_usec;

	ib_modify_cq(ssk->rx_ring.cq, &attr, IB_CQ_MODERATION);
}

static void
sdp_dev_add(struct ib_device *device)
{
	struct sdp_device *sdp_dev;

	sdp_dev = malloc(sizeof(*sdp_dev), M_SDP, M_WAITOK | M_ZERO);
	sdp_dev->pd = ib_alloc_pd(device);
	if (IS_ERR(sdp_dev->pd))
		goto out_pd;
        sdp_dev->mr = ib_get_dma_mr(sdp_dev->pd, IB_ACCESS_LOCAL_WRITE);
        if (IS_ERR(sdp_dev->mr))
		goto out_mr;
	ib_set_client_data(device, &sdp_client, sdp_dev);
	return;

out_mr:
	ib_dealloc_pd(sdp_dev->pd);
out_pd:
	free(sdp_dev, M_SDP);
}

static void
sdp_dev_rem(struct ib_device *device)
{
	struct sdp_device *sdp_dev;
	struct sdp_sock *ssk;

	SDP_LIST_WLOCK();
	LIST_FOREACH(ssk, &sdp_list, list) {
		if (ssk->ib_device != device)
			continue;
		SDP_WLOCK(ssk);
		if ((ssk->flags & SDP_DESTROY) == 0)
			ssk = sdp_notify(ssk, ECONNRESET);
		if (ssk)
			SDP_WUNLOCK(ssk);
	}
	SDP_LIST_WUNLOCK();
	/*
	 * XXX Do I need to wait between these two?
	 */
	sdp_dev = ib_get_client_data(device, &sdp_client);
	if (!sdp_dev)
		return;
	ib_dereg_mr(sdp_dev->mr);
	ib_dealloc_pd(sdp_dev->pd);
	free(sdp_dev, M_SDP);
}

struct ib_client sdp_client =
    { .name = "sdp", .add = sdp_dev_add, .remove = sdp_dev_rem };


static int
sdp_pcblist(SYSCTL_HANDLER_ARGS)
{
	int error, n, i;
	struct sdp_sock *ssk;
	struct xinpgen xig;

	/*
	 * The process of preparing the TCB list is too time-consuming and
	 * resource-intensive to repeat twice on every request.
	 */
	if (req->oldptr == NULL) {
		n = sdp_count;
		n += imax(n / 8, 10);
		req->oldidx = 2 * (sizeof xig) + n * sizeof(struct xtcpcb);
		return (0);
	}

	if (req->newptr != NULL)
		return (EPERM);

	/*
	 * OK, now we're committed to doing something.
	 */
	SDP_LIST_RLOCK();
	n = sdp_count;
	SDP_LIST_RUNLOCK();

	error = sysctl_wire_old_buffer(req, 2 * (sizeof xig)
		+ n * sizeof(struct xtcpcb));
	if (error != 0)
		return (error);

	xig.xig_len = sizeof xig;
	xig.xig_count = n;
	xig.xig_gen = 0;
	xig.xig_sogen = so_gencnt;
	error = SYSCTL_OUT(req, &xig, sizeof xig);
	if (error)
		return (error);

	SDP_LIST_RLOCK();
	for (ssk = LIST_FIRST(&sdp_list), i = 0;
	    ssk != NULL && i < n; ssk = LIST_NEXT(ssk, list)) {
		struct xtcpcb xt;

		SDP_RLOCK(ssk);
		if (ssk->flags & SDP_TIMEWAIT) {
			if (ssk->cred != NULL)
				error = cr_cansee(req->td->td_ucred,
				    ssk->cred);
			else
				error = EINVAL;	/* Skip this inp. */
		} else if (ssk->socket)
			error = cr_canseesocket(req->td->td_ucred,
			    ssk->socket);
		else
			error = EINVAL;
		if (error) {
			error = 0;
			goto next;
		}

		bzero(&xt, sizeof(xt));
		xt.xt_len = sizeof xt;
		xt.xt_inp.inp_gencnt = 0;
		xt.xt_inp.inp_vflag = INP_IPV4;
		memcpy(&xt.xt_inp.inp_laddr, &ssk->laddr, sizeof(ssk->laddr));
		xt.xt_inp.inp_lport = ssk->lport;
		memcpy(&xt.xt_inp.inp_faddr, &ssk->faddr, sizeof(ssk->faddr));
		xt.xt_inp.inp_fport = ssk->fport;
		xt.xt_tp.t_state = ssk->state;
		if (ssk->socket != NULL)
			sotoxsocket(ssk->socket, &xt.xt_socket);
		else
			bzero(&xt.xt_socket, sizeof xt.xt_socket);
		xt.xt_socket.xso_protocol = IPPROTO_TCP;
		SDP_RUNLOCK(ssk);
		error = SYSCTL_OUT(req, &xt, sizeof xt);
		if (error)
			break;
		i++;
		continue;
next:
		SDP_RUNLOCK(ssk);
	}
	if (!error) {
		/*
		 * Give the user an updated idea of our state.
		 * If the generation differs from what we told
		 * her before, she knows that something happened
		 * while we were processing this request, and it
		 * might be necessary to retry.
		 */
		xig.xig_gen = 0;
		xig.xig_sogen = so_gencnt;
		xig.xig_count = sdp_count;
		error = SYSCTL_OUT(req, &xig, sizeof xig);
	}
	SDP_LIST_RUNLOCK();
	return (error);
}

static void
sdp_zone_change(void *tag)
{

	uma_zone_set_max(sdp_zone, maxsockets);
}

static void
sdp_init(void)
{

	LIST_INIT(&sdp_list);
	sdp_zone = uma_zcreate("sdp_sock", sizeof(struct sdp_sock),
	    NULL, NULL, NULL, NULL, UMA_ALIGN_PTR, UMA_ZONE_NOFREE);
	uma_zone_set_max(sdp_zone, maxsockets);
	EVENTHANDLER_REGISTER(maxsockets_change, sdp_zone_change, NULL,
		EVENTHANDLER_PRI_ANY);
	rx_comp_wq = create_singlethread_workqueue("rx_comp_wq");
	ib_register_client(&sdp_client);
}

extern struct domain sdpdomain;

struct pr_usrreqs sdp_usrreqs = {
	.pru_abort =		sdp_abort,
	.pru_accept =		sdp_accept,
	.pru_attach =		sdp_attach,
	.pru_bind =		sdp_bind,
	.pru_connect =		sdp_connect,
	.pru_control =		sdp_control,
	.pru_detach =		sdp_detach,
	.pru_disconnect =	sdp_disconnect,
	.pru_listen =		sdp_listen,
	.pru_peeraddr =		sdp_getpeeraddr,
	.pru_rcvoob =		sdp_rcvoob,
	.pru_send =		sdp_send,
	.pru_rcvd =		sdp_rcvd,
	.pru_shutdown =		sdp_shutdown,
	.pru_sockaddr =		sdp_getsockaddr,
	.pru_close =		sdp_close,
};

struct protosw sdpsw[] = {
{
	.pr_type =		SOCK_STREAM,
	.pr_domain =		&sdpdomain,
	.pr_protocol =		IPPROTO_IP,
	.pr_flags =		PR_CONNREQUIRED|PR_IMPLOPCL|PR_WANTRCVD,
	.pr_ctlinput =		sdp_ctlinput,
	.pr_ctloutput =		sdp_ctloutput,
	.pr_usrreqs =		&sdp_usrreqs
},
{
	.pr_type =		SOCK_STREAM,
	.pr_domain =		&sdpdomain,
	.pr_protocol =		IPPROTO_TCP,
	.pr_flags =		PR_CONNREQUIRED|PR_IMPLOPCL|PR_WANTRCVD,
	.pr_ctlinput =		sdp_ctlinput,
	.pr_ctloutput =		sdp_ctloutput,
	.pr_usrreqs =		&sdp_usrreqs
},
};

struct domain sdpdomain = {
	.dom_family =		AF_INET_SDP,
	.dom_name =		"SDP",
	.dom_init =		sdp_init,
	.dom_protosw =		sdpsw,
	.dom_protoswNPROTOSW =	&sdpsw[nitems(sdpsw)],
};

DOMAIN_SET(sdp);

int sdp_debug_level = 1;
int sdp_data_debug_level = 0;
