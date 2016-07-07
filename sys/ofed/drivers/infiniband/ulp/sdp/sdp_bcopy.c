/*
 * Copyright (c) 2006 Mellanox Technologies Ltd.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * $Id$
 */
#include "sdp.h"

static void sdp_nagle_timeout(void *data);

static inline int
sdp_nagle_off(struct sdp_sock *ssk, struct mbuf *mb)
{

	struct sdp_bsdh *h;

	h = mtod(mb, struct sdp_bsdh *);
	int send_now =
		unlikely(h->mid != SDP_MID_DATA) ||
		(ssk->flags & SDP_NODELAY) ||
		!ssk->nagle_last_unacked ||
		mb->m_pkthdr.len >= ssk->xmit_size_goal / 4 ||
		(mb->m_flags & M_PUSH);

	if (send_now) {
		unsigned long mseq = ring_head(ssk->tx_ring);
		ssk->nagle_last_unacked = mseq;
	} else {
		if (!callout_pending(&ssk->nagle_timer)) {
			callout_reset(&ssk->nagle_timer, SDP_NAGLE_TIMEOUT,
			    sdp_nagle_timeout, ssk);
		}
	}
	return send_now;
}

static void
sdp_nagle_timeout(void *data)
{
	struct sdp_sock *ssk = (struct sdp_sock *)data;
	struct socket *sk = ssk->socket;

	if (!callout_active(&ssk->nagle_timer))
		return;
	callout_deactivate(&ssk->nagle_timer);

	if (!ssk->nagle_last_unacked)
		goto out;
	if (ssk->state == TCPS_CLOSED)
		return;
	ssk->nagle_last_unacked = 0;
	sdp_post_sends(ssk, M_NOWAIT);

	sowwakeup(ssk->socket);
out:
	if (sk->so_snd.sb_sndptr)
		callout_reset(&ssk->nagle_timer, SDP_NAGLE_TIMEOUT,
		    sdp_nagle_timeout, ssk);
}

void
sdp_post_sends(struct sdp_sock *ssk, int wait)
{
	struct mbuf *mb;
	int post_count = 0;
	struct socket *sk;
	int low;

	sk = ssk->socket;
	if (unlikely(!ssk->id)) {
		if (sk->so_snd.sb_sndptr) {
			sdp_dbg(ssk->socket,
				"Send on socket without cmid ECONNRESET.\n");
			sdp_notify(ssk, ECONNRESET);
		}
		return;
	}
again:
	if (sdp_tx_ring_slots_left(ssk) < SDP_TX_SIZE / 2)
		sdp_xmit_poll(ssk,  1);

	if (ssk->recv_request &&
	    ring_tail(ssk->rx_ring) >= ssk->recv_request_head &&
	    tx_credits(ssk) >= SDP_MIN_TX_CREDITS &&
	    sdp_tx_ring_slots_left(ssk)) {
		mb = sdp_alloc_mb_chrcvbuf_ack(sk,
		    ssk->recv_bytes - SDP_HEAD_SIZE, wait);
		if (mb == NULL)
			goto allocfail;
		ssk->recv_request = 0;
		sdp_post_send(ssk, mb);
		post_count++;
	}

	if (tx_credits(ssk) <= SDP_MIN_TX_CREDITS &&
	    sdp_tx_ring_slots_left(ssk) && sk->so_snd.sb_sndptr &&
	    sdp_nagle_off(ssk, sk->so_snd.sb_sndptr)) {
		SDPSTATS_COUNTER_INC(send_miss_no_credits);
	}

	while (tx_credits(ssk) > SDP_MIN_TX_CREDITS &&
	    sdp_tx_ring_slots_left(ssk) && (mb = sk->so_snd.sb_sndptr) &&
	    sdp_nagle_off(ssk, mb)) {
		struct mbuf *n;

		SOCKBUF_LOCK(&sk->so_snd);
		sk->so_snd.sb_sndptr = mb->m_nextpkt;
		sk->so_snd.sb_mb = mb->m_nextpkt;
		mb->m_nextpkt = NULL;
		SB_EMPTY_FIXUP(&sk->so_snd);
		for (n = mb; n != NULL; n = n->m_next)
			sbfree(&sk->so_snd, n);
		SOCKBUF_UNLOCK(&sk->so_snd);
		sdp_post_send(ssk, mb);
		post_count++;
	}

	if (credit_update_needed(ssk) && ssk->state >= TCPS_ESTABLISHED &&
	    ssk->state < TCPS_FIN_WAIT_2) {
		mb = sdp_alloc_mb_data(ssk->socket, wait);
		if (mb == NULL)
			goto allocfail;
		sdp_post_send(ssk, mb);

		SDPSTATS_COUNTER_INC(post_send_credits);
		post_count++;
	}

	/* send DisConn if needed
	 * Do not send DisConn if there is only 1 credit. Compliance with CA4-82
	 * If one credit is available, an implementation shall only send SDP
	 * messages that provide additional credits and also do not contain ULP
	 * payload. */
	if ((ssk->flags & SDP_NEEDFIN) && !sk->so_snd.sb_sndptr &&
	    tx_credits(ssk) > 1) {
		mb = sdp_alloc_mb_disconnect(sk, wait);
		if (mb == NULL)
			goto allocfail;
		ssk->flags &= ~SDP_NEEDFIN;
		sdp_post_send(ssk, mb);
		post_count++;
	}
	low = (sdp_tx_ring_slots_left(ssk) <= SDP_MIN_TX_CREDITS);
	if (post_count || low) {
		if (low)
			sdp_arm_tx_cq(ssk);
		if (sdp_xmit_poll(ssk, low))
			goto again;
	}
	return;

allocfail:
	ssk->nagle_last_unacked = -1;
	callout_reset(&ssk->nagle_timer, 1, sdp_nagle_timeout, ssk);
	return;
}
