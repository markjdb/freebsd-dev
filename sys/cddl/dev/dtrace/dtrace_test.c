/*-
 * Copyright 2008 John Birrell <jb@FreeBSD.org>
 * Copyright 2017 Mark Johnston <markj@FreeBSD.org>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
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
#include <sys/systm.h>

#include <sys/conf.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <sys/rwlock.h>
#include <sys/sdt.h>
#include <sys/sx.h>
#include <sys/sysctl.h>
#include <sys/vnode.h>

SDT_PROVIDER_DEFINE(test);

SDT_PROBE_DEFINE7(test, , , sdttest, "int", "int", "int", "int", "int",
    "int", "int");

SDT_PROBE_DEFINE1(test, , , adaptive__mutex, "struct mtx *");
SDT_PROBE_DEFINE2(test, , , adaptive__mutex_test, "struct mtx *", "int");
SDT_PROBE_DEFINE1(test, , , spin__mutex, "struct mtx *");
SDT_PROBE_DEFINE2(test, , , spin__mutex_test, "struct mtx *", "int");
SDT_PROBE_DEFINE1(test, , , rw__lock, "struct rwlock *");
SDT_PROBE_DEFINE2(test, , , rw__lock_test, "struct rwlock *", "int");
SDT_PROBE_DEFINE1(test, , , sx__lock, "struct sx *");
SDT_PROBE_DEFINE2(test, , , sx__lock_test, "struct sx *", "int");

/*
 * These are variables that the DTrace test suite references in the
 * Solaris kernel. We define them here so that the tests function 
 * unaltered.
 */
int	kmem_flags;

typedef struct vnode vnode_t;
vnode_t dummy;
vnode_t *rootvp = &dummy;

static SYSCTL_NODE(_debug, OID_AUTO, dtrace_test, CTLFLAG_RD, 0, "");

static struct mtx dt_mutex;
MTX_SYSINIT(dt_mutex, &dt_mutex, "dtrace test mutex", MTX_DEF);
static struct mtx dt_mutex_spin;
MTX_SYSINIT(dt_mutex_spin, &dt_mutex_spin, "dtrace test spin mutex", MTX_SPIN);
static struct rwlock dt_rwlock;
RW_SYSINIT(dt_rwlock, &dt_rwlock, "dtrace test rw lock");
static struct sx dt_sxlock;
SX_SYSINIT(dt_sxlock, &dt_sxlock, "dtrace test sx lock");

static int
dtrace_test_mutex(SYSCTL_HANDLER_ARGS)
{
	int val, error;

	val = 0;
	error = sysctl_handle_int(oidp, &val, 0, req);
	if (error || req->newptr == NULL)
		return (error);
	else if (val == 0)
		return (0);

	SDT_PROBE2(test, , , adaptive__mutex_test, &dt_mutex, 1);
	SDT_PROBE1(test, , , adaptive__mutex, &dt_mutex);
	mtx_lock(&dt_mutex);
	SDT_PROBE1(test, , , adaptive__mutex, &dt_mutex);
	mtx_unlock(&dt_mutex);
	SDT_PROBE1(test, , , adaptive__mutex, &dt_mutex);
	SDT_PROBE2(test, , , adaptive__mutex_test, &dt_mutex, 0);

	SDT_PROBE2(test, , , spin__mutex_test, &dt_mutex_spin, 1);
	SDT_PROBE1(test, , , spin__mutex, &dt_mutex_spin);
	mtx_lock_spin(&dt_mutex_spin);
	SDT_PROBE1(test, , , spin__mutex, &dt_mutex_spin);
	mtx_unlock_spin(&dt_mutex_spin);
	SDT_PROBE1(test, , , spin__mutex, &dt_mutex_spin);
	SDT_PROBE2(test, , , spin__mutex_test, &dt_mutex_spin, 0);

	return (0);
}
SYSCTL_PROC(_debug_dtrace_test, OID_AUTO, mutex,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE, NULL, 0,
    dtrace_test_mutex, "I",
    "");

static int
dtrace_test_rw_lock(SYSCTL_HANDLER_ARGS)
{
	int val, error;

	val = 0;
	error = sysctl_handle_int(oidp, &val, 0, req);
	if (error || req->newptr == NULL)
		return (error);
	else if (val == 0)
		return (0);

	SDT_PROBE2(test, , , rw__lock_test, &dt_rwlock, 1);
	SDT_PROBE1(test, , , rw__lock, &dt_rwlock);
	rw_rlock(&dt_rwlock);
	SDT_PROBE1(test, , , rw__lock, &dt_rwlock);
	rw_runlock(&dt_rwlock);
	SDT_PROBE1(test, , , rw__lock, &dt_rwlock);
	rw_wlock(&dt_rwlock);
	SDT_PROBE1(test, , , rw__lock, &dt_rwlock);
	rw_wunlock(&dt_rwlock);
	SDT_PROBE1(test, , , rw__lock, &dt_rwlock);
	rw_rlock(&dt_rwlock);
	SDT_PROBE1(test, , , rw__lock, &dt_rwlock);
	if (!rw_try_upgrade(&dt_rwlock))
		panic("%s: lock upgrade failed", __func__);
	SDT_PROBE1(test, , , rw__lock, &dt_rwlock);
	rw_downgrade(&dt_rwlock);
	SDT_PROBE1(test, , , rw__lock, &dt_rwlock);
	rw_runlock(&dt_rwlock);
	SDT_PROBE1(test, , , rw__lock, &dt_rwlock);
	SDT_PROBE2(test, , , rw__lock_test, &dt_rwlock, 0);

	return (0);
}
SYSCTL_PROC(_debug_dtrace_test, OID_AUTO, rw_lock,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE, NULL, 0,
    dtrace_test_rw_lock, "I",
    "");

static int
dtrace_test_sx_lock(SYSCTL_HANDLER_ARGS)
{
	int val, error;

	val = 0;
	error = sysctl_handle_int(oidp, &val, 0, req);
	if (error || req->newptr == NULL)
		return (error);
	else if (val == 0)
		return (0);

	SDT_PROBE2(test, , , sx__lock_test, &dt_sxlock, 1);
	SDT_PROBE1(test, , , sx__lock, &dt_sxlock);
	sx_slock(&dt_sxlock);
	SDT_PROBE1(test, , , sx__lock, &dt_sxlock);
	sx_sunlock(&dt_sxlock);
	SDT_PROBE1(test, , , sx__lock, &dt_sxlock);
	sx_xlock(&dt_sxlock);
	SDT_PROBE1(test, , , sx__lock, &dt_sxlock);
	sx_xunlock(&dt_sxlock);
	SDT_PROBE1(test, , , sx__lock, &dt_sxlock);
	sx_slock(&dt_sxlock);
	SDT_PROBE1(test, , , sx__lock, &dt_sxlock);
	if (!sx_try_upgrade(&dt_sxlock))
		panic("%s: lock upgrade failed", __func__);
	SDT_PROBE1(test, , , sx__lock, &dt_sxlock);
	sx_downgrade(&dt_sxlock);
	SDT_PROBE1(test, , , sx__lock, &dt_sxlock);
	sx_sunlock(&dt_sxlock);
	SDT_PROBE1(test, , , sx__lock, &dt_sxlock);
	SDT_PROBE2(test, , , sx__lock_test, &dt_sxlock, 0);

	return (0);
}
SYSCTL_PROC(_debug_dtrace_test, OID_AUTO, sx_lock,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE, NULL, 0,
    dtrace_test_sx_lock, "I",
    "");

/*
 * Test SDT probes with more than 5 arguments. On amd64, such probes require
 * special handling since only the first 5 arguments will be passed to
 * dtrace_probe() in registers; the rest must be fetched off the stack.
 */
static int
dtrace_test_sdttest(SYSCTL_HANDLER_ARGS)
{
	int val, error;

	val = 0;
	error = sysctl_handle_int(oidp, &val, 0, req);
	if (error || req->newptr == NULL)
		return (error);
	else if (val == 0)
		return (0);

	SDT_PROBE7(test, , , sdttest, 1, 2, 3, 4, 5, 6, 7);

	return (error);
}
SYSCTL_PROC(_debug_dtrace_test, OID_AUTO, sdttest,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE, NULL, 0,
    dtrace_test_sdttest, "I",
    "");

static int
dtrace_test_modevent(module_t mod, int type, void *data)
{
	int error;

	error = 0;
	switch (type) {
	case MOD_LOAD:
		break;
	case MOD_UNLOAD:
		break;
	case MOD_SHUTDOWN:
		break;
	default:
		error = EOPNOTSUPP;
		break;
	}
	return (error);
}

DEV_MODULE(dtrace_test, dtrace_test_modevent, NULL);
MODULE_VERSION(dtrace_test, 1);
MODULE_DEPEND(dtrace_test, dtraceall, 1, 1, 1);
