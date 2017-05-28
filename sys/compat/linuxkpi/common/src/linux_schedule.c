#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include "opt_ktrace.h"
#include "opt_sched.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/condvar.h>
#include <sys/kdb.h>
#include <sys/kernel.h>
#include <sys/ktr.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/resourcevar.h>
#include <sys/sched.h>
#include <sys/sdt.h>
#include <sys/signalvar.h>
#include <sys/sleepqueue.h>
#include <sys/smp.h>
#include <sys/sx.h>
#include <sys/sysctl.h>
#include <sys/sysproto.h>
#include <sys/vmmeter.h>
#ifdef KTRACE
#include <sys/uio.h>
#include <sys/ktrace.h>
#endif

#include <machine/cpu.h>

#include <linux/sched.h>
#include <linux/wait.h>
#include <linux/fs.h>
#include <linux/list.h>

bool
linux_signal_pending(struct task_struct *task)
{
	struct thread *td;
	sigset_t pending;

	td = task->task_thread;
	PROC_LOCK(td->td_proc);
	pending = td->td_siglist;
	SIGSETOR(pending, td->td_proc->p_siglist);
	SIGSETNAND(pending, td->td_sigmask);
	PROC_UNLOCK(td->td_proc);
	return (!SIGISEMPTY(pending));
}

bool
linux_fatal_signal_pending(struct task_struct *task)
{
	struct thread *td;
	bool ret;

	td = task->task_thread;
	PROC_LOCK(td->td_proc);
	ret = SIGISMEMBER(td->td_siglist, SIGKILL) ||
	    SIGISMEMBER(td->td_proc->p_siglist, SIGKILL);
	PROC_UNLOCK(td->td_proc);
	return (ret);
}

bool
linux_signal_pending_state(long state, struct task_struct *task)
{

	MPASS((state & ~TASK_NORMAL) == 0);

	if ((state & TASK_INTERRUPTIBLE) == 0)
		return (false);
	return (linux_signal_pending(task));
}

int
linux_send_sig(int signo, struct task_struct *task)
{
	struct thread *td;

	td = task->task_thread;
	PROC_LOCK(td->td_proc);
	tdsignal(td, signo);
	PROC_UNLOCK(td->td_proc);
	return (0);
}

long
schedule_timeout(long timeout)
{
	struct task_struct *task;
	sbintime_t sbt;
	long ret = 0;
	int state;
	int delta;

	/* under FreeBSD jiffies are 32-bit */
	timeout = (int)timeout;

	/* get task pointer */
	task = current;

	MPASS(task);

	mtx_lock(&task->sleep_lock);

	/* check for invalid timeout or panic */
	if (timeout < 0 || SKIP_SLEEP())
		goto done;

	/* store current ticks value */
	delta = ticks;

	state = atomic_read(&task->state);

	/* check if about to wake up */
	if (state != TASK_WAKING) {
		int flags;

		/* get sleep flags */
		flags = (state == TASK_INTERRUPTIBLE) ? PCATCH : 0;

		/* compute timeout value to use */
		if (timeout == MAX_SCHEDULE_TIMEOUT)
			sbt = 0;		/* infinite timeout */
		else if (timeout < 1)
			sbt = tick_sbt;		/* avoid underflow */
		else
			sbt = tick_sbt * timeout;	/* normal case */

		(void) _sleep(task, &task->sleep_lock.lock_object, flags,
		    "lsti", sbt, 0 , C_HARDCLOCK);

		/* compute number of ticks consumed */
		delta = (ticks - delta);
	} else {
		/* no ticks consumed */
		delta = 0;
	}

	/* compute number of ticks left from timeout */
	ret = timeout - delta;

	/* check for underflow or overflow */
	if (ret < 0 || delta < 0)
		ret = 0;
done:
	set_task_state(task, TASK_RUNNING);

	mtx_unlock(&task->sleep_lock);

	return ((timeout == MAX_SCHEDULE_TIMEOUT) ? timeout : ret);
}
