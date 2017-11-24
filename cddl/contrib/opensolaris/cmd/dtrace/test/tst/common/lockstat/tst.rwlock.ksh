#!/usr/bin/env ksh -p

if [ $# != 1 ]; then
	echo expected one argument: '<'dtrace-path'>'
	exit 2
fi

dtrace=$1
script=$(mktemp)
cat > $script <<'__EOF__'
test:::rw-lock_test
{
        if (args[1]) {
                self->lockptr = args[0];
                self->rlocked = 0;
                self->wlocked = 0;
                self->racquisitions = 0;
                self->wacquisitions = 0;
                self->rreleases = 0;
                self->wreleases = 0;
                self->upgrades = 0;
                self->downgrades = 0;
        } else {
                if (self->rlocked || self->wlocked) {
                        exit(1);
                }
                if (self->racquisitions != 2 || self->rreleases != 2) {
                        exit(1);
                }
                if (self->wacquisitions != 1 || self->wreleases != 1) {
                        exit(1);
                }
                if (self->upgrades != 1 || self->downgrades != 1) {
                        exit(1);
                }
                self->lockptr = NULL;
        }
}

test:::rw-lock
/self->rlocked/
{
        if (self->wlocked) {
                exit(1);
        }
        if (rw_iswriter(args[0]) || rw_write_held(args[0]) ||
            !rw_read_held(args[0])) {
                exit(1);
        }
}

test:::rw-lock
/self->wlocked/
{
        if (self->rlocked) {
                exit(1);
        }
        if (!rw_iswriter(args[0]) || !rw_write_held(args[0]) ||
            rw_read_held(args[0])) {
                exit(1);
        }
}

test:::rw-lock
/!self->rlocked && !self->wlocked/
{
        if (rw_iswriter(args[0]) || rw_read_held(args[0]) ||
            rw_write_held(args[0])) {
                exit(1);
        }
}

lockstat:::rw-acquire
/self->lockptr != NULL/
{
        if (self->lockptr != args[0]) {
                exit(1);
        }

        if (args[1] == 1) {
                if (self->wlocked) {
                        exit(1);
                }
                self->rlocked = 1;
                self->racquisitions++;
                printf("read-locking '%s'\n",
                    stringof(args[0]->lock_object.lo_name));
        } else if (args[1] == 0) {
                if (self->rlocked) {
                        exit(1);
                }
                self->wlocked = 1;
                self->wacquisitions++;
                printf("write-locking '%s'\n",
                    stringof(args[0]->lock_object.lo_name));
        } else {
                exit(1);
        }
}

lockstat:::rw-release
/self->lockptr != NULL/
{
        if (self->lockptr != args[0]) {
                exit(1);
        }

        if (args[1] == 1) {
                if (self->wlocked || !self->rlocked) {
                        exit(1);
                }
                self->rlocked = 0;
                self->rreleases++;
                printf("read-unlocking '%s'\n",
                    stringof(args[0]->lock_object.lo_name));
        } else if (args[1] == 0) {
                if (!self->wlocked || self->rlocked) {
                        exit(1);
                }
                self->wlocked = 0;
                self->wreleases++;
                printf("write-unlocking '%s'\n",
                    stringof(args[0]->lock_object.lo_name));
        } else {
                exit(1);
        }
}

lockstat:::rw-upgrade
/self->lockptr != NULL/
{
        if (self->lockptr != args[0] || !self->rlocked) {
                exit(1);
        }
        self->rlocked = 0;
        self->wlocked = 1;
        self->upgrades++;
        printf("upgrading '%s'\n", stringof(args[0]->lock_object.lo_name));
}

lockstat:::rw-downgrade
/self->lockptr != NULL/
{
        if (self->lockptr != args[0] || !self->wlocked) {
                exit(1);
        }
        self->rlocked = 1;
        self->wlocked = 0;
        self->downgrades++;
        printf("downgrading '%s'\n", stringof(args[0]->lock_object.lo_name));
}
__EOF__

$dtrace -x switchrate=100hz -q -s $script -c "sysctl debug.dtrace_test.rw_lock=1"
status=$?

rm -f $mktemp
exit $status
