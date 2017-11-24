#!/usr/bin/env ksh -p

if [ $# != 1 ]; then
	echo expected one argument: '<'dtrace-path'>'
	exit 2
fi

dtrace=$1
script=$(mktemp)
cat > $script <<'__EOF__'
test:::sx-lock_test
{
        if (args[1]) {
                self->lockptr = args[0];
                self->slocked = 0;
                self->xlocked = 0;
                self->sacquisitions = 0;
                self->xacquisitions = 0;
                self->sreleases = 0;
                self->xreleases = 0;
                self->upgrades = 0;
                self->downgrades = 0;
        } else {
                if (self->slocked || self->xlocked) {
                        exit(1);
                }
                if (self->sacquisitions != 2 || self->sreleases != 2) {
                        exit(1);
                }
                if (self->xacquisitions != 1 || self->xreleases != 1) {
                        exit(1);
                }
                if (self->upgrades != 1 || self->downgrades != 1) {
                        exit(1);
                }
                self->lockptr = NULL;
        }
}

test:::sx-lock
/self->slocked/
{
        if (self->xlocked) {
                exit(1);
        }
        if (sx_isexclusive(args[0]) || sx_exclusive_held(args[0]) ||
            !sx_shared_held(args[0])) {
                exit(1);
        }
}

test:::sx-lock
/self->xlocked/
{
        if (self->slocked) {
                exit(1);
        }
        if (!sx_isexclusive(args[0]) || !sx_exclusive_held(args[0]) ||
            sx_shared_held(args[0])) {
                exit(1);
        }
}

test:::sx-lock
/!self->slocked && !self->xlocked/
{
        if (sx_isexclusive(args[0]) || sx_shared_held(args[0]) ||
            sx_exclusive_held(args[0])) {
                exit(1);
        }
}

lockstat:::sx-acquire
/self->lockptr != NULL/
{
        if (self->lockptr != args[0]) {
                exit(1);
        }

        if (args[1] == 1) {
                if (self->xlocked) {
                        exit(1);
                }
                self->slocked = 1;
                self->sacquisitions++;
                printf("read-locking '%s'\n",
                    stringof(args[0]->lock_object.lo_name));
        } else if (args[1] == 0) {
                if (self->slocked) {
                        exit(1);
                }
                self->xlocked = 1;
                self->xacquisitions++;
                printf("write-locking '%s'\n",
                    stringof(args[0]->lock_object.lo_name));
        } else {
                exit(1);
        }
}

lockstat:::sx-release
/self->lockptr != NULL/
{
        if (self->lockptr != args[0]) {
                exit(1);
        }

        if (args[1] == 1) {
                if (self->xlocked || !self->slocked) {
                        exit(1);
                }
                self->slocked = 0;
                self->sreleases++;
                printf("read-unlocking '%s'\n",
                    stringof(args[0]->lock_object.lo_name));
        } else if (args[1] == 0) {
                if (!self->xlocked || self->slocked) {
                        exit(1);
                }
                self->xlocked = 0;
                self->xreleases++;
                printf("write-unlocking '%s'\n",
                    stringof(args[0]->lock_object.lo_name));
        } else {
                exit(1);
        }
}

lockstat:::sx-upgrade
/self->lockptr != NULL/
{
        if (self->lockptr != args[0] || !self->slocked) {
                exit(1);
        }
        self->slocked = 0;
        self->xlocked = 1;
        self->upgrades++;
        printf("upgrading '%s'\n", stringof(args[0]->lock_object.lo_name));
}

lockstat:::sx-downgrade
/self->lockptr != NULL/
{
        if (self->lockptr != args[0] || !self->xlocked) {
                exit(1);
        }
        self->slocked = 1;
        self->xlocked = 0;
        self->downgrades++;
        printf("downgrading '%s'\n", stringof(args[0]->lock_object.lo_name));
}
__EOF__

$dtrace -x switchrate=100hz -q -s $script -c "sysctl debug.dtrace_test.sx_lock=1"
status=$?

rm -f $mktemp
exit $status
