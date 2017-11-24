#!/usr/bin/env ksh -p

if [ $# != 1 ]; then
	echo expected one argument: '<'dtrace-path'>'
	exit 2
fi

dtrace=$1
script=$(mktemp)
cat > $script <<'__EOF__'
test:::adaptive-mutex_test
{
        if (args[1]) {
                self->lockptr = args[0];
                self->locked = 0;
                self->acquisitions = 0;
                self->releases = 0;
                self->blocked = 0;
        } else {
                if (self->locked) {
                        exit(1);
                }
                if (self->acquisitions != 1 || self->releases != 1 ||
                    self->blocked != 1) {
                        exit(1);
                }
                self->lockptr = NULL;
                self->acquisitions = 0;
                self->releases = 0;
                self->blocked = 0;
        }
}

lockstat:::adaptive-acquire
/self->lockptr != NULL/
{
        if (self->lockptr != args[0] || self->locked) {
                exit(1);
        }
        printf("locking '%s'\n", stringof(args[0]->lock_object.lo_name));
        self->locked = 1;
        self->acquisitions++;
}

lockstat:::adaptive-release
/self->lockptr != NULL/
{
        if (args[0] != self->lockptr || !self->locked) {
                exit(1);
        }
        printf("releasing '%s'\n", stringof(args[0]->lock_object.lo_name));
        self->locked = 0;
        self->releases++;
}

lockstat:::adaptive-block
/self->lockptr != NULL/
{
        if (self->lockptr != args[0] || !self->locked) {
                exit(1);
        }
        if (args[1] < 300000000 - 100000000 || args[1] > 300000000 + 100000000) {
                exit(1);
        }
        printf("blocked on '%s'\n", stringof(args[0]->lock_object.lo_name));
        self->blocked++;
}

lockstat:::adaptive-spin
/self->lockptr != NULL/
{
        if (self->lockptr != args[0] || !self->locked) {
                exit(1);
        }
        if (args[1] == 0) {
                exit(1);
        }
}
__EOF__

$dtrace -x switchrate=100hz -q -s $script -c "sysctl debug.dtrace_test.mutex_contended=1"
status=$?

rm -f $mktemp
exit $status
