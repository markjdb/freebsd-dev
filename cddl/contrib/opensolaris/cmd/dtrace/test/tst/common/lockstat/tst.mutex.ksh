#!/usr/bin/env ksh -p

if [ $# != 1 ]; then
	echo expected one argument: '<'dtrace-path'>'
	exit 2
fi

dtrace=$1
script=$(mktemp)
cat > $script <<'__EOF__'
test:::adaptive-mutex_test,
test:::spin-mutex_test
{
        if (args[1]) {
                self->lockptr = args[0];
                self->locked = 0;
                self->acquisitions = 0;
                self->releases = 0;
        } else {
                if (self->locked) {
                        exit(1);
                }
                if (self->acquisitions != 1 || self->releases != 1) {
                        exit(1);
                }
                self->lockptr = NULL;
                self->acquisitions = 0;
                self->releases = 0;
        }
}

test:::adaptive-mutex,
test:::spin-mutex
/self->locked/
{
        if (!mutex_owned(args[0]) || mutex_owner(args[0]) != curthread) {
                exit(1);
        }
        if (probename == "adaptive-mutex" && !mutex_type_adaptive(args[0])) {
                exit(1);
        }
        if (probename == "spin-mutex" && !mutex_type_spin(args[0])) {
                exit(1);
        }
}

lockstat:::adaptive-acquire,
lockstat:::spin-acquire
/self->lockptr != NULL/
{
        if (self->lockptr != args[0] || self->locked) {
                exit(1);
        }
        printf("locking '%s'\n", stringof(args[0]->lock_object.lo_name));
        self->locked = 1;
        self->acquisitions++;
}

lockstat:::adaptive-release,
lockstat:::spin-release
/self->locked/
{
        if (args[0] != self->lockptr || !self->locked) {
                exit(1);
        }
        printf("releasing '%s'\n", stringof(args[0]->lock_object.lo_name));
        self->locked = 0;
        self->releases++;
}
__EOF__

$dtrace -x switchrate=100hz -q -s $script -c "sysctl debug.dtrace_test.mutex=1"
status=$?

rm -f $mktemp
exit $status
