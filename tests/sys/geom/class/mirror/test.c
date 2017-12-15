#include <sys/disk.h>
#include <sys/ioctl.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>

static void
usage(void)
{

	errx(1, "usage: <-d <off> <len> | -f> <dev>");
}

static int
opendev(const char *dev)
{
	int fd;

	fd = open(dev, O_RDWR);
	if (fd == -1)
		err(1, "open(%s)", dev);
	return (fd);
}

static off_t
getparam(char *param)
{
	char *endptr;
	off_t ret;

	endptr = param;
	if (*endptr == '\0')
		usage();
	ret = strtoul(param, &endptr, 0);
	if (*endptr != '\0')
		usage();
	return (ret);
}

int
main(int argc, char **argv)
{
	off_t params[2];
	int ch, fd;
	bool delete, flush;

	delete = flush = false;
	while ((ch = getopt(argc, argv, "df")) != -1) {
		switch (ch) {
		case 'd':
			delete = true;
			break;
		case 'f':
			flush = true;
			break;
		default:
			usage();
			break;
		}
	}
	argc -= optind;
	argv += optind;

	if ((delete && flush) || (!delete && !flush))
		usage();
	if (delete) {
		if (argc != 3)
			usage();

		params[0] = getparam(argv[0]);
		params[1] = getparam(argv[1]);
		fd = opendev(argv[2]);
		if (ioctl(fd, DIOCGDELETE, params) != 0)
			err(1, "ioctl(DIOCGDELETE)");
	} else {
		if (argc != 1)
			usage();
		fd = opendev(argv[0]);
		if (ioctl(fd, DIOCGFLUSH) != 0)
			err(1, "ioctl(DIOCGFLUSH)");
	}

	(void)close(fd);

	return (0);
}
