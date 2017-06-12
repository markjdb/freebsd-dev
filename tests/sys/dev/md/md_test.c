/*-
 * Copyright (c) 2017 Mark Johnston <markj@FreeBSD.org>
 * All rights reserved.
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

#include <sys/disk.h>
#include <sys/mdioctl.h>

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <atf-c.h>

/*
 * Test cases don't appear to have a way to pass values to a cleanup routine,
 * so we need to use global variables.
 */
static int mdunit = -1;
static int mdfd = -1;

/*
 * Page-aligned offset within the first megabyte of a device. For some tests we
 * want to write a sector before reading it, but the first sector is not
 * suitable because of GEOM tasting.
 *
 * XXX disable GEOM tasting instead
 */
#define	SEEK_OFF	(512 * 1024)

static int
mdcreate(struct md_ioctl *mdio)
{
	char mdpath[64];
	int fd;

	mdio->md_version = MDIOVERSION;

	fd = open("/dev/" MDCTL_NAME, O_RDWR);
	ATF_REQUIRE(fd >= 0);
	ATF_REQUIRE(ioctl(fd, MDIOCATTACH, mdio) == 0);
	ATF_REQUIRE(close(fd) == 0);
	mdunit = mdio->md_unit;

	(void)snprintf(mdpath, sizeof(mdpath), "/dev/" MD_NAME "%d",
	    mdio->md_unit);
	fd = open(mdpath, O_RDWR);
	ATF_REQUIRE(fd >= 0);
	mdfd = fd;

	return (fd);
}

static int
mdcreate_basic(enum md_types type, off_t mediasize, u_int sectorsize)
{
	struct md_ioctl mdio;

	memset(&mdio, 0, sizeof(mdio));
	mdio.md_type = type;
	mdio.md_mediasize = mediasize;
	mdio.md_sectorsize = sectorsize;
	mdio.md_options = MD_AUTOUNIT;
	return (mdcreate(&mdio));
}

static void
mdcleanup(void)
{
	struct md_ioctl mdio;
	int fd;

	if (mdfd != -1) {
		(void)close(mdfd);
		mdfd = -1;
	}

	if (mdunit != -1) {
		fd = open("/dev/" MDCTL_NAME, O_RDWR);
		if (fd >= 0) {
			memset(&mdio, 0, sizeof(mdio));
			mdio.md_unit = mdunit;
			mdio.md_options = MD_AUTOUNIT;
			(void)ioctl(fd, MDIOCDETACH, &mdio);
			(void)close(fd);
		}
		mdunit = -1;
	}
}

ATF_TC_WITH_CLEANUP(md__partial_write_swap);
ATF_TC_HEAD(md__partial_write_swap, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}

/*
 * Allocate a page by writing a single page-aligned 512-byte sector, and then
 * read the entire page back.
 */
ATF_TC_BODY(md__partial_write_swap, tc)
{
	char buf[PAGE_SIZE];
	struct md_ioctl mdio;
	int fd, i;

	fd = mdcreate_basic(MD_SWAP, 1 * 1024 * 1024, DEV_BSIZE);

	/* XXX use something other than zeros for the write. */
	memset(buf, 0, sizeof(buf));
	ATF_REQUIRE(lseek(fd, SEEK_OFF, SEEK_SET) == SEEK_OFF);
	ATF_REQUIRE(write(fd, buf, DEV_BSIZE) == DEV_BSIZE);
	ATF_REQUIRE(lseek(fd, SEEK_OFF, SEEK_SET) == SEEK_OFF);
	ATF_REQUIRE(read(fd, buf, sizeof(buf)) == sizeof(buf));
	for (i = 0; i < sizeof(buf); i++)
		ATF_REQUIRE(buf[i] == 0);
}

ATF_TC_CLEANUP(md__partial_write_swap, tc)
{
	mdcleanup();
}

ATF_TC_WITH_CLEANUP(md__partial_delete_swap);
ATF_TC_HEAD(md__partial_delete_swap, tc)
{
	atf_tc_set_md_var(tc, "require.user", "root");
}

/*
 * Allocate a page by deleting a single page-aligned 512-byte sector, and then
 * read the entire page back.
 */
ATF_TC_BODY(md__partial_delete_swap, tc)
{
	char buf[PAGE_SIZE];
	struct md_ioctl mdio;
	off_t args[2];
	int fd, i;

	fd = mdcreate_basic(MD_SWAP, 1 * 1024 * 1024, DEV_BSIZE);

	memset(buf, 0, sizeof(buf));
	args[0] = SEEK_OFF;
	args[1] = DEV_BSIZE;
	ATF_REQUIRE(ioctl(fd, DIOCGDELETE, args) == 0);
	ATF_REQUIRE(lseek(fd, SEEK_OFF, SEEK_SET) == SEEK_OFF);
	ATF_REQUIRE(read(fd, buf, sizeof(buf)) == sizeof(buf));
	for (i = 0; i < sizeof(buf); i++)
		ATF_REQUIRE(buf[i] == 0);
}

ATF_TC_CLEANUP(md__partial_delete_swap, tc)
{
	mdcleanup();
}

ATF_TP_ADD_TCS(tp)
{

	ATF_TP_ADD_TC(tp, md__partial_write_swap);
	ATF_TP_ADD_TC(tp, md__partial_delete_swap);

	return (atf_no_error());
}
