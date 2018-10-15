/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2018 The FreeBSD Foundation
 *
 * This software was developed by Mark Johnston under sponsorship from
 * the FreeBSD Foundation.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the distribution.
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

#include <sys/types.h>
#include <sys/capsicum.h>
#include <sys/nv.h>
#include <sys/queue.h>
#include <sys/wait.h>

#include <net/if.h>
#include <netinet/in.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <libcasper.h>
#include <libcasper_service.h>

#include "rtsold.h"

int
cap_script_run(cap_channel_t *cap, const char *const *argv)
{
	nvlist_t *nvl;
	size_t argc;
	int error, wfd;

	for (argc = 0; argv[argc] != NULL; argc++) ;

	nvl = nvlist_create(0);
	nvlist_add_string(nvl, "cmd", "run");
	nvlist_add_string_array(nvl, "argv", argv, argc);
	nvl = cap_xfer_nvlist(cap, nvl);
	if (nvl == NULL)
		return (-1);

	error = 0;
	if (nvlist_exists_number(nvl, "error"))
		error = (int)nvlist_get_number(nvl, "error");
	if (error == 0)
		wfd = nvlist_take_descriptor(nvl, "fd");
	nvlist_destroy(nvl);
	errno = error;
	return (error == 0 ? wfd : -1);
}

int
cap_script_wait(cap_channel_t *cap, int *statusp)
{
	nvlist_t *nvl;
	int error;

	nvl = nvlist_create(0);
	nvlist_add_string(nvl, "cmd", "wait");
	nvl = cap_xfer_nvlist(cap, nvl);
	if (nvl == NULL)
		return (-1);

	error = 0;
	if (nvlist_exists_number(nvl, "error"))
		error = (int)nvlist_get_number(nvl, "error");
	if (error == 0)
		*statusp = (int)nvlist_get_number(nvl, "status");
	nvlist_destroy(nvl);
	errno = error;
	return (error == 0 ? 0 : -1);
}

static int
script_command(const char *cmd, const nvlist_t *limits, nvlist_t *nvlin,
    nvlist_t *nvlout)
{
	cap_rights_t rights;
	const char *const *iargv, *const *scripts;
	char **argv;
	size_t argc, i, nscripts;
	pid_t pid;
	int fd[2], null, status;

	if (strcmp(cmd, "wait") == 0) {
		/* Wait for the result of a previous "run" command. */
		if (wait(&status) == -1)
			return (errno);
		nvlist_add_number(nvlout, "status", status);
		return (0);
	}
	if (strcmp(cmd, "run") != 0)
		return (EINVAL);

	/*
	 * Validate the argv against the limits specified at initialization
	 * time.
	 */
	iargv = nvlist_get_string_array(nvlin, "argv", &argc);
	if (argc == 0)
		return (EINVAL);
	scripts = nvlist_get_string_array(limits, "scripts", &nscripts);
	for (i = 0; i < nscripts; i++)
		if (strcmp(iargv[0], scripts[i]) == 0)
			break;
	if (i == nscripts)
		return (EINVAL);

	/*
	 * The nvlist API does not permit NULL pointers in an array, so we have
	 * to add the nul terminator ourselves.  Yuck.
	 */
	argv = calloc(argc + 1, sizeof(*argv));
	if (argv == NULL)
		return (errno);
	memcpy(argv, iargv, sizeof(*argv) * argc);

	/*
	 * Run the script and return the write end of a pipe to the main
	 * process.
	 */
	if (pipe(fd) != 0)
		return (errno);
	if ((pid = fork()) < 0)
		return (errno);
	if (pid == 0) {
		(void)close(fd[1]);
		null = open("/dev/null", O_RDWR);
		if (null < 0)
			_exit(1);
		if (dup2(fd[0], STDIN_FILENO) != STDIN_FILENO ||
		    dup2(null, STDOUT_FILENO) != STDOUT_FILENO ||
		    dup2(null, STDERR_FILENO) != STDERR_FILENO)
			_exit(1);

		(void)close(null);
		(void)execve(argv[0], argv, NULL);
		_exit(1);
	} else {
		(void)close(fd[0]);
		(void)cap_rights_limit(fd[1],
		    cap_rights_init(&rights, CAP_WRITE));
		nvlist_move_descriptor(nvlout, "fd", fd[1]);
	}

	return (0);
}

static int
script_limit(const nvlist_t *oldlimits, const nvlist_t *newlimits __unused)
{
	const char *name;
	void *cookie;
	int nvtype;
	bool hasscripts;

	/* Limits may only be set once. */
	if (oldlimits != NULL)
		return (ENOTCAPABLE);

	cookie = NULL;
	hasscripts = false;
	while ((name = nvlist_next(newlimits, &nvtype, &cookie)) != NULL) {
		if (nvtype == NV_TYPE_STRING_ARRAY &&
		    strcmp(name, "scripts") == 0)
			hasscripts = true;
		else
			return (EINVAL);
	}
	if (!hasscripts)
		return (EINVAL);
	return (0);
}

CREATE_SERVICE("rtsold.script", script_limit, script_command,
    CASPER_SERVICE_STDIO);
