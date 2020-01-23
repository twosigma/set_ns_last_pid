/*
 * Copyright 2019 Two Sigma Investments, LP.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <err.h>
#include <dirent.h>
#include <sys/mount.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdbool.h>
#include "fork_hack.h"
#include "set_ns_last_pid.h"

#define LAST_PID_PATH "/proc/sys/kernel/ns_last_pid"
#define TEST_PID 1

bool verbose = false;
bool fork_hack_enabled = false;
int last_pid_fd;

static int set_ns_last_pid_privileged(pid_t pid)
{
	char buf[64];

	if (lseek(last_pid_fd, 0, SEEK_SET) == -1) {
		warn("Can't seek");
		return -1;
	}

	int len = snprintf(buf, sizeof(buf), "%d", pid);
	if (write(last_pid_fd, buf, len) != len) {
		if (errno == EPERM) {
			debugx("Insufficient permissions to write to " LAST_PID_PATH);
			return -2;
		} else {
			warn("Can't write to " LAST_PID_PATH);
			return -1;
		}
	}

	return 0;
}

static int enable_fork_hack(void) {
	if (fork_hack_enabled)
		return 0;

	fork_hack_enabled = true;

	debugx("Falling back on the fork hack");

	return fork_hack_init();
}

static int set_ns_last_pid(pid_t pid)
{
	if (!fork_hack_enabled) {
		/* -2 means that we have insufficient permissions */
		int ret = set_ns_last_pid_privileged(pid);
		if (ret != -2)
			return ret;

		if (enable_fork_hack() == -1)
			return -1;
	}

	return set_ns_last_pid_fork_hack(pid);
}

static int run_server(const char *socket_path)
{
	struct sockaddr_un serv_addr, client_addr;
	if (strlen(socket_path)+1 > sizeof(serv_addr.sun_path)) {
		warnx("Socket path too long");
		return -1;
	}

	int sfd = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (sfd == -1) {
		warn("Can't create socket");
		return -1;
	}

	memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sun_family = AF_UNIX;
	strcpy(serv_addr.sun_path, socket_path);

	umask(~0666);
	unlink(socket_path);
	if (bind(sfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == -1) {
		warn("Can't bind socket");
		close(sfd);
		return -1;
	}

	for (;;) {
		uint32_t pid;

		socklen_t addrlen = sizeof(client_addr);
		ssize_t ret = recvfrom(sfd, &pid, sizeof(pid), 0,
				 (struct sockaddr *)&client_addr, &addrlen);
		if (ret == -1) {
			warn("Can't read from socket");
			return -1;
		}

		char r = set_ns_last_pid((pid_t)pid) == -1 ? 1 : 0;
		if (sendto(sfd, &r, sizeof(r), 0, (struct sockaddr *)&client_addr, addrlen) != 1) {
			warn("Failed to write back to socket");
			/* keep running */
		}
	}
}

static void try_remove_ro_proc_layer(void)
{
	/*
	 * A container runtime might have setup a readonly layer on top on proc.
	 * We take it out, because we need r/w access to /proc/sys/kernel/ns_last_pid
	 */
	int err = umount2("/proc/sys", MNT_DETACH);
	if (err == -1 && errno != EINVAL) {
		debug("Can't unmount /proc/sys");
		/* Keep going, the failure may not be fatal */
	}
}

static int get_last_pid_fd(void)
{
	int fd = open(LAST_PID_PATH, O_RDWR);
	if (fd >= 0)
		return fd;

	if (errno == EROFS) {
		try_remove_ro_proc_layer();
		fd = open(LAST_PID_PATH, O_RDWR);
		if (fd >= 0)
			return fd;
	}

	debug("Can't open %s with write access", LAST_PID_PATH);

	fd = open(LAST_PID_PATH, O_RDONLY);
	if (fd == -1) {
		warn("Can't open " LAST_PID_PATH);
		return -1;
	}

	if (enable_fork_hack() == -1) {
		close(fd);
		return -1;
	}

	return fd;
}

static void usage_and_die(const char *progname)
{
	warnx("%s [-v] [ /absolute/path/to/unix_socket | PID ]", progname);
	exit(1);
}

int main(int argc, char *argv[])
{
	int opt;
	while ((opt = getopt(argc, argv, "v")) != -1) {
		switch (opt) {
			case 'v':
				verbose = true;
				break;
			default: /* '?' */
				usage_and_die(argv[0]);
		}
	}

	if (optind >= argc)
		usage_and_die(argv[0]);

	const char *pid_or_path = argv[optind];

	last_pid_fd = get_last_pid_fd();
	if (last_pid_fd == -1)
		return 1;

	if (pid_or_path[0] == '/') {
		/* server mode */

		/* Check if we need to enable to the fork hack before we start */
		if (!fork_hack_enabled &&
		    set_ns_last_pid_privileged(TEST_PID) == -1 &&
		    enable_fork_hack() == -1)
			return 1;

		if (run_server(pid_or_path) == -1)
			return 1;
		/* never reached */
	} else {
		/* CLI mode */
		pid_t pid = atoi(pid_or_path);
		if (set_ns_last_pid(pid) == -1)
			return 1;
	}

	return 0;
}
