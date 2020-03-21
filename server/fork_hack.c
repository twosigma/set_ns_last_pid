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
#include <dirent.h>
#include <ctype.h>
#include <sys/mount.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <pthread.h>
#include <sys/syscall.h>
#include <sched.h>
#include <err.h>
#include <time.h>
#include <stdbool.h>
#include "set_ns_last_pid.h"
#include "timespec-util.h"
#include "fork_hack.h"

#define MAX_PID_PATH "/proc/sys/kernel/pid_max"

#define FIRST_PID_AFTER_MAX 300

pid_t max_pid;

int num_cpus;
int num_threads;

uint64_t num_pids_to_cycle;
uint64_t num_pids_to_cycle_done;

pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

///////////////////////////////////////////////////////////////////////////////////////////

struct pid_array {
	pid_t *array;
	int num;
};

static void free_pid_array(struct pid_array *pids)
{
	free(pids->array);
}

static int _pid_compare(const void *pa, const void *pb)
{
	pid_t a = *(const pid_t *)pa;
	pid_t b = *(const pid_t *)pb;
	if (a == b) return 0;
	return a < b ? -1 : 1;
}

static int get_system_pids(struct pid_array *pids)
{
	DIR *proc_dir = NULL, *task_dir = NULL;
	struct dirent *proc_dirent = NULL, *task_dirent = NULL;

	int proc_fd = open("/proc", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (proc_fd == -1) {
		warn("Can't open /proc");
		return -1;
	}

	proc_dir = fdopendir(proc_fd);
	if (!proc_dir) {
		warn("Can't opendir /proc");
		return -1;
	}

	pids->num = 0;
	pids->array = calloc(sizeof(int), max_pid);
	if (!pids->array) {
		warn("Can't malloc");
		goto err_closedir;
	}

	/*
	 * We iterate through all the numeric /proc entries. These are the
	 * pids. For each pid, we iterate through the tasks /proc/N/task to
	 * get all the threads ids.
	 */

	for (;;) {
		errno = 0;
		proc_dirent = readdir(proc_dir);
		if (!proc_dirent && errno) {
			warn("Can't readdir()");
			goto err_freearray;
		}
		if (!proc_dirent)
			break;

		if (!isdigit((unsigned char)proc_dirent->d_name[0]))
			continue;

		char name_buf[64];
		snprintf(name_buf, sizeof(name_buf), "%s/task", proc_dirent->d_name);

		int task_fd = openat(proc_fd, name_buf, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
		if (task_fd == -1) {
			/* Task is most likely dead */
			continue;
		}

		task_dir = fdopendir(task_fd);
		if (!task_dir) {
			warn("Can't opendir proc task");
			close(task_fd);
			goto err_freearray;
		}

		while (pids->num < max_pid) {
			errno = 0;
			task_dirent = readdir(task_dir);
			if (!task_dirent && errno) {
				warn("Can't readdir()");
				close(task_fd);
				goto err_freearray;
			}

			if (!task_dirent)
				break;

			if (!isdigit((unsigned char)task_dirent->d_name[0]))
				continue;

			pids->array[pids->num++] = atoi(task_dirent->d_name);
		}

		closedir(task_dir);
	}

	closedir(proc_dir);

	qsort(pids->array, pids->num, sizeof(pids->array[0]), _pid_compare);

	return 0;

err_freearray:
	free_pid_array(pids);
err_closedir:
	closedir(proc_dir);
	return -1;
}

static int count_pids_in_range(const struct pid_array *pids, pid_t min, pid_t max)
{
	int count = 0;

	for (int i = 0; i < pids->num; i++) {
		if (pids->array[i] < min)
			continue;
		if (pids->array[i] > max)
			break;
		count++;
	}

	return count;
}

///////////////////////////////////////////////////////////////////////////////////////////

static pid_t get_ns_last_pid(void)
{
	char buf[64];

	if (lseek(last_pid_fd, 0, SEEK_SET) == -1) {
		warn("Can't seek");
		return -1;
	}

	ssize_t len = read(last_pid_fd, buf, sizeof(buf)-1);
	if (len == -1) {
		warn("Can't read last pid");
		return -1;
	}
	buf[len] = '\0';

	return atoi(buf);
}

static int spawn_child(void)
{
	/* We use CLONE_VFORK to reduce scheduling overhead */
	unsigned long clone_flags = CLONE_VM|CLONE_FS|CLONE_FILES| \
				CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM|CLONE_VFORK;

	long rval = syscall(__NR_clone, clone_flags, 0, 0, NULL);
	if (rval == -1)
		return -1;

	if (rval == 0) {
		/* Child. Must die as quick as possible. */
		syscall(__NR_exit, 0);
	}

	return 0;
}

static void *thread_main(void *arg)
{
	(void)arg;

	pthread_mutex_lock(&mutex);
	for (;;) {
		while (!num_pids_to_cycle)
			pthread_cond_wait(&cond, &mutex);
		num_pids_to_cycle--;
		pthread_mutex_unlock(&mutex);

		if (spawn_child() < 0) {
			if (errno == EAGAIN) {
				/*
				 * We might be failing to fork due to too many
				 * processes, but the PIDs can still get
				 * allocated, so we'll keep counting our
				 * potential success.
				 */
			} else
				err(1, "Can't fork()");
		}

		pthread_mutex_lock(&mutex);
		if (--num_pids_to_cycle_done == 0)
			pthread_cond_broadcast(&cond);
	}

	/* never reached */
	return NULL;
}

static pid_t increment_pid(pid_t pid, int increment)
{
	pid = pid + increment;
	if (pid >= max_pid)
		pid = pid - max_pid + FIRST_PID_AFTER_MAX;
	return pid;
}

int set_ns_last_pid_fork_hack(pid_t pid)
{
	struct pid_array pids;
	pid_t current_pid;

	if (pid < FIRST_PID_AFTER_MAX) {
		warnx("Cannot set pid less than %d", FIRST_PID_AFTER_MAX);
		return -1;
	}

	if (pid >= max_pid) {
		warnx("Cannot set pid more or equal than %d", max_pid);
		return -1;
	}

	int64_t max_total_pids_to_cycle = max_pid * 10;
	int64_t total_cycled_pids = 0;

	for (int pass = 1;; pass++) {
		current_pid = get_ns_last_pid();
		if (current_pid == -1)
			return -1;

		if (current_pid == pid)
			break;

		if (total_cycled_pids > max_total_pids_to_cycle) {
			warnx("Cycled through too many pids, giving up");
			return -1;
		}

		if (get_system_pids(&pids) == -1)
			return -1;

		/*
		 * In reality, we don't really care about setting last_pid.
		 * We care about the pid of the next process that will be
		 * created, and that's pid+1
		 */
		pid_t desired_next_pid = increment_pid(pid, 1);
		if (count_pids_in_range(&pids, desired_next_pid, desired_next_pid))
			warnx("Warning: Desired next pid %d is already taken", desired_next_pid);

		int64_t _num_pids_to_cycle = pid - current_pid;
		if (_num_pids_to_cycle > 0) {
			_num_pids_to_cycle -= count_pids_in_range(&pids, current_pid+1, pid);
		} else {
			/* Rollover */
			_num_pids_to_cycle += max_pid - FIRST_PID_AFTER_MAX;

			_num_pids_to_cycle -= count_pids_in_range(&pids, current_pid+1, max_pid);
			_num_pids_to_cycle -= count_pids_in_range(&pids, FIRST_PID_AFTER_MAX, pid);
		}

		free_pid_array(&pids);

		if (_num_pids_to_cycle == 0)
			break;

		if (_num_pids_to_cycle >= 100) {
			/*
			 * When we have many pids to cycle through, we do
			 * multiple passes, as new processes that we don't
			 * control may be created while we are doing work.
			 */
			_num_pids_to_cycle = _num_pids_to_cycle * 9 / 10;
		}

		debugx("Cycling through %ld pids, pass %d", _num_pids_to_cycle, pass);

		pthread_mutex_lock(&mutex);
		num_pids_to_cycle = _num_pids_to_cycle;
		num_pids_to_cycle_done = _num_pids_to_cycle;
		pthread_cond_broadcast(&cond);

		while (num_pids_to_cycle_done)
			pthread_cond_wait(&cond, &mutex);
		pthread_mutex_unlock(&mutex);

		total_cycled_pids += _num_pids_to_cycle;
	}

	debugx("ns_last_pid is now %d", get_ns_last_pid());

	return 0;
}

static pid_t get_max_pid(void)
{
	int fd = open(MAX_PID_PATH, O_RDONLY);
	if (fd == -1) {
		warn("Can't open " MAX_PID_PATH);
		return -1;
	}

	char buf[64];
	ssize_t len = read(fd, buf, sizeof(buf)-1);
	if (len == -1) {
		warn("Can't read " MAX_PID_PATH);
		return -1;
	}
	buf[len] = '\0';
	return atoi(buf);
}

static int init_threads(void)
{
	for (int i = 0; i < num_threads; i++) {
		pthread_t thread;
		if ((errno = pthread_create(&thread, NULL, thread_main, NULL))) {
			warn("Cannot create thread");
			return -1;
		}
	}

	return 0;
}

int fork_hack_init(void)
{
	max_pid = get_max_pid();
	if (max_pid == -1)
		return -1;

	num_cpus = sysconf(_SC_NPROCESSORS_ONLN);

	/*
	 * The tool doesn't go any faster with more than 16 threads
	 * on a 40 CPU machine due to contention.
	 */
	num_threads = num_cpus + 2;
	if (num_threads > 20)
		num_threads = 20;
	debugx("num CPUs: %d, num threads: %d, max PID: %d",
	       num_cpus, num_threads, max_pid);

	if (init_threads() == -1)
		return -1;

	return 0;
}
