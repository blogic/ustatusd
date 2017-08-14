/*
 * Copyright (C) 2017 John Crispin <john@phrozen.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include "ustatusd.h"

#include <glob.h>
#include <ctype.h>
#include <libgen.h>
#include <fcntl.h>
#include <sys/types.h>
#include <regex.h>

#include <libubox/ulog.h>

#define CACHE_SIZE_M	60
#define CACHE_SIZE_H	24
#define CACHE_SIZE_D	3
#define TOUT		(1 * 1000)
#define TOUT_REPORT	(60 * 1000)

static int debug = 0;

struct pid_info {
	struct vlist_node vlist;

	pid_t pid;
	char *name;

	int m_idx;
	int h_idx;
	int d_idx;

	uint32_t m_fd[CACHE_SIZE_M];
	uint32_t m_mem[CACHE_SIZE_M];
	uint32_t m_load[CACHE_SIZE_M];

	uint32_t h_fd[CACHE_SIZE_H];
	uint32_t h_mem[CACHE_SIZE_H];
	uint32_t h_load[CACHE_SIZE_H];

	uint32_t d_fd[CACHE_SIZE_D];
	uint32_t d_mem[CACHE_SIZE_D];
	uint32_t d_load[CACHE_SIZE_D];

	uint64_t last_load;

};

static struct uloop_timeout update_timer;
static struct uloop_timeout report_timer;
static struct vlist_tree proc;

static regex_t pat_vmdata, pat_vmstk, pat_ppid, pat_state, pat_uid;

void resmon_to_blob(struct blob_buf *b)
{
	struct pid_info *pid;
	void *cookie = blobmsg_open_array(b, "proc_stat");

	vlist_for_each_element(&proc, pid, vlist) {
		void *table = blobmsg_open_table(b, NULL);

		blobmsg_add_u32(b, "pid", pid->pid);
		blobmsg_add_string(b, "name", pid->name);
		blobmsg_add_u32(b, "fd", pid->m_fd[pid->m_idx]);
		blobmsg_add_u32(b, "mem", pid->m_mem[pid->m_idx]);
		blobmsg_add_u32(b, "load", pid->m_load[pid->m_idx]);
		blobmsg_close_table(b, table);
	}

	blobmsg_close_array(b, cookie);
}

static void __attribute__((constructor)) measure_init()
{
	regcomp(&pat_vmdata, "VmData:[ \t]*([0-9]*) kB", REG_EXTENDED);
	regcomp(&pat_vmstk, "VmStk:[ \t]*([0-9]*) kB", REG_EXTENDED);
	regcomp(&pat_uid, "Uid:[ \t]*([0-9]*).*", REG_EXTENDED);
	regcomp(&pat_ppid, "PPid:[ \t]*([0-9]+)", REG_EXTENDED);
	regcomp(&pat_state, "State:[ \t]*([A-Z])", REG_EXTENDED);
}

static void __attribute__((destructor)) measure_fini()
{
	regfree(&pat_vmdata);
	regfree(&pat_vmstk);
	regfree(&pat_ppid);
	regfree(&pat_uid);
	regfree(&pat_state);
}

static char *strnchr(char *buf, int c, int i)
{
	while (*buf && i) {
		buf = strchr(buf, c);
		buf++;
		i--;
	}
	return buf;
}

static int measure_process(pid_t pid, uint32_t *fdcount, uint32_t *mem, uint32_t *load, uint64_t *last_load)
{
	int fd;
	char buffer[512] = "";
	ssize_t rxed;
	regmatch_t matches[2];
	glob_t gl;
	int i;
	char *ch;
	uint64_t new_load;

	snprintf(buffer, sizeof(buffer), "/proc/%i/fd/*", (int)pid);

	if (glob(buffer, GLOB_NOESCAPE | GLOB_MARK, NULL, &gl)) {
		if (debug)
			ULOG_INFO("glob failed on %s\n", buffer);
		return -1;
	}

	*fdcount = 0;
	for (i = 0; i < gl.gl_pathc; i++)
		if (isdigit(basename(gl.gl_pathv[i])[0]))
			*fdcount = *fdcount + 1;
	globfree(&gl);

	snprintf(buffer, sizeof(buffer), "/proc/%i/stat", (int)pid);
	fd = open(buffer, O_RDONLY);
	if (fd == -1)
		return -1;

	rxed = read(fd, buffer, sizeof(buffer) - 1);
	close(fd);
	if (rxed == -1)
		return -1;

	buffer[rxed] = 0;

	ch = strnchr(buffer, ' ', 14);
	if (ch) {
		new_load = atoll(ch);
		*load = new_load - *last_load;
		*last_load = new_load;
	}

	snprintf(buffer, sizeof(buffer), "/proc/%i/status", (int)pid);
	fd = open(buffer, O_RDONLY);
	if (fd == -1)
		return -1;

	rxed = read(fd, buffer, sizeof(buffer) - 1);
	close(fd);
	if (rxed == -1)
		return -1;

	buffer[rxed] = 0;

	*mem = 0;
	if (!regexec(&pat_vmdata, buffer, 2, matches, 0))
		*mem += atoi(buffer + matches[1].rm_so) * 1024;

	if (!regexec(&pat_vmstk, buffer, 2, matches, 0))
		*mem += atoi(buffer + matches[1].rm_so) * 1024;

	return 0;
}

static inline void*
pid_to_void(pid_t p)
{
	long pid = p;

	return (void *) pid;
}


static int
proc_load(void)
{
	glob_t gl;
	int i;

	if (glob("/proc/*", GLOB_MARK | GLOB_ONLYDIR | GLOB_NOSORT, NULL, &gl)) {
		if (debug)
			ULOG_INFO("glob failed on /proc/*\n");
		return -1;
	}

	vlist_update(&proc);
	for (i = 0; i < gl.gl_pathc; i++) {
		char *b = basename(gl.gl_pathv[i]);
		char name[512] = { 0 };
		char *_name;
		pid_t pid;
		int fd, len;
		struct pid_info *pi;

		if (!isdigit(b[0]))
			continue;

		pid = (pid_t) atoi(b);
		snprintf(name, sizeof(name), "%s/cmdline", gl.gl_pathv[i]);
		fd = open(name, O_RDONLY);
		if (!fd)
			continue;

		len = read(fd, name, sizeof(name) - 1);
		close(fd);
		if (len < 1)
			continue;
		name[len] = '\0';

		pi = calloc_a(sizeof(*pi), &_name, strlen(name) + 1);
		if (!pi)
			continue;

		memset(pi, 0, sizeof(*pi));
		pi->name = _name;
		strcpy(pi->name, name);
		pi->pid = pid;
		vlist_add(&proc, &pi->vlist, pid_to_void(pi->pid));
		measure_process(pi->pid, &pi->m_fd[pi->m_idx], &pi->m_mem[pi->m_idx], &pi->m_load[pi->m_idx], &pi->last_load);
	}
	globfree(&gl);
	vlist_flush(&proc);

	return 0;
}

static int
pid_cmp(const void *k1, const void *k2, void *ptr)
{
	const pid_t p1 = (const long) k1;
	const pid_t p2 = (const long) k2;

	return p1 - p2;
}

static uint32_t
sum_avg(uint32_t *data, int len)
{
	uint32_t ret = 0;
	int i;

	for (i = 0; i < len; i++)
		ret += data[i];

	return ret / len;
}


static void
pid_update(struct vlist_tree *tree,
		struct vlist_node *node_new, struct vlist_node *node_old)
{
	struct pid_info *pid_old, *pid_new;

	pid_old = container_of(node_old, struct pid_info, vlist);
	pid_new = container_of(node_new, struct pid_info, vlist);

	if (node_old) {
		if (debug && !node_new)
			ULOG_INFO("removing %s(%d)\n", pid_old->name, pid_old->pid);
		free(pid_old);
	}

	if (node_new) {
		if (debug && !node_old)
			ULOG_INFO("new %s(%d)\n", pid_new->name, pid_new->pid);

		pid_new->m_idx++;
		if (pid_new->m_idx % CACHE_SIZE_M == 0) {
			pid_new->m_idx = 0;
			pid_new->h_fd[pid_new->h_idx] = sum_avg(pid_new->m_fd, CACHE_SIZE_M);
			pid_new->h_mem[pid_new->h_idx] = sum_avg(pid_new->m_mem, CACHE_SIZE_M);
			pid_new->h_load[pid_new->h_idx] = sum_avg(pid_new->m_load, CACHE_SIZE_M);
			pid_new->h_idx++;
		}
		if (pid_new->h_idx % CACHE_SIZE_H == 0) {
			pid_new->h_idx = 0;
			pid_new->d_fd[pid_new->d_idx] = sum_avg(pid_new->h_fd, CACHE_SIZE_H);
			pid_new->d_mem[pid_new->d_idx] = sum_avg(pid_new->h_mem, CACHE_SIZE_H);
			pid_new->d_load[pid_new->d_idx] = sum_avg(pid_new->h_load, CACHE_SIZE_H);
			pid_new->d_idx++;
		}
		if (pid_new->d_idx % CACHE_SIZE_D == 0)
			pid_new->d_idx = 0;
	}
}

static void
update_timer_cb(struct uloop_timeout *t)
{
	proc_load();
	uloop_timeout_set(t, TOUT);
}

static void report(void)
{
	struct pid_info *pid;
	struct blob_buf b = { 0 };

	blob_buf_init(&b, 0);
	resmon_to_blob(&b);
	ubus_notify(&conn.ctx, &ubus_object, "proc.stat", b.head, -1);

	vlist_for_each_element(&proc, pid, vlist) {
		if (debug)
			ULOG_INFO("%s(%d) fd:%d mem: %d load:%d\n",
				pid->name, pid->pid, pid->m_fd[pid->m_idx],
				pid->m_mem[pid->m_idx], pid->m_load[pid->m_idx]);
	}
}

static void
report_timer_cb(struct uloop_timeout *t)
{
	report();
	uloop_timeout_set(t, TOUT_REPORT);
}

void
resmon_init(void)
{
	vlist_init(&proc, pid_cmp, pid_update);
	proc_load();
	update_timer.cb = update_timer_cb;
	uloop_timeout_set(&update_timer, TOUT);
	report_timer.cb = report_timer_cb;
	uloop_timeout_set(&report_timer, TOUT);
}
