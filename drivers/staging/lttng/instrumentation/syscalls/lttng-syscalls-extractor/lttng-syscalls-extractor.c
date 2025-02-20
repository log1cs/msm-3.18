/* 2017-05-30: File added by Sony Corporation */
/*
 * lttng-syscalls-extractor.c
 *
 * Dump syscall metadata to console.
 *
 * Copyright 2011 - Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 * Copyright 2011 - Julien Desfossez <julien.desfossez@polymtl.ca>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/list.h>
#include <linux/err.h>
#include <linux/slab.h>
#include <linux/kallsyms.h>
#include <linux/dcache.h>
#include <linux/ftrace_event.h>
#include <trace/syscall.h>
#include <asm/syscall.h>

#ifndef CONFIG_FTRACE_SYSCALLS
#error "You need to set CONFIG_FTRACE_SYSCALLS=y"
#endif

#ifndef CONFIG_KALLSYMS_ALL
#error "You need to set CONFIG_KALLSYMS_ALL=y"
#endif

static struct syscall_metadata **__start_syscalls_metadata;
static struct syscall_metadata **__stop_syscalls_metadata;

static __init
struct syscall_metadata *find_syscall_meta(unsigned long syscall)
{
	struct syscall_metadata **iter;

	for (iter = __start_syscalls_metadata;
			iter < __stop_syscalls_metadata; iter++) {
		if ((*iter)->syscall_nr == syscall)
			return (*iter);
	}
	return NULL;
}

int init_module(void)
{
	struct syscall_metadata *meta;
	int i;

	__start_syscalls_metadata = (void *) kallsyms_lookup_name("__start_syscalls_metadata");
	__stop_syscalls_metadata = (void *) kallsyms_lookup_name("__stop_syscalls_metadata");

	for (i = 0; i < NR_syscalls; i++) {
		int j;

		meta = find_syscall_meta(i);
		if (!meta)
			continue;
		printk("syscall %s nr %d nbargs %d ",
			meta->name, meta->syscall_nr, meta->nb_args);
		printk("types: (");
		for (j = 0; j < meta->nb_args; j++) {
			if (j > 0)
				printk(", ");
			printk("%s", meta->types[j]);
		}
		printk(") ");
		printk("args: (");
		for (j = 0; j < meta->nb_args; j++) {
			if (j > 0)
				printk(", ");
			printk("%s", meta->args[j]);
		}
		printk(")\n");
	}
	printk("SUCCESS\n");

	return -1;
}

void cleanup_module(void)
{
}

MODULE_LICENSE("GPL");
