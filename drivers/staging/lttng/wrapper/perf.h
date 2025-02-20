/* 2017-05-30: File added by Sony Corporation */
#ifndef _LTTNG_WRAPPER_PERF_H
#define _LTTNG_WRAPPER_PERF_H

/*
 * wrapper/perf.h
 *
 * Copyright (C) 2010-2012 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; only
 * version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <linux/perf_event.h>

#ifdef CONFIG_PERF_EVENTS

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,1,0))
static inline struct perf_event *
wrapper_perf_event_create_kernel_counter(struct perf_event_attr *attr,
				int cpu,
				struct task_struct *task,
				perf_overflow_handler_t callback)
{
	return perf_event_create_kernel_counter(attr, cpu, task, callback, NULL);
}
#else /* (LINUX_VERSION_CODE >= KERNEL_VERSION(3,1,0)) */

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,37))
static inline struct perf_event *
wrapper_perf_event_create_kernel_counter(struct perf_event_attr *attr,
				int cpu,
				struct task_struct *task,
				perf_overflow_handler_t callback)
{
	return perf_event_create_kernel_counter(attr, cpu, task, callback);
}
#else /* (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,37)) */
static inline struct perf_event *
wrapper_perf_event_create_kernel_counter(struct perf_event_attr *attr,
				int cpu,
				struct task_struct *task,
				perf_overflow_handler_t callback)
{
	pid_t pid;

	if (!task)
		pid = -1;
	else
		pid = task->pid;

	return perf_event_create_kernel_counter(attr, cpu, pid, callback);
}

#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,37)) */

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,36))
#define local64_read(l)		atomic64_read(l)
#endif

#endif /* (LINUX_VERSION_CODE >= KERNEL_VERSION(3,1,0)) */

#endif /* CONFIG_PERF_EVENTS */

#endif /* _LTTNG_WRAPPER_PERF_H */
