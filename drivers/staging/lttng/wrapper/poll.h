/* 2017-05-30: File added by Sony Corporation */
#ifndef _LTTNG_WRAPPER_POLL_H
#define _LTTNG_WRAPPER_POLL_H

/*
 * wrapper/poll.h
 *
 * Copyright (C) 2011-2012 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
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

#include <linux/poll.h>

/*
 * Note: poll_wait_set_exclusive() is defined as no-op. Thundering herd
 * effect can be noticed with large number of consumer threads.
 */

#define poll_wait_set_exclusive(poll_table)

#endif /* _LTTNG_WRAPPER_POLL_H */
