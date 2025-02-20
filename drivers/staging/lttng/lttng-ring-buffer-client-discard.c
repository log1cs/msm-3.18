/* 2017-05-30: File added by Sony Corporation */
/*
 * lttng-ring-buffer-client-discard.c
 *
 * LTTng lib ring buffer client (discard mode).
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

#include <linux/module.h>
#include <lttng-tracer.h>

#define RING_BUFFER_MODE_TEMPLATE		RING_BUFFER_DISCARD
#define RING_BUFFER_MODE_TEMPLATE_STRING	"discard"
#define RING_BUFFER_OUTPUT_TEMPLATE		RING_BUFFER_SPLICE
#include "lttng-ring-buffer-client.h"

MODULE_LICENSE("GPL and additional rights");
MODULE_AUTHOR("Mathieu Desnoyers");
MODULE_DESCRIPTION("LTTng Ring Buffer Client Discard Mode");
MODULE_VERSION(__stringify(LTTNG_MODULES_MAJOR_VERSION) "."
	__stringify(LTTNG_MODULES_MINOR_VERSION) "."
	__stringify(LTTNG_MODULES_PATCHLEVEL_VERSION)
	LTTNG_MODULES_EXTRAVERSION);
