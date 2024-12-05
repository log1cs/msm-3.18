/* 2017-04-25: File changed by Sony Corporation */
/*
 * Copyright (C) 2012 ARM Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef __ASM_STACKTRACE_H
#define __ASM_STACKTRACE_H

#include <asm/ptrace.h>

struct stackframe {
	unsigned long fp;
	unsigned long sp;
	unsigned long pc;
};

static __always_inline
void arm64_get_current_stackframe(struct pt_regs *regs,
				struct stackframe *frame)
{
		frame->fp = frame_pointer(regs);
		frame->sp = regs->sp;
		frame->pc = regs->pc;
}

extern int unwind_frame(struct stackframe *frame);
extern void walk_stackframe(struct stackframe *frame,
			    int (*fn)(struct stackframe *, void *), void *data);
extern void dump_backtrace(struct pt_regs *regs, struct task_struct *tsk);

struct unwind_idx {
	unsigned long addr_offset;
	unsigned long insn;
};

struct unwind_table {
	struct list_head list;
	const struct unwind_idx *start;
	const struct unwind_idx *origin;
	const struct unwind_idx *stop;
	unsigned long begin_addr;
	unsigned long end_addr;
};

extern struct unwind_table *unwind_table_add(unsigned long start,
					     unsigned long size,
					     unsigned long text_addr,
					     unsigned long text_size);
extern void unwind_table_del(struct unwind_table *tab);

#endif	/* __ASM_STACKTRACE_H */
