/* 2017-04-26: File changed by Sony Corporation */
/*
 * Stack tracing support
 *
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
#include <linux/kasan.h>
#include <linux/kernel.h>
#include <linux/export.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/stacktrace.h>

#include <asm/irq.h>
#include <asm/stacktrace.h>

/*
 * AArch64 PCS assigns the frame pointer to x29.
 *
 * A simple function prologue looks like this:
 * 	sub	sp, sp, #0x10
 *   	stp	x29, x30, [sp]
 *	mov	x29, sp
 *
 * A simple function epilogue looks like this:
 *	mov	sp, x29
 *	ldp	x29, x30, [sp]
 *	add	sp, sp, #0x10
 */
int notrace unwind_frame(struct stackframe *frame)
{
	unsigned long high, low;
	unsigned long fp = frame->fp;
	unsigned long irq_stack_ptr;

	/*
	 * Use raw_smp_processor_id() to avoid false-positives from
	 * CONFIG_DEBUG_PREEMPT. get_wchan() calls unwind_frame() on sleeping
	 * task stacks, we can be pre-empted in this case, so
	 * {raw_,}smp_processor_id() may give us the wrong value. Sleeping
	 * tasks can't ever be on an interrupt stack, so regardless of cpu,
	 * the checks will always fail.
	 */
	irq_stack_ptr = IRQ_STACK_PTR(raw_smp_processor_id());

	low  = frame->sp;
	/* irq stacks are not THREAD_SIZE aligned */
	if (on_irq_stack(frame->sp, raw_smp_processor_id()))
		high = irq_stack_ptr;
	else
		high = ALIGN(low, THREAD_SIZE) - 0x20;

	if (fp < low || fp > high || fp & 0xf)
		return -EINVAL;

	kasan_disable_current();

	frame->sp = fp + 0x10;
	frame->fp = *(unsigned long *)(fp);
	frame->pc = *(unsigned long *)(fp + 8);

	kasan_enable_current();
	/*
	 * Check whether we are going to walk through from interrupt stack
	 * to task stack.
	 * If we reach the end of the stack - and its an interrupt stack,
	 * read the original task stack pointer from the dummy frame.
	 */
	if (frame->sp == irq_stack_ptr)
		frame->sp = IRQ_STACK_TO_TASK_STACK(irq_stack_ptr);

	return 0;
}

void notrace walk_stackframe(struct stackframe *frame,
		     int (*fn)(struct stackframe *, void *), void *data)
{
	while (1) {
		int ret;

		if (fn(frame, data))
			break;
		ret = unwind_frame(frame);
		if (ret < 0)
			break;
	}
}
EXPORT_SYMBOL(walk_stackframe);

static DEFINE_SPINLOCK(unwind_lock);
static LIST_HEAD(unwind_tables);

static const struct unwind_idx *unwind_find_origin(
		const struct unwind_idx *start, const struct unwind_idx *stop)
{
	pr_debug("%s(%p, %p)\n", __func__, start, stop);
	while (start < stop) {
		const struct unwind_idx *mid = start + ((stop - start) >> 1);

		if (mid->addr_offset >= 0x40000000)
			/* negative offset */
			start = mid + 1;
		else
			/* positive offset */
			stop = mid;
	}
	pr_debug("%s -> %p\n", __func__, stop);
	return stop;
}

struct unwind_table *unwind_table_add(unsigned long start, unsigned long size,
				      unsigned long text_addr,
				      unsigned long text_size)
{
	unsigned long flags;
	struct unwind_table *tab = kmalloc(sizeof(*tab), GFP_KERNEL);

	pr_debug("%s(%08lx, %08lx, %08lx, %08lx)\n", __func__, start, size,
		 text_addr, text_size);

	if (!tab)
		return tab;

	tab->start = (const struct unwind_idx *)start;
	tab->stop = (const struct unwind_idx *)(start + size);
	tab->origin = unwind_find_origin(tab->start, tab->stop);
	tab->begin_addr = text_addr;
	tab->end_addr = text_addr + text_size;

	spin_lock_irqsave(&unwind_lock, flags);
	list_add_tail(&tab->list, &unwind_tables);
	spin_unlock_irqrestore(&unwind_lock, flags);

	return tab;
}

void unwind_table_del(struct unwind_table *tab)
{
	unsigned long flags;

	if (!tab)
		return;

	spin_lock_irqsave(&unwind_lock, flags);
	list_del(&tab->list);
	spin_unlock_irqrestore(&unwind_lock, flags);

	kfree(tab);
}

#ifdef CONFIG_STACKTRACE
struct stack_trace_data {
	struct stack_trace *trace;
	unsigned int no_sched_functions;
	unsigned int skip;
};

static int save_trace(struct stackframe *frame, void *d)
{
	struct stack_trace_data *data = d;
	struct stack_trace *trace = data->trace;
	unsigned long addr = frame->pc;

	if (data->no_sched_functions && in_sched_functions(addr))
		return 0;
	if (data->skip) {
		data->skip--;
		return 0;
	}

	trace->entries[trace->nr_entries++] = addr;

	return trace->nr_entries >= trace->max_entries;
}

void save_stack_trace_tsk(struct task_struct *tsk, struct stack_trace *trace)
{
	struct stack_trace_data data;
	struct stackframe frame;

	data.trace = trace;
	data.skip = trace->skip;

	if (tsk != current) {
		data.no_sched_functions = 1;
		frame.fp = thread_saved_fp(tsk);
		frame.sp = thread_saved_sp(tsk);
		frame.pc = thread_saved_pc(tsk);
	} else {
		data.no_sched_functions = 0;
		frame.fp = (unsigned long)__builtin_frame_address(0);
		frame.sp = current_stack_pointer;
		frame.pc = (unsigned long)save_stack_trace_tsk;
	}

	walk_stackframe(&frame, save_trace, &data);
	if (trace->nr_entries < trace->max_entries)
		trace->entries[trace->nr_entries++] = ULONG_MAX;
}

void save_stack_trace(struct stack_trace *trace)
{
	save_stack_trace_tsk(current, trace);
}
EXPORT_SYMBOL_GPL(save_stack_trace);
#endif
