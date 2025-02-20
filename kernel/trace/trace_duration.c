/* 2017-06-02: File added by Sony Corporation */
/*
 * Function duration tracer.
 * Copyright 2009 Sony Corporation
 * Author: Tim Bird <tim.bird@am.sony.com>
 *
 * Mostly borrowed from function graph tracer which
 * is Copyright (c) 2008-2009 Frederic Weisbecker <fweisbec@gmail.com>
 */
#include <linux/debugfs.h>
#include <linux/uaccess.h>
#include <linux/ftrace.h>
#include <linux/fs.h>

#include "trace.h"
#include "trace_output.h"

struct fgraph_data {
	int		depth;
};

#define DURATION_INDENT	2

/* Flag options */
#define DURATION_PRINT_OVERRUN		0x1
#define DURATION_PRINT_CPU		0x2
#define DURATION_PRINT_OVERHEAD		0x4
#define DURATION_PRINT_PROC		0x8
#define DURATION_PRINT_ABS_TIME		0X20

static struct tracer_opt trace_opts[] = {
	/* Display overruns? (for self-debug purpose) */
	{ TRACER_OPT(duration-overrun, DURATION_PRINT_OVERRUN) },
	/* Display CPU ? */
	{ TRACER_OPT(duration-cpu, DURATION_PRINT_CPU) },
	/* Display Overhead ? */
	{ TRACER_OPT(duration-overhead, DURATION_PRINT_OVERHEAD) },
	/* Display proc name/pid */
	{ TRACER_OPT(duration-proc, DURATION_PRINT_PROC) },
	/* Display absolute time of an entry */
	{ TRACER_OPT(duration-abstime, DURATION_PRINT_ABS_TIME) },
	{ } /* Empty entry */
};

static struct tracer_flags tracer_flags = {
	/* Don't display overruns and proc by default */
	.val = DURATION_PRINT_CPU | DURATION_PRINT_OVERHEAD,
	.opts = trace_opts
};


static int duration_trace_init(struct trace_array *tr)
{
	int ret = register_ftrace_graph(&duration_return,
					&duration_entry);
	if (ret)
		return ret;
	tracing_start_cmdline_record();

	return 0;
}

static void duration_trace_reset(struct trace_array *tr)
{
	tracing_stop_cmdline_record();
	unregister_ftrace_graph();
}

static inline int log10_cpu(int nb)
{
	if (nb / 100)
		return 3;
	if (nb / 10)
		return 2;
	return 1;
}

static enum print_line_t
print_duration_cpu(struct trace_seq *s, int cpu)
{
	int i;
	int ret;
	int log10_this = log10_cpu(cpu);
	int log10_all = log10_cpu(cpumask_weight(cpu_online_mask));


	/*
	 * Start with a space character - to make it stand out
	 * to the right a bit when trace output is pasted into
	 * email:
	 */
	ret = trace_seq_printf(s, " ");

	/*
	 * Tricky - we space the CPU field according to the max
	 * number of online CPUs. On a 2-cpu system it would take
	 * a maximum of 1 digit - on a 128 cpu system it would
	 * take up to 3 digits:
	 */
	for (i = 0; i < log10_all - log10_this; i++) {
		ret = trace_seq_printf(s, " ");
		if (!ret)
			return TRACE_TYPE_PARTIAL_LINE;
	}
	ret = trace_seq_printf(s, "%d) ", cpu);
	if (!ret)
		return TRACE_TYPE_PARTIAL_LINE;

	return TRACE_TYPE_HANDLED;
}

#define DURATION_PROCINFO_LENGTH	14

static enum print_line_t
print_duration_proc(struct trace_seq *s, pid_t pid)
{
	char comm[TASK_COMM_LEN];
	/* sign + log10(MAX_INT) + '\0' */
	char pid_str[11];
	int spaces = 0;
	int ret;
	int len;
	int i;

	trace_find_cmdline(pid, comm);
	comm[7] = '\0';
	sprintf(pid_str, "%d", pid);

	/* 1 stands for the "-" character */
	len = strlen(comm) + strlen(pid_str) + 1;

	if (len < DURATION_PROCINFO_LENGTH)
		spaces = DURATION_PROCINFO_LENGTH - len;

	/* First spaces to align center */
	for (i = 0; i < spaces / 2; i++) {
		ret = trace_seq_printf(s, " ");
		if (!ret)
			return TRACE_TYPE_PARTIAL_LINE;
	}

	ret = trace_seq_printf(s, "%s-%s", comm, pid_str);
	if (!ret)
		return TRACE_TYPE_PARTIAL_LINE;

	/* Last spaces to align center */
	for (i = 0; i < spaces - (spaces / 2); i++) {
		ret = trace_seq_printf(s, " ");
		if (!ret)
			return TRACE_TYPE_PARTIAL_LINE;
	}
	return TRACE_TYPE_HANDLED;
}

/* Signal a overhead of time execution to the output */
static int
print_duration_overhead(unsigned long long duration, struct trace_seq *s)
{
	/* Non nested entry or return */
	if (duration == -1)
		return trace_seq_printf(s, "  ");

	if (tracer_flags.val & DURATION_PRINT_OVERHEAD) {
		/* Duration exceeded 100 msecs */
		if (duration > 100000ULL)
			return trace_seq_printf(s, "! ");

		/* Duration exceeded 10 msecs */
		if (duration > 10000ULL)
			return trace_seq_printf(s, "+ ");
	}

	return trace_seq_printf(s, "  ");
}

static int print_duration_abs_time(u64 t, struct trace_seq *s)
{
	unsigned long usecs_rem;

	usecs_rem = do_div(t, NSEC_PER_SEC);
	usecs_rem /= 1000;

	return trace_seq_printf(s, "%5lu.%06lu |  ",
			(unsigned long)t, usecs_rem);
}

static int print_duration_calltime(u64 t, struct trace_seq *s)
{
       unsigned long usecs_rem;

       usecs_rem = do_div(t, NSEC_PER_SEC);

       return trace_seq_printf(s, "%5lu.%09lu |  ",
                       (unsigned long)t, usecs_rem);
}

static enum print_line_t
print_duration_irq(struct trace_iterator *iter, unsigned long addr,
		enum trace_type type, int cpu, pid_t pid)
{
	int ret;
	struct trace_seq *s = &iter->seq;

	if (addr < (unsigned long)__irqentry_text_start ||
		addr >= (unsigned long)__irqentry_text_end)
		return TRACE_TYPE_UNHANDLED;

	/* Absolute time */
	if (tracer_flags.val & DURATION_PRINT_ABS_TIME) {
		ret = print_duration_abs_time(iter->ts, s);
		if (!ret)
			return TRACE_TYPE_PARTIAL_LINE;
	}

	/* Cpu */
	if (tracer_flags.val & DURATION_PRINT_CPU) {
		ret = print_duration_cpu(s, cpu);
		if (ret == TRACE_TYPE_PARTIAL_LINE)
			return TRACE_TYPE_PARTIAL_LINE;
	}
	/* Proc */
	if (tracer_flags.val & DURATION_PRINT_PROC) {
		ret = print_duration_proc(s, pid);
		if (ret == TRACE_TYPE_PARTIAL_LINE)
			return TRACE_TYPE_PARTIAL_LINE;
		ret = trace_seq_printf(s, " | ");
		if (!ret)
			return TRACE_TYPE_PARTIAL_LINE;
	}

	/* No overhead */
	ret = print_duration_overhead(-1, s);
	if (!ret)
		return TRACE_TYPE_PARTIAL_LINE;

	if (type == TRACE_GRAPH_ENT)
		ret = trace_seq_printf(s, "==========>");
	else
		ret = trace_seq_printf(s, "<==========");

	if (!ret)
		return TRACE_TYPE_PARTIAL_LINE;

	/* close the duration column */
	trace_seq_printf(s, " |");
	ret = trace_seq_printf(s, "\n");

	if (!ret)
		return TRACE_TYPE_PARTIAL_LINE;
	return TRACE_TYPE_HANDLED;
}

enum print_line_t
trace_print_duration_duration(unsigned long long duration, struct trace_seq *s)
{
	unsigned long nsecs_rem = do_div(duration, 1000);
	/* log10(ULONG_MAX) + '\0' */
	char msecs_str[21];
	char nsecs_str[5];
	int ret, len;
	int i;

	sprintf(msecs_str, "%lu", (unsigned long) duration);

	/* Print msecs */
	ret = trace_seq_printf(s, "%s", msecs_str);
	if (!ret)
		return TRACE_TYPE_PARTIAL_LINE;

	len = strlen(msecs_str);

	/* Print nsecs (we don't want to exceed 7 numbers) */
	if (len < 7) {
		snprintf(nsecs_str, 8 - len, "%03lu", nsecs_rem);
		ret = trace_seq_printf(s, ".%s", nsecs_str);
		if (!ret)
			return TRACE_TYPE_PARTIAL_LINE;
		len += strlen(nsecs_str);
	}

	ret = trace_seq_printf(s, " us ");
	if (!ret)
		return TRACE_TYPE_PARTIAL_LINE;

	/* Print remaining spaces to fit the row's width */
	for (i = len; i < 7; i++) {
		ret = trace_seq_printf(s, " ");
		if (!ret)
			return TRACE_TYPE_PARTIAL_LINE;
	}
	return TRACE_TYPE_HANDLED;
}

static enum print_line_t
print_duration_duration(unsigned long long duration, struct trace_seq *s)
{
	int ret;

	ret = trace_print_duration_duration(duration, s);
	if (ret != TRACE_TYPE_HANDLED)
		return ret;

	ret = trace_seq_printf(s, "|  ");
	if (!ret)
		return TRACE_TYPE_PARTIAL_LINE;

	return TRACE_TYPE_HANDLED;
}

static enum print_line_t
print_duration_prologue(struct trace_iterator *iter, struct trace_seq *s)

{
	struct trace_entry *ent = iter->ent;
	int cpu = iter->cpu;
	int ret;

	/* Absolute time */
	if (tracer_flags.val & DURATION_PRINT_ABS_TIME) {
		ret = print_duration_abs_time(iter->ts, s);
		if (!ret)
			return TRACE_TYPE_PARTIAL_LINE;
	}

	/* Cpu */
	if (tracer_flags.val & DURATION_PRINT_CPU) {
		ret = print_duration_cpu(s, cpu);
		if (ret == TRACE_TYPE_PARTIAL_LINE)
			return TRACE_TYPE_PARTIAL_LINE;
	}

	/* Proc */
	if (tracer_flags.val & DURATION_PRINT_PROC) {
		ret = print_duration_proc(s, ent->pid);
		if (ret == TRACE_TYPE_PARTIAL_LINE)
			return TRACE_TYPE_PARTIAL_LINE;

		ret = trace_seq_printf(s, " | ");
		if (!ret)
			return TRACE_TYPE_PARTIAL_LINE;
	}

	return 0;
}

static enum print_line_t
print_duration_return(struct ftrace_graph_ret *trace, struct trace_seq *s,
		   struct trace_entry *ent, struct trace_iterator *iter)
{
	unsigned long long duration = trace->rettime - trace->calltime;
	struct fgraph_data *data = iter->private;
	pid_t pid = ent->pid;
	int cpu = iter->cpu;
	int ret;
	int i;

	if (data) {
		int cpu = iter->cpu;
		int *depth = &(per_cpu_ptr(data, cpu)->depth);

		/*
		 * Comments display at + 1 to depth. This is the
		 * return from a function, we now want the comments
		 * to display at the same level of the bracket.
		 */
		*depth = trace->depth - 1;
	}

	if (print_duration_prologue(iter, s))
		return TRACE_TYPE_PARTIAL_LINE;

	/* Calltime */
	ret = print_duration_calltime(trace->calltime, s);
	if (!ret)
		return TRACE_TYPE_PARTIAL_LINE;

	/* Overhead */
	ret = print_duration_overhead(duration, s);
	if (!ret)
		return TRACE_TYPE_PARTIAL_LINE;

	/* Duration */
	ret = print_duration_duration(duration, s);
	if (ret == TRACE_TYPE_PARTIAL_LINE)
		return TRACE_TYPE_PARTIAL_LINE;

	/* Function */
	for (i = 0; i < trace->depth * DURATION_INDENT; i++) {
		ret = trace_seq_printf(s, " ");
		if (!ret)
			return TRACE_TYPE_PARTIAL_LINE;
	}

	ret = seq_print_ip_sym(s, trace->func, 0);
	if (!ret)
		return TRACE_TYPE_PARTIAL_LINE;

	ret = trace_seq_printf(s, "\n");
	if (!ret)
		return TRACE_TYPE_PARTIAL_LINE;

	/* Overrun */
	if (tracer_flags.val & DURATION_PRINT_OVERRUN) {
		ret = trace_seq_printf(s, " (Overruns: %lu)\n",
					trace->overrun);
		if (!ret)
			return TRACE_TYPE_PARTIAL_LINE;
	}

	ret = print_duration_irq(iter, trace->func, TRACE_GRAPH_RET, cpu, pid);
	if (ret == TRACE_TYPE_PARTIAL_LINE)
		return TRACE_TYPE_PARTIAL_LINE;

	return TRACE_TYPE_HANDLED;
}

static enum print_line_t
print_duration_comment(struct trace_seq *s,  struct trace_entry *ent,
		    struct trace_iterator *iter)
{
	unsigned long sym_flags = (trace_flags & TRACE_ITER_SYM_MASK);
	struct fgraph_data *data = iter->private;
	struct trace_event *event;
	int depth = 0;
	int ret;
	int i;

	if (data)
		depth = per_cpu_ptr(data, iter->cpu)->depth;

	if (print_duration_prologue(iter, s))
		return TRACE_TYPE_PARTIAL_LINE;

	/* No overhead */
	ret = print_duration_overhead(-1, s);
	if (!ret)
		return TRACE_TYPE_PARTIAL_LINE;

	/* No time */
	ret = trace_seq_printf(s, "            |  ");
	if (!ret)
		return TRACE_TYPE_PARTIAL_LINE;

	/* Indentation */
	if (depth > 0)
		for (i = 0; i < (depth + 1) * DURATION_INDENT; i++) {
			ret = trace_seq_printf(s, " ");
			if (!ret)
				return TRACE_TYPE_PARTIAL_LINE;
		}

	/* The comment */
	ret = trace_seq_printf(s, "/* ");
	if (!ret)
		return TRACE_TYPE_PARTIAL_LINE;

	switch (iter->ent->type) {
	case TRACE_BPRINT:
		ret = trace_print_bprintk_msg_only(iter);
		if (ret != TRACE_TYPE_HANDLED)
			return ret;
		break;
	case TRACE_PRINT:
		ret = trace_print_printk_msg_only(iter);
		if (ret != TRACE_TYPE_HANDLED)
			return ret;
		break;
	default:
		event = ftrace_find_event(ent->type);
		if (!event)
			return TRACE_TYPE_UNHANDLED;

		ret = event->funcs->trace(iter, sym_flags, event);
		if (ret != TRACE_TYPE_HANDLED)
			return ret;
	}

	/* Strip ending newline */
	if (s->buffer[s->len - 1] == '\n') {
		s->buffer[s->len - 1] = '\0';
		s->len--;
	}

	ret = trace_seq_printf(s, " */\n");
	if (!ret)
		return TRACE_TYPE_PARTIAL_LINE;

	return TRACE_TYPE_HANDLED;
}


enum print_line_t
print_duration_function(struct trace_iterator *iter)
{
	struct trace_entry *entry = iter->ent;
	struct trace_seq *s = &iter->seq;

	switch (entry->type) {
	case TRACE_GRAPH_RET: {
		/* FIXTHIS - removed trace_assign_type here, since it was
		 * redundant.  (No need to use a type-checking macro
		 * inside a case statement which already checked the type.)
		 */
		struct ftrace_graph_ret_entry *ret_entry;
		ret_entry = (struct ftrace_graph_ret_entry *)entry;
		return print_duration_return( &ret_entry->ret, s, entry, iter);
	}
	default:
		return print_duration_comment(s, entry, iter);
	}

	return TRACE_TYPE_HANDLED;
}

static void print_duration_headers(struct seq_file *s)
{
	/* 1st line */
	seq_printf(s, "# ");
	if (tracer_flags.val & DURATION_PRINT_ABS_TIME)
		seq_printf(s, "     TIME       ");
	if (tracer_flags.val & DURATION_PRINT_CPU)
		seq_printf(s, "CPU");
	if (tracer_flags.val & DURATION_PRINT_PROC)
		seq_printf(s, "  TASK/PID      ");
	seq_printf(s, "  CALLTIME     ");
	seq_printf(s, "  DURATION   ");
	seq_printf(s, "               FUNCTION CALLS\n");

	/* 2nd line */
	seq_printf(s, "# ");
	if (tracer_flags.val & DURATION_PRINT_ABS_TIME)
		seq_printf(s, "      |         ");
	if (tracer_flags.val & DURATION_PRINT_CPU)
		seq_printf(s, "|  ");
	if (tracer_flags.val & DURATION_PRINT_PROC)
		seq_printf(s, "  |    |        ");
	seq_printf(s, "    |           ");
	seq_printf(s, "   |   |      ");
	seq_printf(s, "               |   |   |   |\n");
}

static void duration_trace_open(struct trace_iterator *iter)
{
	/* pid and depth on the last trace processed */
	struct fgraph_data *data = alloc_percpu(struct fgraph_data);
	int cpu;

	if (!data)
		pr_warning("duration tracer: not enough memory\n");
	else
		for_each_possible_cpu(cpu) {
			int *depth = &(per_cpu_ptr(data, cpu)->depth);
			*depth = 0;
		}

	iter->private = data;
}

static void duration_trace_close(struct trace_iterator *iter)
{
	free_percpu(iter->private);
}

static struct tracer duration_trace __read_mostly = {
	.name		= "function_duration",
	.open		= duration_trace_open,
	.close		= duration_trace_close,
	.init		= duration_trace_init,
	.reset		= duration_trace_reset,
	.print_line	= print_duration_function,
	.print_header	= print_duration_headers,
	.flags		= &tracer_flags,
};

static __init int init_duration_trace(void)
{
	return register_tracer(&duration_trace);
}

device_initcall(init_duration_trace);
