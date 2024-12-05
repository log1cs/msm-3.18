/* 2016-07-14: File added by Sony Corporation */
/*
 *
 * Author: Nandhakumar Rangasamy <Nandhakumar.x.rangasamy@sonymobile.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 */
#include <linux/init.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/rdtags.h>
#include <linux/timekeeper_internal.h>
#include <linux/seq_file.h>
#include <linux/io.h>
#include <linux/slab.h>

static struct timekeeper *tk;

struct rd_tk_core {
	seqcount_t seq;
	struct timekeeper timekeeper;
};

static int crashtime_timekeeper_read(unsigned long *timekeeper_phys_base)
{
	const char *name = "tk_core";
	size_t bufsize = 0;
	char *buf;
	int ret = -1;

	if (rdtags_get_tag_data(name, NULL, &bufsize) != -ENOBUFS) {
		pr_err("Could not find tag \"%s\"!\n",
			name ? name : "NULL");
		return ret;
	}

	buf = kzalloc(bufsize, GFP_KERNEL);
	if (!buf) {
		pr_err("Could not allocate %zd bytes of memory!\n",
			bufsize);
		return ret;
	}

	ret = rdtags_get_tag_data(name, buf, &bufsize);
	if (ret) {
		pr_err("Could not get %zd bytes of data for tag \"%s\": %d!\n",
			 bufsize, name, ret);
		goto exit;
	}

	ret = kstrtoul(buf, 16, timekeeper_phys_base);
	if (ret != 0)
		pr_err("Failed to convert timerkeeper string %d\n", ret);

exit:
	kfree(buf);

	return ret;
}

static int crashtime_proc_show(struct seq_file *m, void *v)
{
	seq_printf(m, "%lu", (unsigned long)tk->xtime_sec);

	return 0;
}

static int crashtime_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, crashtime_proc_show, NULL);
}

static const struct file_operations crashtime_fops = {
	.open  = crashtime_proc_open,
	.read  = seq_read,
};

static int __init crashtime_device_init(void)
{
	unsigned long tk_core_phys_base = 0;
	struct rd_tk_core *tk_core = NULL;
	int ret = 0;

	ret = crashtime_timekeeper_read(&tk_core_phys_base);
	if (ret != 0) {
		pr_err("Failed to get timekeeper physical address\n");
		ret = -EINVAL;
		goto exit;
	}

	pr_info("tk_core phys_base = %lx\n", tk_core_phys_base);
	tk_core = (struct rd_tk_core *)ioremap(tk_core_phys_base,
					sizeof(struct rd_tk_core));
	if (!tk_core) {
		pr_err("Failed to map at tk_core\n");
		ret = -EINVAL;
		goto exit;
	}

	tk = &tk_core->timekeeper;
	pr_info("timekeeper xtime = %lu\n", (unsigned long)tk->xtime_sec);

	if (!proc_create("crashtime", 0, NULL, &crashtime_fops)) {
		ret = -ENOMEM;
		goto exit;
	}

	return 0;

exit:
	if (tk_core) {
		iounmap(tk_core);
		tk_core = NULL;
	}

	return ret;
}

MODULE_AUTHOR("Sony Mobile Communications");
MODULE_DESCRIPTION("Crashtime");
MODULE_LICENSE("GPL V2");

device_initcall(crashtime_device_init);
