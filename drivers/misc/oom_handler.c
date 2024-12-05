/* drivers/misc/oom_handler.c
 *
 * Copyright (C) 2020 Sony Corporation
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/notifier.h>
#include <linux/oom.h>
#include <linux/err.h>

#include <asm/uaccess.h>
#include <linux/fs.h>
#include <linux/file.h>

static void suicide(void)
{
	int *null = NULL;
	printk(KERN_INFO "OOM_HANDLER: Invoke panic().\n");
	/* SEGV */
	*null = 1;
}

/* [[noreturn]] */
static int oom_notifier(struct notifier_block *self, unsigned long val,
			void *parm)
{
	printk(KERN_INFO
	       "OOM_HANDLER: Received System OOM notification (%lo).\n",
	       val);
	suicide();
	/* It will not return NOTIFY_STATUS */
	return NOTIFY_OK;
}

static struct notifier_block oom_notifier_block = { .notifier_call =
							    oom_notifier };

static int oom_init(void)
{
	int err;
	printk(KERN_INFO "OOM_HANDLER: Register OOM handler.\n");
	if ((err = register_oom_notifier(&oom_notifier_block)) < 0) {
		printk(KERN_ERR
		       "OOM_HANDLER: Failed to regist OOM handler(%d).\n",
		       err);
		return err;
	}
	return 0;
}

static void oom_exit(void)
{
	printk(KERN_INFO "OOM_HANDLER: Unregister OOM handler.\n");
	unregister_oom_notifier(&oom_notifier_block);
}

module_init(oom_init);
module_exit(oom_exit);

MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("System OOM handler module");
