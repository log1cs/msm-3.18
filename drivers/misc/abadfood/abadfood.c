/* 2017-08-10: File added by Sony Corporation */
/*
 * Copyright (c) 2015 Sony Mobile Communications Inc.
 * All rights, including trade secret rights, reserved.
 */

/*
 * This is the module to occur crash-dump while FOTA kernel running.
 * Then abadfood writes 0xABADF00D to restart_reason,
 * since crash-dump needs it.
 */

#include <linux/init.h>
#include <linux/io.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_address.h>

void *restart_reason;

static __init int abadfood_init(void)
{
    unsigned long val;
    struct device_node *np;

    pr_debug("abadfood: init\n");

    np = of_find_compatible_node(NULL, NULL, "qcom,msm-imem-restart_reason");
    if (np == NULL)
    {
        pr_err("abadfood: unable to find DT imem restart reason node\n");
        return -ENOENT;
    }

    restart_reason = of_iomap(np, 0);
    if (restart_reason == NULL)
    {
        pr_err("abadfood: unable to map imem restart reason offset\n");
        return -ENOENT;
    }

    val = __raw_readl(restart_reason);
    pr_debug("abadfood: prev: addr:%p val:0x%lx\n", restart_reason, val);

    __raw_writel(0xABADF00D, restart_reason);

    val = __raw_readl(restart_reason);
    pr_info("abadfood: restart_reason(%p) set to val:0x%lx\n", restart_reason, val);

    return 0;
}

static __exit void abadfood_exit(void)
{
    unsigned long val;

    val = __raw_readl(restart_reason);
    pr_debug("abadfood: prev: addr:%p val:0x%lx\n", restart_reason, val);

    __raw_writel(0xABADBABE, restart_reason);

    val = __raw_readl(restart_reason);
    pr_info("abadfood: restart_reason(%p) set to val:0x%lx\n", restart_reason, val);

    pr_debug("abadfood: exit\n");
}

module_init(abadfood_init);
module_exit(abadfood_exit);

MODULE_LICENSE("GPL");
