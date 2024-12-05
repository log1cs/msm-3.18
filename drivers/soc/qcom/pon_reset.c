/* 2016-07-14: File added by Sony Corporation */
/*
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2, as
 * published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/proc_fs.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <asm/memory.h>
#include <soc/qcom/smem.h>
#include <soc/qcom/hwconfig_status.h>
#ifdef CONFIG_OF
#include <linux/of.h>
#include <linux/of_address.h>
#endif
#ifdef CONFIG_RAMDUMP_MEMDESC
#include <linux/ramdump_mem_desc.h>
#endif

#define MAX_NAME_LEN 32

struct dump_region {
	u64 addr;
	u64 size;
	u8 name[MAX_NAME_LEN];
};

static int get_reset_stat_region(struct mem_desc *region)
{
	struct device_node *imem_gcc_node;
	struct resource *res = NULL;

	if (!region)
		return -EINVAL;
#ifdef CONFIG_OF
	imem_gcc_node = of_find_compatible_node(NULL, NULL,
			"qcom,msm-imem-gcc_reset_base");
	if (!imem_gcc_node) {
		pr_err("gcc reset base in DT does not exist\n");
		return -EINVAL;
	}

	res = kmalloc(sizeof(struct resource), GFP_KERNEL);
	if (!res) {
		pr_err("Failed to allocate memory for res\n");
		return -ENOMEM;
	}

	if (of_address_to_resource(imem_gcc_node, 0, res)) {
		pr_err("gcc reset resource does not exist\n");
		kfree(res);
		return -EINVAL;
	}

	region->phys_addr = res->start;
	region->size = resource_size(res);
	region->flags = MEM_DESC_PLATFORM;
	strncpy(region->name, "RST_STAT.BIN", MAX_NAME_LEN);
	kfree(res);

	return 0;
#else
	return -EINVAL;
#endif
}

static int get_pmic_pon_region(struct mem_desc *region)
{
	void *pmic_pon = NULL;
	unsigned size;
	unsigned long paddr;

	if (!region)
		return -EINVAL;

	pmic_pon = smem_get_entry(SMEM_POWER_ON_STATUS_INFO, &size, 0,
			SMEM_ANY_HOST_FLAG);
	if (!pmic_pon) {
		pr_err("Failed to get smem entry for PON status\n");
		return -EINVAL;
	}

	paddr = smem_virt_to_phys(pmic_pon);
	if (!paddr) {
		pr_err("Failed to get smem phys address\n");
		return -EINVAL;
	}

	region->phys_addr = paddr;
	region->size = size;
	region->flags = MEM_DESC_PLATFORM;
	strncpy(region->name, "PMIC_PON.BIN", MAX_NAME_LEN);

	return 0;
}

static int __init reset_reason_module_init(void)
{
	struct mem_desc pmic_pon, rst_stat;
	if (!get_hw_config_status())
		return 0;

	if (!ramdump_reset_mem_desc()) {
		if (!get_reset_stat_region(&rst_stat))
			ramdump_add_mem_desc(&rst_stat);

		if (!get_pmic_pon_region(&pmic_pon))
			ramdump_add_mem_desc(&pmic_pon);
	}

	return 0;
}

module_init(reset_reason_module_init)
