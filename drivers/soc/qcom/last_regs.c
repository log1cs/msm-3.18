/* 2016-07-14: File added by Sony Corporation */
/* Copyright (c) 2014, The Linux Foundation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */
#include <linux/slab.h>
#include <linux/io.h>
#include <linux/init.h>
#include <linux/export.h>
#include <linux/err.h>
#include <linux/of.h>
#include <linux/uaccess.h>
#include <linux/of_address.h>
#include <soc/qcom/memory_dump.h>
#include <linux/proc_fs.h>
#include <linux/rdtags.h>
#include <soc/qcom/hwconfig_status.h>

#define MSM_DUMP_TABLE_VERSION		MSM_DUMP_MAKE_VERSION(2, 0)
#define MSM_DUMP_DATA_MAGIC 0x42445953
#define CPU_CTXT_DUMP_SIZE 0x800
#define MAX_CPU 8
#define STRUCT_DUMP_DATA_SZ (MAX_CPU * (sizeof(struct msm_dump_data)))
#define LAST_REGS_BUF_LENGTH (MAX_CPU * CPU_CTXT_DUMP_SIZE) + \
				STRUCT_DUMP_DATA_SZ
#define DUMP_TABLE_OVERWRITTEN

struct msm_dump_table {
	uint32_t version;
	uint32_t num_entries;
	struct msm_dump_entry entries[MAX_NUM_ENTRIES];
};

static char *last_cpuregs;
static uint64_t last_cpuregs_sz;

static ssize_t last_regs_read(struct file *file, char __user *buf,
				size_t len, loff_t *offset)
{
	loff_t pos = *offset;
	ssize_t count;

	if (pos >= last_cpuregs_sz)
		return 0;

	count = min(len, (size_t)(last_cpuregs_sz - pos));
	if (copy_to_user(buf, last_cpuregs + pos, count))
		return -EFAULT;

	*offset += count;
	return count;
}

static const struct file_operations last_regs_fops = {
	.owner = THIS_MODULE,
	.read = last_regs_read,
};

static int dump_cpu_registers(int cpu, uint64_t addr, uint64_t length)
{
	char __iomem *regbuf;

	if (length <= 0 && !addr) {
		pr_info("Dump data length of cpu-% is zero\n", cpu);
		return 0;
	}

	if (length > CPU_CTXT_DUMP_SIZE) {
		pr_info("cpu-%d regs dump corrupted/dump size changed\n", cpu);
		length = CPU_CTXT_DUMP_SIZE;
	}

	regbuf = (char *)ioremap(addr, length);
	if (!regbuf) {
		pr_err("Failed to ioremap regs memory\n");
		return -ENOMEM;
	}

	memcpy_fromio(last_cpuregs + last_cpuregs_sz, regbuf, length);
	last_cpuregs_sz += length;

	iounmap(regbuf);
	return 0;
}

static int cpu_dump_data(struct msm_dump_entry *entry)
{
	struct __iomem msm_dump_data *cpu_data;
	int ret = 0, i, num_cpus_dumped = 0;

	cpu_data = (struct msm_dump_data *)ioremap(entry->addr,
			STRUCT_DUMP_DATA_SZ);
	if (!cpu_data) {
		pr_err("Failed to ioremap cpu%d data\n", entry->id);
		return -ENOMEM;
	}

	memcpy_fromio(last_cpuregs + last_cpuregs_sz, cpu_data,
			STRUCT_DUMP_DATA_SZ);
	last_cpuregs_sz += STRUCT_DUMP_DATA_SZ;
	for (i = 0; i < MAX_CPU; i++) {
		if (cpu_data && (cpu_data->magic == MSM_DUMP_DATA_MAGIC)) {
			ret = dump_cpu_registers(i, cpu_data->addr,
					cpu_data->len);
			num_cpus_dumped++;
		} else {
			memset(last_cpuregs + last_cpuregs_sz, 0x0,
					CPU_CTXT_DUMP_SIZE);
			last_cpuregs_sz += CPU_CTXT_DUMP_SIZE;
		}
		cpu_data++;
	}

	pr_info("%s: Dumped %d cpu context \n", __func__, num_cpus_dumped);
	iounmap(cpu_data);
	return num_cpus_dumped;
}

#ifdef DUMP_TABLE_OVERWRITTEN
static int dump_table_addr_read(unsigned long *dump_table_addr)
{
	const char *name = "dump_table_addr";
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

	ret = kstrtoul(buf, 16, dump_table_addr);
	if (ret != 0)
		pr_err("Failed to convert timerkeeper string %d\n", ret);

exit:
	kfree(buf);

	return ret;
}
#endif

static int __init init_last_regs_dump(void)
{
	unsigned long dump_table_addr = 0, adump_table_addr = 0;
	struct msm_dump_entry entry;
	struct proc_dir_entry *proc_entry;
	struct __iomem msm_dump_table *dump_table = NULL;
	struct __iomem msm_dump_table *apps_dump_table = NULL;
	int i, ret = 0, cpus_dumped = 0;

	if (get_hw_config_status()) {
		pr_info("Skip creating last_regs\n");
		return ret;
	}

#ifndef DUMP_TABLE_OVERWRITTEN
	struct device_node *np;
	void __iomem *imem_base;

	np = of_find_compatible_node(NULL, NULL,
				     "qcom,msm-imem-mem_dump_table");
	if (!np) {
		pr_err("mem dump base table DT node does not exist\n");
		return -ENODEV;
	}

	imem_base = of_iomap(np, 0);
	if (!imem_base) {
		pr_err("mem dump base table imem offset mapping failed\n");
		return -ENOMEM;
	}

	dump_table_addr = readl_relaxed(imem_base);
	iounmap(imem_base);
#else
	ret = dump_table_addr_read(&dump_table_addr);
	if (ret) {
		pr_err("dump table addr read failed\n");
		return -EINVAL;
	}
#endif
	pr_err("msm dump table phy addr %lx\n", dump_table_addr);

	dump_table = (struct msm_dump_table *)ioremap(dump_table_addr,
			sizeof(struct msm_dump_table));
	if (!dump_table) {
		pr_err("Failed to ioremap dump table address\n");
		return -ENOMEM;
	}

	if (dump_table->version == MSM_DUMP_TABLE_VERSION) {
		for (i = 0; i < dump_table->num_entries; i++) {
			memcpy_fromio(&entry, &dump_table->entries[i],
					sizeof(struct msm_dump_entry));
			if (entry.type == MSM_DUMP_TYPE_TABLE) {
				adump_table_addr = entry.addr;
				break;
			}
		}
	}

	iounmap(dump_table);

	if (adump_table_addr == 0) {
		pr_err("Not found msm dump table entry\n");
		return 0;
	}

	last_cpuregs = (char *)__get_free_pages(GFP_KERNEL,
			get_order(LAST_REGS_BUF_LENGTH));
	if (!last_cpuregs) {
		pr_err("Failed to allocate pages of order %d\n",
				get_order(LAST_REGS_BUF_LENGTH));
		return -ENOMEM;
	}

	pr_debug("apps dump table phy addr %lx\n", adump_table_addr);
	apps_dump_table = (struct msm_dump_table *)ioremap(adump_table_addr,
			sizeof(struct msm_dump_table));
	if (!apps_dump_table) {
		pr_err("Failed to ioremap apps dump table address\n");
		ret = -ENOMEM;
		goto free_pages;
	}

	if (apps_dump_table->version == MSM_DUMP_TABLE_VERSION) {
		for (i = 0; i < apps_dump_table->num_entries; i++) {
			memcpy_fromio(&entry, &apps_dump_table->entries[i],
					sizeof(struct msm_dump_entry));
			if (entry.id == MSM_CPU_CTXT) {
				cpus_dumped = cpu_dump_data(&entry);
				if (cpu_dump_data < 0) {
					pr_err("Failed to read cpu%d" \
						"context\n", entry.id);
					continue;
				}

				break;
			}
		}
	}

	if (cpus_dumped) {
		proc_entry = proc_create_data("last_regs",
			S_IFREG | S_IRUGO, NULL, &last_regs_fops, NULL);
		if (!proc_entry) {
			pr_info("failed to create last_kmsg proc entry\n");
			ret = -ENOMEM;
			iounmap(apps_dump_table);
			goto free_pages;
		}
	}

	iounmap(apps_dump_table);
	return 0;

free_pages:
	free_pages((unsigned long)last_cpuregs,
			get_order(LAST_REGS_BUF_LENGTH));
	return ret;
}
late_initcall(init_last_regs_dump);
