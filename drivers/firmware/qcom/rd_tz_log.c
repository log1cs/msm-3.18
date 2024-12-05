/* 2017-10-12: File added and changed by Sony Corporation */
/* Copyright (c) 2011-2017, The Linux Foundation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */
#include <linux/debugfs.h>
#include <linux/errno.h>
#include <linux/delay.h>
#include <linux/io.h>
#include <linux/msm_ion.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/proc_fs.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/of.h>

#include <soc/qcom/scm.h>
#include <soc/qcom/qseecomi.h>
#include <soc/qcom/hwconfig_status.h>

/* QSEE_LOG_BUF_SIZE = 32K */
#define QSEE_LOG_BUF_SIZE 0x8000

#define TZBSP_DIAG_MAGIC 0x747a6461

/* TZ Diagnostic Area legacy version number */
#define TZBSP_DIAG_MAJOR_VERSION_LEGACY	2
/*
 * Preprocessor Definitions and Constants
 */
#define TZBSP_MAX_CPU_COUNT 0x08
/*
 * Number of VMID Tables
 */
#define TZBSP_DIAG_NUM_OF_VMID 16
/*
 * VMID Description length
 */
#define TZBSP_DIAG_VMID_DESC_LEN 7
/*
 * Number of Interrupts
 */
#define TZBSP_DIAG_INT_NUM  32
/*
 * Length of descriptive name associated with Interrupt
 */
#define TZBSP_MAX_INT_DESC 16
/*
 * TZ 3.X version info
 */
#define QSEE_VERSION_TZ_3_X 0x800000
/*
 * VMID Table
 */
struct tzdbg_vmid_t {
	uint8_t vmid; /* Virtual Machine Identifier */
	uint8_t desc[TZBSP_DIAG_VMID_DESC_LEN];	/* ASCII Text */
};
/*
 * Boot Info Table
 */
struct tzdbg_boot_info_t {
	uint32_t wb_entry_cnt;	/* Warmboot entry CPU Counter */
	uint32_t wb_exit_cnt;	/* Warmboot exit CPU Counter */
	uint32_t pc_entry_cnt;	/* Power Collapse entry CPU Counter */
	uint32_t pc_exit_cnt;	/* Power Collapse exit CPU counter */
	uint32_t warm_jmp_addr;	/* Last Warmboot Jump Address */
	uint32_t spare;	/* Reserved for future use. */
};
/*
 * Boot Info Table for 64-bit
 */
struct tzdbg_boot_info64_t {
	uint32_t wb_entry_cnt;  /* Warmboot entry CPU Counter */
	uint32_t wb_exit_cnt;   /* Warmboot exit CPU Counter */
	uint32_t pc_entry_cnt;  /* Power Collapse entry CPU Counter */
	uint32_t pc_exit_cnt;   /* Power Collapse exit CPU counter */
	uint32_t psci_entry_cnt;/* PSCI syscall entry CPU Counter */
	uint32_t psci_exit_cnt;   /* PSCI syscall exit CPU Counter */
	uint64_t warm_jmp_addr; /* Last Warmboot Jump Address */
	uint32_t warm_jmp_instr; /* Last Warmboot Jump Address Instruction */
};
/*
 * Reset Info Table
 */
struct tzdbg_reset_info_t {
	uint32_t reset_type;	/* Reset Reason */
	uint32_t reset_cnt;	/* Number of resets occured/CPU */
};
/*
 * Interrupt Info Table
 */
struct tzdbg_int_t {
	/*
	 * Type of Interrupt/exception
	 */
	uint16_t int_info;
	/*
	 * Availability of the slot
	 */
	uint8_t avail;
	/*
	 * Reserved for future use
	 */
	uint8_t spare;
	/*
	 * Interrupt # for IRQ and FIQ
	 */
	uint32_t int_num;
	/*
	 * ASCII text describing type of interrupt e.g:
	 * Secure Timer, EBI XPU. This string is always null terminated,
	 * supporting at most TZBSP_MAX_INT_DESC characters.
	 * Any additional characters are truncated.
	 */
	uint8_t int_desc[TZBSP_MAX_INT_DESC];
	uint32_t int_count[TZBSP_MAX_CPU_COUNT]; /* # of times seen per CPU */
};

/*
 * Log ring buffer position
 */
struct tzdbg_log_pos_t {
	uint16_t wrap;
	uint16_t offset;
};

 /*
 * Log ring buffer
 */
struct tzdbg_log_t {
	struct tzdbg_log_pos_t	log_pos;
	/* open ended array to the end of the 4K IMEM buffer */
	uint8_t					log_buf[];
};

/*
 * Diagnostic Table
 * Note: This is the reference data structure for tz diagnostic table
 * supporting TZBSP_MAX_CPU_COUNT, the real diagnostic data is directly
 * copied into buffer from i/o memory.
 */
struct tzdbg_t {
	uint32_t magic_num;
	uint32_t version;
	/*
	 * Number of CPU's
	 */
	uint32_t cpu_count;
	/*
	 * Offset of VMID Table
	 */
	uint32_t vmid_info_off;
	/*
	 * Offset of Boot Table
	 */
	uint32_t boot_info_off;
	/*
	 * Offset of Reset info Table
	 */
	uint32_t reset_info_off;
	/*
	 * Offset of Interrupt info Table
	 */
	uint32_t int_info_off;
	/*
	 * Ring Buffer Offset
	 */
	uint32_t ring_off;
	/*
	 * Ring Buffer Length
	 */
	uint32_t ring_len;
	/*
	 * VMID to EE Mapping
	 */
	struct tzdbg_vmid_t vmid_info[TZBSP_DIAG_NUM_OF_VMID];
	/*
	 * Boot Info
	 */
	struct tzdbg_boot_info_t  boot_info[TZBSP_MAX_CPU_COUNT];
	/*
	 * Reset Info
	 */
	struct tzdbg_reset_info_t reset_info[TZBSP_MAX_CPU_COUNT];
	uint32_t num_interrupts;
	struct tzdbg_int_t  int_info[TZBSP_DIAG_INT_NUM];
	/*
	 * We need at least 2K for the ring buffer
	 */
	struct tzdbg_log_t ring_buffer;	/* TZ Ring Buffer */
};

/*
 * Enumeration order for VMID's
 */
enum tzdbg_stats_type {
	TZDBG_BOOT = 0,
	TZDBG_RESET,
	TZDBG_INTERRUPT,
	TZDBG_VMID,
	TZDBG_GENERAL,
	TZDBG_LOG,
	TZDBG_STATS_MAX
};

struct tzdbg_stat {
	char *name;
	char *data;
};

struct tzdbg {
	void __iomem *virt_iobase;
	struct tzdbg_t *diag_buf;
	char *disp_buf;
	char *merge_buf;
	uint32_t merge_buf_len;
	uint32_t max_merge_buf_len;
	int debug_tz[TZDBG_STATS_MAX];
	struct tzdbg_stat stat[TZDBG_STATS_MAX];
	int (*disp_stat[TZDBG_STATS_MAX])(void);
};

static uint32_t debug_rw_buf_size;
static uint32_t debug_resource_size;
static struct tzdbg_log_t *g_qsee_log;

static struct tzdbg tzdbg = {
	.stat[TZDBG_BOOT].name = "boot",
	.stat[TZDBG_RESET].name = "reset",
	.stat[TZDBG_INTERRUPT].name = "interrupt",
	.stat[TZDBG_VMID].name = "vmid",
	.stat[TZDBG_GENERAL].name = "general",
	.stat[TZDBG_LOG].name = "log",
};

/*
 * Debugfs data structure and functions
 */

static int _disp_tz_general_stats(void)
{
	int len = 0;

	len += snprintf(tzdbg.disp_buf + len, debug_rw_buf_size - 1,
			"   Version        : 0x%x\n"
			"   Magic Number   : 0x%x\n"
			"   Number of CPU  : %d\n",
			tzdbg.diag_buf->version,
			tzdbg.diag_buf->magic_num,
			tzdbg.diag_buf->cpu_count);
	tzdbg.stat[TZDBG_GENERAL].data = tzdbg.disp_buf;
	return len;
}

static int _disp_tz_vmid_stats(void)
{
	int i, num_vmid;
	int len = 0;
	struct tzdbg_vmid_t *ptr;

	ptr = (struct tzdbg_vmid_t *)((unsigned char *)tzdbg.diag_buf +
					tzdbg.diag_buf->vmid_info_off);
	num_vmid = ((tzdbg.diag_buf->boot_info_off -
				tzdbg.diag_buf->vmid_info_off)/
					(sizeof(struct tzdbg_vmid_t)));

	for (i = 0; i < num_vmid; i++) {
		if (ptr->vmid < 0xFF) {
			len += snprintf(tzdbg.disp_buf + len,
				(debug_rw_buf_size - 1) - len,
				"   0x%x        %s\n",
				(uint32_t)ptr->vmid, (uint8_t *)ptr->desc);
		}
		if (len > (debug_rw_buf_size - 1)) {
			pr_warn("%s: Cannot fit all info into the buffer\n",
								__func__);
			break;
		}
		ptr++;
	}

	tzdbg.stat[TZDBG_VMID].data = tzdbg.disp_buf;
	return len;
}

static int _disp_tz_boot_stats(void)
{
	int i;
	int len = 0;
	struct tzdbg_boot_info_t *ptr = NULL;
	struct tzdbg_boot_info64_t *ptr_64 = NULL;
	int ret = 0;
	uint32_t smc_id = 0;
	uint32_t feature = 10;
	struct qseecom_command_scm_resp resp = {};
	struct scm_desc desc = {0};

	if (!is_scm_armv8()) {
		ret = scm_call(SCM_SVC_INFO, SCM_SVC_UTIL,  &feature,
					sizeof(feature), &resp, sizeof(resp));
	} else {
		smc_id = TZ_INFO_GET_FEATURE_VERSION_ID;
		desc.arginfo = TZ_INFO_GET_FEATURE_VERSION_ID_PARAM_ID;
		desc.args[0] = feature;
		ret = scm_call2(smc_id, &desc);
		resp.result = desc.ret[0];
	}

	if (ret) {
		pr_err("%s: scm_call to register log buffer failed\n",
				__func__);
		return 0;
	}
	pr_info("qsee_version = 0x%x\n", resp.result);

	if (resp.result >= QSEE_VERSION_TZ_3_X) {
		ptr_64 = (struct tzdbg_boot_info64_t *)((unsigned char *)
			tzdbg.diag_buf + tzdbg.diag_buf->boot_info_off);
	} else {
		ptr = (struct tzdbg_boot_info_t *)((unsigned char *)
			tzdbg.diag_buf + tzdbg.diag_buf->boot_info_off);
	}

	for (i = 0; i < tzdbg.diag_buf->cpu_count; i++) {
		if (resp.result >= QSEE_VERSION_TZ_3_X) {
			len += snprintf(tzdbg.disp_buf + len,
					(debug_rw_buf_size - 1) - len,
					"  CPU #: %d\n"
					"     Warmboot jump address : 0x%llx\n"
					"     Warmboot entry CPU counter : 0x%x\n"
					"     Warmboot exit CPU counter : 0x%x\n"
					"     Power Collapse entry CPU counter : 0x%x\n"
					"     Power Collapse exit CPU counter : 0x%x\n"
					"     Psci entry CPU counter : 0x%x\n"
					"     Psci exit CPU counter : 0x%x\n"
					"     Warmboot Jump Address Instruction : 0x%x\n",
					i, (uint64_t)ptr_64->warm_jmp_addr,
					ptr_64->wb_entry_cnt,
					ptr_64->wb_exit_cnt,
					ptr_64->pc_entry_cnt,
					ptr_64->pc_exit_cnt,
					ptr_64->psci_entry_cnt,
					ptr_64->psci_exit_cnt,
					ptr_64->warm_jmp_instr);

			if (len > (debug_rw_buf_size - 1)) {
				pr_warn("%s: Cannot fit all info into the buffer\n",
						__func__);
				break;
			}
			ptr_64++;
		} else {
			len += snprintf(tzdbg.disp_buf + len,
					(debug_rw_buf_size - 1) - len,
					"  CPU #: %d\n"
					"     Warmboot jump address     : 0x%x\n"
					"     Warmboot entry CPU counter: 0x%x\n"
					"     Warmboot exit CPU counter : 0x%x\n"
					"     Power Collapse entry CPU counter: 0x%x\n"
					"     Power Collapse exit CPU counter : 0x%x\n",
					i, ptr->warm_jmp_addr,
					ptr->wb_entry_cnt,
					ptr->wb_exit_cnt,
					ptr->pc_entry_cnt,
					ptr->pc_exit_cnt);

			if (len > (debug_rw_buf_size - 1)) {
				pr_warn("%s: Cannot fit all info into the buffer\n",
						__func__);
				break;
			}
			ptr++;
		}
	}
	tzdbg.stat[TZDBG_BOOT].data = tzdbg.disp_buf;
	return len;
}

static int _disp_tz_reset_stats(void)
{
	int i;
	int len = 0;
	struct tzdbg_reset_info_t *ptr;

	ptr = (struct tzdbg_reset_info_t *)((unsigned char *)tzdbg.diag_buf +
					tzdbg.diag_buf->reset_info_off);

	for (i = 0; i < tzdbg.diag_buf->cpu_count; i++) {
		len += snprintf(tzdbg.disp_buf + len,
				(debug_rw_buf_size - 1) - len,
				"  CPU #: %d\n"
				"     Reset Type (reason)       : 0x%x\n"
				"     Reset counter             : 0x%x\n",
				i, ptr->reset_type, ptr->reset_cnt);

		if (len > (debug_rw_buf_size - 1)) {
			pr_warn("%s: Cannot fit all info into the buffer\n",
								__func__);
			break;
		}

		ptr++;
	}
	tzdbg.stat[TZDBG_RESET].data = tzdbg.disp_buf;
	return len;
}

static int _disp_tz_interrupt_stats(void)
{
	int i, j, int_info_size;
	int len = 0;
	int *num_int;
	unsigned char *ptr;
	struct tzdbg_int_t *tzdbg_ptr;

	num_int = (uint32_t *)((unsigned char *)tzdbg.diag_buf +
			(tzdbg.diag_buf->int_info_off - sizeof(uint32_t)));
	ptr = ((unsigned char *)tzdbg.diag_buf +
					tzdbg.diag_buf->int_info_off);
	int_info_size = ((tzdbg.diag_buf->ring_off -
				tzdbg.diag_buf->int_info_off)/(*num_int));

	for (i = 0; i < (*num_int); i++) {
		tzdbg_ptr = (struct tzdbg_int_t *)ptr;
		len += snprintf(tzdbg.disp_buf + len,
				(debug_rw_buf_size - 1) - len,
				"     Interrupt Number          : 0x%x\n"
				"     Type of Interrupt         : 0x%x\n"
				"     Description of interrupt  : %s\n",
				tzdbg_ptr->int_num,
				(uint32_t)tzdbg_ptr->int_info,
				(uint8_t *)tzdbg_ptr->int_desc);
		for (j = 0; j < tzdbg.diag_buf->cpu_count; j++) {
			len += snprintf(tzdbg.disp_buf + len,
				(debug_rw_buf_size - 1) - len,
				"     int_count on CPU # %d      : %u\n",
				(uint32_t)j,
				(uint32_t)tzdbg_ptr->int_count[j]);
		}
		len += snprintf(tzdbg.disp_buf + len, debug_rw_buf_size - 1,
									"\n");

		if (len > (debug_rw_buf_size - 1)) {
			pr_warn("%s: Cannot fit all info into the buffer\n",
								__func__);
			break;
		}

		ptr += int_info_size;
	}
	tzdbg.stat[TZDBG_INTERRUPT].data = tzdbg.disp_buf;
	return len;
}

static int _disp_tz_log_stats_legacy(void)
{
	int len = 0;
	unsigned char *ptr;

	ptr = (unsigned char *)tzdbg.diag_buf +
					tzdbg.diag_buf->ring_off;
	len += snprintf(tzdbg.disp_buf, (debug_rw_buf_size - 1) - len,
							"%s\n", ptr);
	tzdbg.stat[TZDBG_LOG].data = tzdbg.disp_buf;
	return len;
}

static int _disp_log_stats(struct tzdbg_log_t *log,
			struct tzdbg_log_pos_t *log_start, uint32_t log_len,
			size_t count, uint32_t buf_idx)
{
	uint32_t wrap_start;
	uint32_t wrap_end;
	uint32_t wrap_cnt;
	int max_len;
	int len = 0;
	int i = 0;

	wrap_start = log_start->wrap;
	wrap_end = log->log_pos.wrap;

	/* Calculate difference in # of buffer wrap-arounds */
	if (wrap_end >= wrap_start) {
		wrap_cnt = wrap_end - wrap_start;
	} else {
		/* wrap counter has wrapped around, invalidate start position */
		wrap_cnt = 2;
	}

	if (wrap_cnt > 1) {
		/* end position has wrapped around more than once, */
		/* current start no longer valid                   */
		log_start->wrap = log->log_pos.wrap - 1;
		log_start->offset = (log->log_pos.offset + 1) % log_len;
	} else if ((wrap_cnt == 1) &&
		(log->log_pos.offset > log_start->offset)) {
		/* end position has overwritten start */
		log_start->offset = (log->log_pos.offset + 1) % log_len;
	}

	max_len = (count > debug_rw_buf_size) ? debug_rw_buf_size : count;

	/*
	 *  Read from ring buff while there is data and space in return buff
	 */
	while ((log_start->offset != log->log_pos.offset) && (len < max_len)) {
		tzdbg.disp_buf[i++] = log->log_buf[log_start->offset];
		log_start->offset = (log_start->offset + 1) % log_len;
		if (0 == log_start->offset)
			++log_start->wrap;
		++len;
	}

	/*
	 * return buffer to caller
	 */
	tzdbg.stat[buf_idx].data = tzdbg.disp_buf;
	return len;
}

static int _disp_tz_log_stats(void)
{
	static struct tzdbg_log_pos_t log_start = {0};
	struct tzdbg_log_t *log_ptr;
	size_t count = debug_rw_buf_size;

	log_ptr = (struct tzdbg_log_t *)((unsigned char *)tzdbg.diag_buf +
				tzdbg.diag_buf->ring_off -
				offsetof(struct tzdbg_log_t, log_buf));

	return _disp_log_stats(log_ptr, &log_start,
				tzdbg.diag_buf->ring_len, count, TZDBG_LOG);
}


#define MAX_BANNER_LEN 1024
static int merge_buffers(void)
{
	int data_len = 0, len = 0, i;

	for (i = 0; i < TZDBG_STATS_MAX; i++) {
		if ((get_hw_config_status() == 1) && (i == TZDBG_LOG))
			continue;

		if ((len + MAX_BANNER_LEN + debug_rw_buf_size) <
				tzdbg.max_merge_buf_len) {
			len += snprintf(tzdbg.merge_buf + len,
				MAX_BANNER_LEN, "\n\n--------%s--------\n\n",
				tzdbg.stat[i].name);
			data_len = tzdbg.disp_stat[i]();
			memcpy(tzdbg.merge_buf + len, tzdbg.stat[(i)].data,
						data_len);
			len += data_len;
			memset(tzdbg.disp_buf, 0x0, debug_rw_buf_size);
		}
	}

	tzdbg.merge_buf_len = len;
	pr_info("Length of merged buffers %d\n", len);
	return 0;
}

static ssize_t tzbsp_log_read(struct file *file, char __user *buf,
	size_t len, loff_t *offset)
{
	loff_t pos = *offset;
	ssize_t count;

	if (pos >= tzdbg.merge_buf_len)
		return 0;

	count = min(len, (size_t)(tzdbg.merge_buf_len - pos));
	if (copy_to_user(buf, tzdbg.merge_buf + pos, count))
		return -EFAULT;

	*offset += count;
	return count;
}

static const struct file_operations tzbsp_log_fops = {
	.owner = THIS_MODULE,
	.read = tzbsp_log_read,
};

static int  tzdbgfs_init(struct platform_device *pdev)
{
	struct proc_dir_entry *entry;

	entry = proc_create_data("tzbsp_log",
		S_IFREG | S_IRUGO, NULL, &tzbsp_log_fops, NULL);
	if (!entry) {
		dev_err(&pdev->dev, "Failed to create proc entry tzbsp_log\n");
		return -ENOMEM;
	}

	tzdbg.disp_buf = kzalloc(debug_rw_buf_size, GFP_KERNEL);
	if (tzdbg.disp_buf == NULL) {
		pr_err("%s: Can't Allocate memory for tzdbg.disp_buf\n",
			__func__);
		remove_proc_entry("tzbsp_log", NULL);
		return -EINVAL;
	}

	return 0;
}

static void tzdbgfs_exit(struct platform_device *pdev)
{
	kzfree(tzdbg.disp_buf);
}


static struct ion_client  *g_ion_clnt;
static struct ion_handle *g_ihandle;

/*
 * Allocates log buffer from ION, registers the buffer at TZ
 */
static void tzdbg_register_qsee_log_buf(void)
{
	/* register log buffer scm request */
	struct qseecom_reg_log_buf_ireq req;

	/* scm response */
	struct qseecom_command_scm_resp resp = {};
	ion_phys_addr_t pa = 0;
	size_t len;
	int ret = 0;

	/* Create ION msm client */
	g_ion_clnt = msm_ion_client_create("qsee_log");
	if (g_ion_clnt == NULL) {
		pr_err("%s: Ion client cannot be created\n", __func__);
		return;
	}

	g_ihandle = ion_alloc(g_ion_clnt, QSEE_LOG_BUF_SIZE,
			4096, ION_HEAP(ION_QSECOM_HEAP_ID), 0);
	if (IS_ERR_OR_NULL(g_ihandle)) {
		pr_err("%s: Ion client could not retrieve the handle\n",
			__func__);
		goto err1;
	}

	ret = ion_phys(g_ion_clnt, g_ihandle, &pa, &len);
	if (ret) {
		pr_err("%s: Ion conversion to physical address failed\n",
			__func__);
		goto err2;
	}

	req.qsee_cmd_id = QSEOS_REGISTER_LOG_BUF_COMMAND;
	req.phy_addr = (uint32_t)pa;
	req.len = len;

	if (!is_scm_armv8()) {
		/*  SCM_CALL  to register the log buffer */
		ret = scm_call(SCM_SVC_TZSCHEDULER, 1,  &req, sizeof(req),
			&resp, sizeof(resp));
	} else {
		struct scm_desc desc = {0};
		desc.args[0] = pa;
		desc.args[1] = len;
		desc.arginfo = 0x22;
		ret = scm_call2(SCM_QSEEOS_FNID(1, 6), &desc);
		resp.result = desc.ret[0];
	}

	if (ret) {
		pr_err("%s: scm_call to register log buffer failed\n",
			__func__);
		goto err2;
	}

	if (resp.result != QSEOS_RESULT_SUCCESS) {
		pr_err(
		"%s: scm_call to register log buf failed, resp result =%d\n",
		__func__, resp.result);
		goto err2;
	}

	g_qsee_log =
		(struct tzdbg_log_t *)ion_map_kernel(g_ion_clnt, g_ihandle);

	if (IS_ERR(g_qsee_log)) {
		pr_err("%s: Couldn't map ion buffer to kernel\n",
			__func__);
		goto err2;
	}

	g_qsee_log->log_pos.wrap = g_qsee_log->log_pos.offset = 0;
	return;

err2:
	ion_free(g_ion_clnt, g_ihandle);
	g_ihandle = NULL;
err1:
	ion_client_destroy(g_ion_clnt);
	g_ion_clnt = NULL;
}

/*
 * Driver functions
 */
static int tz_log_probe(struct platform_device *pdev)
{
	struct resource *resource;
	uint32_t *ptr = NULL;
	uint32_t *magic = NULL;

	/*
	 * Get address that stores the physical location diagnostic data
	 */
	resource = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (!resource) {
		dev_err(&pdev->dev,
				"%s: ERROR Missing MEM resource\n", __func__);
		return -ENXIO;
	};

	/*
	 * Get the debug buffer size
	 */
	debug_resource_size = resource->end - resource->start + 1;
	dev_info(&pdev->dev, "Tzbsp log driver initialized %u@%llx\n",
			(unsigned int)debug_resource_size, resource->start);
	/*
	 * Map address that stores the physical location diagnostic data
	 */
	tzdbg.virt_iobase = devm_ioremap_nocache(&pdev->dev, resource->start,
				debug_resource_size);
	if (!tzdbg.virt_iobase) {
		dev_err(&pdev->dev,
			"%s: ERROR could not ioremap: start=%pr, len=%u\n",
			__func__, &resource->start,
			(unsigned int)(debug_resource_size));
		return -ENXIO;
	}

	/*validate tzdiag area w.r.t magic*/
	magic = tzdbg.virt_iobase;
	if (*magic != TZBSP_DIAG_MAGIC) {
		pr_err("No magic found in tzbsp diag area\n");
		return -ENXIO;
	}

	/* Debug buffer increased to 24k size */
	debug_rw_buf_size = debug_resource_size * 3;

	ptr = kzalloc(debug_rw_buf_size, GFP_KERNEL);
	if (ptr == NULL) {
		pr_err("%s: Can't Allocate memory: ptr\n",
			__func__);
		return -ENXIO;
	}

	tzdbg.diag_buf = (struct tzdbg_t *)ptr;

	if (tzdbgfs_init(pdev))
		goto err;

	tzdbg.max_merge_buf_len = debug_rw_buf_size * (TZDBG_STATS_MAX + 1);
	tzdbg.merge_buf = kzalloc(tzdbg.max_merge_buf_len, GFP_KERNEL);
	if (tzdbg.merge_buf == NULL) {
		pr_err("%s: Can't Allocate memory: merged_buf\n",
			__func__);
		goto err;
	}
	tzdbg.disp_stat[TZDBG_BOOT] = _disp_tz_boot_stats;
	tzdbg.disp_stat[TZDBG_RESET] = _disp_tz_reset_stats;
	tzdbg.disp_stat[TZDBG_INTERRUPT] = _disp_tz_interrupt_stats;
	tzdbg.disp_stat[TZDBG_VMID] = _disp_tz_vmid_stats;
	tzdbg.disp_stat[TZDBG_GENERAL] = _disp_tz_general_stats;

	memcpy_fromio((void *)tzdbg.diag_buf, tzdbg.virt_iobase,
						debug_resource_size);
	if (get_hw_config_status() == 0) {
		if (TZBSP_DIAG_MAJOR_VERSION_LEGACY
				< (tzdbg.diag_buf->version >> 16))
			tzdbg.disp_stat[TZDBG_LOG] = _disp_tz_log_stats;
		else
			tzdbg.disp_stat[TZDBG_LOG] = _disp_tz_log_stats_legacy;
	}

	merge_buffers();
	tzdbg_register_qsee_log_buf();
	pr_info("probe of tzbsp log done\n");

	return 0;
err:
	kfree(tzdbg.diag_buf);
	return -ENXIO;
}


static int tz_log_remove(struct platform_device *pdev)
{
	kzfree(tzdbg.diag_buf);
	tzdbgfs_exit(pdev);

	return 0;
}

static struct platform_driver tz_log_driver = {
	.probe		= tz_log_probe,
	.remove		= tz_log_remove,
	.driver		= {
		.name = "rd_tzbsp_log",
		.owner = THIS_MODULE,
		.probe_type = PROBE_PREFER_ASYNCHRONOUS,
	},
};

static int __init tz_log_init(void)
{
	return platform_driver_register(&tz_log_driver);
}

static void __exit tz_log_exit(void)
{
	platform_driver_unregister(&tz_log_driver);
}

module_init(tz_log_init);
module_exit(tz_log_exit);

MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("TZ Log driver");
MODULE_ALIAS("platform:tz_log");
