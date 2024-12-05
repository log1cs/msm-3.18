/* 2016-11-01: File added by Sony Corporation */
 /*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */
#include <linux/debugfs.h>
#include <linux/errno.h>
#include <linux/delay.h>
#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/of.h>

struct dentry *debugfs_entry;

struct last_log_data {
	int offset;
	void *addr;
	struct dentry *debugfs_file;
};

static void last_log_clean(struct last_log_data *priv_data)
{
	memset(priv_data->addr, 0, priv_data->offset);
}


static ssize_t last_log_read(struct file *file, char __user *buf,
	size_t len, loff_t *offset)
{
	loff_t pos = *offset;
	ssize_t count;
	int last_buf_len;
	char *last_buf;
	struct last_log_data *priv_data = (struct last_log_data *)file->private_data;

	last_buf = priv_data->addr;
	last_buf_len = priv_data->offset;

	if (pos >= last_buf_len) {
		last_log_clean(priv_data);
		return 0;
	}

	count = min(len, (size_t)(last_buf_len - pos));
	if (copy_to_user(buf, last_buf + pos, count))
		return -EFAULT;

	*offset += count;

	return count;
}

static int last_log_open(struct inode *inode, struct file *file)
{
	file->private_data = inode->i_private;
	return 0;
}

static const struct file_operations last_log_fops = {
	.owner = THIS_MODULE,
	.read = last_log_read,
	.open = last_log_open,
};

static int last_log_init_resource(struct platform_device *pdev,
					struct resource *resource)
{

	struct last_log_data *priv_data;
	int debug_resource_size, ret = -1;
	void __iomem *last_virt_iobase;
	void *last_log_addr;

	debug_resource_size = resource->end - resource->start + 1;

	dev_info(&pdev->dev, "log driver initialized %u@%llx\n",
			(unsigned int)debug_resource_size, resource->start);
	/*
	 * Map address that stores the physical location diagnostic data
	 */
	last_virt_iobase = devm_ioremap_nocache(&pdev->dev, resource->start,
				debug_resource_size);
	if (!last_virt_iobase) {
		dev_err(&pdev->dev,
			"%s: ERROR could not ioremap: start=%pr, len=%u\n",
			__func__, &resource->start,
			(unsigned int)(debug_resource_size));
		return -ENXIO;
	}

	last_log_addr = kzalloc(debug_resource_size, GFP_KERNEL);
	if (!last_log_addr) {
		pr_err("ERROR: %s could not allocate memory", __func__);
		iounmap(last_virt_iobase);
		return -ENOMEM;
	}

	memcpy_fromio(last_log_addr, last_virt_iobase, debug_resource_size);
	/* clear & unmap last_log debug memory */
	memset_io(last_virt_iobase, 0, debug_resource_size);
	iounmap(last_virt_iobase);

	priv_data = kzalloc(sizeof(struct last_log_data), GFP_KERNEL);
	if (!priv_data) {
		pr_err("ERROR: %s could not allocate memory", __func__);
		ret = -ENOMEM;
		goto exit;
	}

	priv_data->addr = (struct last_log_data *)last_log_addr;
	priv_data->offset = debug_resource_size;

	if (!debugfs_entry) {
		debugfs_entry = debugfs_create_dir("last_logs", NULL);
		if (!debugfs_entry) {
			dev_err(&pdev->dev,
				"%s: Failed to create debug file dir %s\n",
				__func__, resource->name);
			ret = -EINVAL;
			goto exit;
		}
	}

	if (debugfs_entry) {
		priv_data->debugfs_file = debugfs_create_file(resource->name,
			S_IFREG | S_IRUGO, debugfs_entry, priv_data, &last_log_fops);
		if (!priv_data->debugfs_file) {
			dev_err(&pdev->dev,
				"%s: Failed to create debug file entry %s\n",
				__func__, resource->name);
			ret = -EINVAL;
			goto exit;
		}
	}

	return 0;

exit:
	memset((void *)last_log_addr, 0, debug_resource_size);
	kzfree(last_log_addr);
	kzfree(priv_data);
	return ret;
}

static int last_log_probe(struct platform_device *dev)
{
	int i;

	for (i = 0; i < dev->num_resources; i++) {
		struct resource *r = &dev->resource[i];
		dev_info(&dev->dev, "%s %s\n", __func__, r->name);
		if (!r->name)
			dev_err(&dev->dev, "ERROR: device name is invalid");
		if (last_log_init_resource(dev, r) != 0)
			dev_err(&dev->dev, "ERROR: %s last_log_init", r->name);
	}

	return 0;
}

static struct platform_driver last_log_driver = {
	.probe		= last_log_probe,
	.driver		= {
		.name = "rd_last_log",
		.owner = THIS_MODULE,
	},
};

static int __init last_log_init(void)
{
	return platform_driver_register(&last_log_driver);
}

static void __exit last_log_exit(void)
{
	platform_driver_unregister(&last_log_driver);
}

module_init(last_log_init);
module_exit(last_log_exit);

MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("last_log driver");
MODULE_ALIAS("platform:last_log");
MODULE_AUTHOR("Nandhakumar <nandhakumar.x.rangasamy@sonymobile.com>");
