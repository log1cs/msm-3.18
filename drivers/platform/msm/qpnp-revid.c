/* 2017-02-17: File changed by Sony Corporation */
/* Copyright (c) 2013-2016, The Linux Foundation. All rights reserved.
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

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/spmi.h>
#ifdef CONFIG_AL0_RAMDUMP
#include <linux/rdtags.h>
#endif
#include <linux/err.h>
#include <linux/qpnp/qpnp-revid.h>

#define REVID_REVISION1	0x0
#define REVID_REVISION2	0x1
#define REVID_REVISION3	0x2
#define REVID_REVISION4	0x3
#define REVID_TYPE	0x4
#define REVID_SUBTYPE	0x5
#define REVID_STATUS1	0x8
#define REVID_SPARE_0	0x60

#define QPNP_REVID_DEV_NAME "qcom,qpnp-revid"

static const char *const pmic_names[] = {
	[0] =	"Unknown PMIC",
	[PM8941_SUBTYPE] = "PM8941",
	[PM8841_SUBTYPE] = "PM8841",
	[PM8019_SUBTYPE] = "PM8019",
	[PM8226_SUBTYPE] = "PM8226",
	[PM8110_SUBTYPE] = "PM8110",
	[PMA8084_SUBTYPE] = "PMA8084",
	[PMI8962_SUBTYPE] = "PMI8962",
	[PMD9635_SUBTYPE] = "PMD9635",
	[PM8994_SUBTYPE] = "PM8994",
	[PMI8994_SUBTYPE] = "PMI8994",
	[PM8916_SUBTYPE] = "PM8916",
	[PM8004_SUBTYPE] = "PM8004",
	[PM8909_SUBTYPE] = "PM8909",
	[PM2433_SUBTYPE] = "PM2433",
	[PMD9655_SUBTYPE] = "PMD9655",
	[PM8950_SUBTYPE] = "PM8950",
	[PMI8950_SUBTYPE] = "PMI8950",
	[PMK8001_SUBTYPE] = "PMK8001",
	[PMI8996_SUBTYPE] = "PMI8996",
	[PMCOBALT_SUBTYPE] = "PMCOBALT",
	[PMICOBALT_SUBTYPE] = "PMICOBALT",
	[PM8005_SUBTYPE] = "PM8005",
	[PM8937_SUBTYPE] = "PM8937",
	[PMI8937_SUBTYPE] = "PMI8937",
	[PMI8940_SUBTYPE] = "PMI8940",
};

struct revid_chip {
	struct list_head	link;
	struct device_node	*dev_node;
	struct pmic_revid_data	data;
};

static LIST_HEAD(revid_chips);
static DEFINE_MUTEX(revid_chips_lock);

static struct of_device_id qpnp_revid_match_table[] = {
	{ .compatible = QPNP_REVID_DEV_NAME },
	{}
};

static u8 qpnp_read_byte(struct spmi_device *spmi, u16 addr)
{
	int rc;
	u8 val;

	rc = spmi_ext_register_readl(spmi->ctrl, spmi->sid, addr, &val, 1);
	if (rc) {
		pr_err("SPMI read failed rc=%d\n", rc);
		return 0;
	}
	return val;
}

/**
 * get_revid_data - Return the revision information of PMIC
 * @dev_node: Pointer to the revid peripheral of the PMIC for which
 *		revision information is seeked
 *
 * CONTEXT: Should be called in non atomic context
 *
 * RETURNS: pointer to struct pmic_revid_data filled with the information
 *		about the PMIC revision
 */
struct pmic_revid_data *get_revid_data(struct device_node *dev_node)
{
	struct revid_chip *revid_chip;

	if (!dev_node)
		return ERR_PTR(-EINVAL);

	mutex_lock(&revid_chips_lock);
	list_for_each_entry(revid_chip, &revid_chips, link) {
		if (dev_node == revid_chip->dev_node) {
			mutex_unlock(&revid_chips_lock);
			return &revid_chip->data;
		}
	}
	mutex_unlock(&revid_chips_lock);
	return ERR_PTR(-EINVAL);
}
EXPORT_SYMBOL(get_revid_data);

#define PM8941_PERIPHERAL_SUBTYPE	0x01
#define PM8226_PERIPHERAL_SUBTYPE	0x04
#define PMD9655_PERIPHERAL_SUBTYPE	0x0F
#define PMI8950_PERIPHERAL_SUBTYPE	0x11
#define PMI8937_PERIPHERAL_SUBTYPE	0x37
#define PMI8940_PERIPHERAL_SUBTYPE	0x40
static size_t build_pmic_string(char *buf, size_t n, int sid,
		u8 subtype, u8 rev1, u8 rev2, u8 rev3, u8 rev4)
{
	size_t pos = 0;
#ifdef CONFIG_AL0_RAMDUMP
	char tag_name[64];
	char tag_data[64];
	int version_pos = 1;
#endif

	/*
	 * In early versions of PM8941 and PM8226, the major revision number
	 * started incrementing from 0 (eg 0 = v1.0, 1 = v2.0).
	 * Increment the major revision number here if the chip is an early
	 * version of PM8941 or PM8226.
	 */
	if (((int)subtype == PM8941_PERIPHERAL_SUBTYPE
			|| (int)subtype == PM8226_PERIPHERAL_SUBTYPE)
			&& rev4 < 0x02)
		rev4++;

	pos += snprintf(buf + pos, n - pos, "PMIC@SID%d", sid);
	if (subtype >= ARRAY_SIZE(pmic_names) || subtype == 0) {
		pos += snprintf(buf + pos, n - pos, ": %s (subtype: 0x%02X)",
				pmic_names[0], subtype);
#ifdef CONFIG_AL0_RAMDUMP
		snprintf(tag_name, sizeof(tag_name), "pmic_%s_revision_str",
				pmic_names[0]);
#endif
	} else {
		pos += snprintf(buf + pos, n - pos, ": %s",
				pmic_names[subtype]);
#ifdef CONFIG_AL0_RAMDUMP
		snprintf(tag_name, sizeof(tag_name), "pmic_%s_revision_str",
				pmic_names[subtype]);
#endif
	}

#ifdef CONFIG_AL0_RAMDUMP
	version_pos += strlen(buf);
#endif
	pos += snprintf(buf + pos, n - pos, " v%d.%d", rev4, rev3);
	if (rev2 || rev1)
		pos += snprintf(buf + pos, n - pos, ".%d", rev2);
	if (rev1)
		pos += snprintf(buf + pos, n - pos, ".%d", rev1);

#ifdef CONFIG_AL0_RAMDUMP
	snprintf(tag_data, sizeof(tag_data), "%s", buf + version_pos);
	rdtags_add_tag(tag_name, tag_data, strlen(tag_data));
#endif
	return pos;
}

#ifdef CONFIG_MACH_OPENQ820
static ssize_t pmic_id_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct spmi_device *spmi_dev = to_spmi_device(dev);
	struct pmic_revid_data *pmic_rev_id;

	pmic_rev_id = get_revid_data(spmi_dev->dev.of_node);

	pr_info("pmic_id: %s\n", pmic_rev_id->pmic_name);
	return sprintf(buf, "%s", pmic_rev_id->pmic_name);
}

static DEVICE_ATTR(pmic_id, S_IRUSR|S_IRGRP|S_IROTH, pmic_id_show, NULL);

static struct attribute *pmic_id_attributes[] = {
	&dev_attr_pmic_id.attr,
	NULL
};

static const struct attribute_group pmic_id_group = {
	.attrs		= pmic_id_attributes,
};

static int num_pmic = 0;
#endif

#define PMIC_PERIPHERAL_TYPE		0x51
#define PMIC_STRING_MAXLENGTH		80
static int qpnp_revid_probe(struct spmi_device *spmi)
{
	u8 rev1, rev2, rev3, rev4, pmic_type, pmic_subtype, pmic_status;
	u8 option1, option2, option3, option4, spare0;
	struct resource *resource;
	char pmic_string[PMIC_STRING_MAXLENGTH] = {'\0'};
	struct revid_chip *revid_chip;
#ifdef CONFIG_MACH_OPENQ820
	int err;
	char link_name[18];
#endif

	resource = spmi_get_resource(spmi, NULL, IORESOURCE_MEM, 0);
	if (!resource) {
		pr_err("Unable to get spmi resource for REVID\n");
		return -EINVAL;
	}
	pmic_type = qpnp_read_byte(spmi, resource->start + REVID_TYPE);
	if (pmic_type != PMIC_PERIPHERAL_TYPE) {
		pr_err("Invalid REVID peripheral type: %02X\n", pmic_type);
		return -EINVAL;
	}

	rev1 = qpnp_read_byte(spmi, resource->start + REVID_REVISION1);
	rev2 = qpnp_read_byte(spmi, resource->start + REVID_REVISION2);
	rev3 = qpnp_read_byte(spmi, resource->start + REVID_REVISION3);
	rev4 = qpnp_read_byte(spmi, resource->start + REVID_REVISION4);

	pmic_subtype = qpnp_read_byte(spmi, resource->start + REVID_SUBTYPE);
	if (pmic_subtype != PMD9655_PERIPHERAL_SUBTYPE)
		pmic_status = qpnp_read_byte(spmi,
					     resource->start + REVID_STATUS1);
	else
		pmic_status = 0;

	/* special case for PMI8937/PMI8940 */
	if (pmic_subtype == PMI8950_PERIPHERAL_SUBTYPE) {
		/* read spare register */
		spare0 = qpnp_read_byte(spmi, resource->start + REVID_SPARE_0);
		switch (spare0) {
		case 0:
			pmic_subtype = PMI8950_PERIPHERAL_SUBTYPE;
			break;
		case PMI8937_PERIPHERAL_SUBTYPE:
			pmic_subtype = PMI8937_PERIPHERAL_SUBTYPE;
			break;
		case PMI8940_PERIPHERAL_SUBTYPE:
			pmic_subtype = PMI8940_PERIPHERAL_SUBTYPE;
			break;
		default:
			pr_warn("Invalid spare0 value=%x\n", spare0);
		}
	}

	revid_chip = devm_kzalloc(&spmi->dev, sizeof(struct revid_chip),
						GFP_KERNEL);
	if (!revid_chip)
		return -ENOMEM;

	revid_chip->dev_node = spmi->dev.of_node;
	revid_chip->data.rev1 = rev1;
	revid_chip->data.rev2 = rev2;
	revid_chip->data.rev3 = rev3;
	revid_chip->data.rev4 = rev4;
	revid_chip->data.pmic_subtype = pmic_subtype;
	revid_chip->data.pmic_type = pmic_type;

	if (pmic_subtype < ARRAY_SIZE(pmic_names))
		revid_chip->data.pmic_name = pmic_names[pmic_subtype];
	else
		revid_chip->data.pmic_name = pmic_names[0];

	mutex_lock(&revid_chips_lock);
	list_add(&revid_chip->link, &revid_chips);
	mutex_unlock(&revid_chips_lock);

	option1 = pmic_status & 0x3;
	option2 = (pmic_status >> 2) & 0x3;
	option3 = (pmic_status >> 4) & 0x3;
	option4 = (pmic_status >> 6) & 0x3;

	build_pmic_string(pmic_string, PMIC_STRING_MAXLENGTH, spmi->sid,
			pmic_subtype, rev1, rev2, rev3, rev4);
	pr_info("%s options: %d, %d, %d, %d\n",
			pmic_string, option1, option2, option3, option4);

#ifdef CONFIG_MACH_OPENQ820
	err = sysfs_create_group(&spmi->dev.kobj, &pmic_id_group);
	if (err){
		pr_err("%s: sysfs entry creation failed.\n", __func__);
		return err;
	}
	/* create consistent device link */
	sprintf(link_name, "%s.%d", QPNP_REVID_DEV_NAME, num_pmic++);
	err = sysfs_create_link(&spmi->dev.parent->kobj, &spmi->dev.kobj, link_name);
	if (err){
		pr_err("%s: sysfs link creation failed.\n", __func__);
		return err;
	}
#endif

	return 0;
}

static struct spmi_driver qpnp_revid_driver = {
	.probe	= qpnp_revid_probe,
	.driver	= {
		.name		= QPNP_REVID_DEV_NAME,
		.owner		= THIS_MODULE,
		.of_match_table	= qpnp_revid_match_table,
	},
};

static int __init qpnp_revid_init(void)
{
	return spmi_driver_register(&qpnp_revid_driver);
}

static void __exit qpnp_revid_exit(void)
{
	return spmi_driver_unregister(&qpnp_revid_driver);
}

subsys_initcall(qpnp_revid_init);
module_exit(qpnp_revid_exit);

MODULE_DESCRIPTION("QPNP REVID DRIVER");
MODULE_LICENSE("GPL v2");
MODULE_ALIAS("platform:" QPNP_REVID_DEV_NAME);
