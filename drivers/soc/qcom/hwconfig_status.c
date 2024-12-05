/* 2017-09-07: File added and changed by Sony Corporation */
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/of_platform.h>
#include <asm/setup.h>

static int hw_config;

static int __init hw_config_setup(char *p)
{
	unsigned long res;

	if (!p || !*p)
		return 0;

	if (!kstrtoul(p, 0 , &res)) {
		if (res & 0x2)
			hw_config = 1;
	}

	pr_info("system booted with HW_CONFIG : %s\n",
		hw_config ? "ON" : "OFF");
	return 0;
}
early_param("oemandroidboot.securityflags", hw_config_setup);

int get_hw_config_status(void)
{
	return hw_config;
}
EXPORT_SYMBOL(get_hw_config_status);
