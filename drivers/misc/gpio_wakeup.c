/* 2017-04-11: File added and changed by Sony Corporation */
/*
 *  This module is wakeup control driver via GPIO port.
 *
 *  Copyright 2017 Sony Corporation
 *
 *  This program is free software; you can redistribute  it and/or modify it
 *  under  the terms of  the GNU General  Public License as published by the
 *  Free Software Foundation;  version 2 of the  License.
 *
 *  THIS  SOFTWARE  IS PROVIDED   ``AS  IS'' AND   ANY  EXPRESS OR IMPLIED
 *  WARRANTIES,   INCLUDING, BUT NOT  LIMITED  TO, THE IMPLIED WARRANTIES OF
 *  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN
 *  NO  EVENT  SHALL   THE AUTHOR  BE    LIABLE FOR ANY   DIRECT, INDIRECT,
 *  INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 *  NOT LIMITED   TO, PROCUREMENT OF  SUBSTITUTE GOODS  OR SERVICES; LOSS OF
 *  USE, DATA,  OR PROFITS; OR  BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 *  ANY THEORY OF LIABILITY, WHETHER IN  CONTRACT, STRICT LIABILITY, OR TORT
 *  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 *  THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *  You should have received a copy of the  GNU General Public License along
 *  with this program; if not, write  to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Suite 500, Boston, MA 02110-1335, USA.
 */

#include <linux/module.h>
#include <linux/irq.h>
#include <linux/interrupt.h>
#include <linux/gpio.h>
#include <linux/platform_device.h>

#define MODULE_NAME "gpio_wakeup"
#define IRQ_HANDLER_NAME "gpio_wakeup_hdl"
#define MAX_GPIO_NUM (20)

uint32_t irq_gpios[MAX_GPIO_NUM] = {0};
int numirq = 0;
struct device virtdev;
static int enable = 1;

static ssize_t gpio_wakeup_enable_show(struct device *dev,
                                       struct device_attribute *attr, char *buf)
{
	return scnprintf(buf, PAGE_SIZE, "%d\n", enable);
}

static ssize_t gpio_wakeup_enable_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	int mode, ret;

	ret = kstrtoint(buf, 10, &mode);
	if (ret < 0) {
		pr_err("%s: Error, buf = %s\n", __func__, buf);
		return ret;
	}

	enable = mode;
	pr_info("gpio_wakeup: %d\n", enable);
	return count;
}

static struct device_attribute gpio_wakeup_attributes[] = {
	__ATTR(enable,  S_IRUGO|S_IWUSR|S_IWGRP, gpio_wakeup_enable_show, gpio_wakeup_enable_store),
};

static void unregister_attributes(struct device *dev)
{
	int i;

	for (i = ARRAY_SIZE(gpio_wakeup_attributes); i > 0; i--)
		device_remove_file(dev, gpio_wakeup_attributes + i);
}

static int register_attributes(struct device *dev)
{
	int i, ret = 0;

	for (i = 0; i < ARRAY_SIZE(gpio_wakeup_attributes); i++) {
		if (device_create_file(dev, gpio_wakeup_attributes + i)) {
			pr_err("%s: Unable to create interface\n", __func__);
			ret = -ENODEV;
			goto err;
		}
	}

err:
	return ret;
}

int gpio_wakeup_create_fs(void *pdata)
{
	int ret = 0;
	char *path_name = MODULE_NAME;

	dev_set_name(&virtdev, "%s", path_name);
	ret = device_register(&virtdev);
	if (ret) {
		pr_err("%s: device_register ret = %d\n", __func__, ret);
		goto err;
	}

	ret = register_attributes(&virtdev);
	if (ret) {
		pr_err("%s: register_attributes ret = %d\n", __func__, ret);
		device_unregister(&virtdev);
		goto err;
	}

	dev_set_drvdata(&virtdev, pdata);

err:
	return ret;
}

static void gpio_wakeup_remove_fs(void)
{
	unregister_attributes(&virtdev);
	device_unregister(&virtdev);
}

static int gpio_wakeup_get_dt(struct platform_device *pdev)
{
	struct device_node *node = pdev->dev.of_node;
	int i, ret = 0;
	ret = of_property_read_u32(node, "irq_gpio_num", &numirq);
	if (ret) {
		pr_err("%s:%d, Unable to read irq_gpio_num\n", __func__, __LINE__);
		ret = -1;
		goto err;
	}

	if (MAX_GPIO_NUM < numirq) {
		pr_err("%s:%d, too many irq_gpio_num\n", __func__, __LINE__);
		ret = -1;
		goto err;
	}

	ret = of_property_read_u32_array(node, "irq_gpios", irq_gpios, numirq);
	if (ret) {
		pr_err("%s:%d, Unable to read irq_gpios\n", __func__, __LINE__);
		ret = -1;
		goto err;
	}

	for (i = 0; i < numirq; i++) {
		pr_info("gpio_wakeup: gpios[%d] = %d\n", i, irq_gpios[i]);
	}

err:
	return ret;
}

static int gpio_wakeup_irq(void)
{
	int i, irq, ret = 0;

	for (i = 0; i < numirq; i++) {
		irq = gpio_to_irq(irq_gpios[i]);
		pr_info("gpio_wakeup: registered for IRQ %d\n", irq);
		enable_irq_wake(irq);
	}
	return ret;
}

static void gpio_wakeup_free_irq(void)
{
	int i, irq;

	for (i = 0; i < numirq; i++) {
		irq = gpio_to_irq(irq_gpios[i]);
		disable_irq_wake(irq);
	}
}

static int gpio_wakeup_probe(struct platform_device *pdev)
{
	void *pdata = platform_get_drvdata(pdev);
	int ret;

	ret = gpio_wakeup_get_dt(pdev);
	if (ret)
		goto err;

	ret = gpio_wakeup_create_fs(pdata);
	if (ret)
		goto err;

	ret = gpio_wakeup_irq();
	if (ret)
		goto err;

err:
	return ret;
}

static int gpio_wakeup_remove(struct platform_device *pdev)
{
	gpio_wakeup_free_irq();
	gpio_wakeup_remove_fs();
	return 0;
}

static int gpio_wakeup_resume(struct platform_device *pdev)
{
	int i, irq;

	for (i = 0; i < numirq; i++) {
		irq = gpio_to_irq(irq_gpios[i]);
		disable_irq_wake(irq);
	}

	return 0;
}

static int gpio_wakeup_suspend(struct platform_device *pdev, pm_message_t state)
{
	int i, irq;

	for (i = 0; i < numirq; i++) {
		irq = gpio_to_irq(irq_gpios[i]);
		if (enable)
			enable_irq_wake(irq);
		else
			disable_irq_wake(irq);
	}

	return 0;
}

static const struct of_device_id gpio_wakeup_of_match[] = {
	{ .compatible = "gpio_wakeup", },
	{ }
};

static struct platform_driver gpio_wakeup_driver = {
	.driver = {
		.name = MODULE_NAME,
		.owner = THIS_MODULE,
		.of_match_table = gpio_wakeup_of_match,
	},
	.probe = gpio_wakeup_probe,
	.remove = gpio_wakeup_remove,
	.suspend = gpio_wakeup_suspend,
	.resume = gpio_wakeup_resume,
};

static int __init gpio_wakeup_init(void)
{
	int ret;
	ret = platform_driver_register(&gpio_wakeup_driver);
	if (ret) {
		pr_err("gpio_wakeup:ret = %d\n",ret);
		return ret;
	}
	pr_info("gpio_wakeup: loaded\n");

	return 0;
}

static void __exit gpio_wakeup_exit(void)
{
	platform_driver_unregister(&gpio_wakeup_driver);
	pr_info("gpio_wakeup: unloaded\n");
}

module_init(gpio_wakeup_init);
module_exit(gpio_wakeup_exit);

MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("GPIO wakeup driver");
