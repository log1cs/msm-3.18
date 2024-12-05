/* 2018-11-19: File added and changed by Sony Corporation */
/*
 *  lib/snsc_lctracer_em_hook.c
 *
 *  Copyright 2018 Sony Corporation
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
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/em_export.h>
#include <linux/snsc_lctracer.h>

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Sony Corporation");

static void *handle = NULL;

static const char *trigger_path = "/proc/snsc_lctracer/trigger";
static const char *trigger_cmd = "external_stop_immediate";

static void lctracer_em_hook_func(struct pt_regs *regs, void *arg)
{
	int len, ret;
	char buf[PROC_TRIGGER_SIZE];
	struct file *filp = NULL;

	do {
		filp = filp_open(trigger_path, O_RDWR, 0);
		if (IS_ERR(filp)) {
			printk(KERN_WARNING "Cannot open [%s]\n",
				trigger_path);
			filp = NULL;
			break;
		}

		len = strlen(trigger_cmd);

		ret = vfs_write(filp, trigger_cmd, len, &(filp->f_pos));
		if (ret != len) {
			printk(KERN_WARNING "Cannot write \"%s\" to [%s]\n",
				trigger_cmd,
				trigger_path);
			break;
		}

 		ret = vfs_read(filp, buf, sizeof(buf), &(filp->f_pos));
		if (ret < 0) {
			printk(KERN_WARNING "Cannot read from [%s]\n",
				trigger_path);
			break;
		}
		buf[ret] = '\0';

		/* report contains prefix of "trigger: ",
			so we cannot use strncmp() for checking */
		if (strstr(buf, trigger_cmd) == NULL) {
			printk(KERN_WARNING "Invalid trigger mode:[%s], except:[%s]\n",
				buf, trigger_cmd);
		} else {
			printk(KERN_INFO "Invoke Trigger on LCTracer!\n");
		}
	} while (0);

	if (filp != NULL) {
		filp_close(filp, NULL);
		filp = NULL;
	}
}

static int __init lctracer_em_hook_init(void)
{
	printk(KERN_NOTICE "%s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);

	handle = em_register_usermode_callback(lctracer_em_hook_func, NULL);
	if(handle == NULL){
		printk(KERN_ERR "%s:%s:Failed em_register_usermode_callback()\n", __FILE__, __FUNCTION__);
		return -ENOMEM;
	}

	printk(KERN_NOTICE "%s:%s:%d handle=%p\n", __FILE__, __FUNCTION__, __LINE__, handle);

	return 0;
}

static void __exit lctracer_em_hook_exit(void)
{
	printk(KERN_NOTICE "%s:%s:%d\n", __FILE__, __FUNCTION__, __LINE__);
	em_unregister_usermode_callback(handle);
	handle = NULL;
}

late_initcall(lctracer_em_hook_init);
module_exit(lctracer_em_hook_exit);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Sony Corporation");

