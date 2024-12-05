/* 2017-10-26: File added and changed by Sony Corporation */
/*
 * driver/soc/qcom/error.c
 *
 * ERROR handler
 *
 * Copyright 2015 Sony Corporation
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
 *
 */
#include <linux/module.h>
#include <linux/init.h>
#include <linux/gpio.h>
#include <linux/cpu.h>
#include <linux/sched.h>
#include <linux/delay.h>
#include <linux/kthread.h>
#include <linux/em_export.h>
#include <asm/io.h>
#include <linux/string.h>
#include <linux/syscalls.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/fcntl.h>
#include <linux/exception_monitor.h>
#include <linux/proc_fs.h>

#define GREEN_LED_GPIO  137
#define RED_LED_GPIO  138
#define YELLOW_LED_GPIO  139

/*
 * More than 10ms interval is required between 1st and 2nd
 * relax command.
 */
#define RELAX_CMD_INTERVAL_MS        20
/*
 * Wait for 60 sec for completion of relax command
 */
#define RELAX_CMD_COMPLETION_SEC     60

/*
 * This led brink interval will be modified via
 * /proc/err_led_blink_time.
 * By default, led will NOT blink to notify exceptions.
 */
#define LED_BLINK_TIMEOUT_SEC       0
static unsigned int waiting_time = LED_BLINK_TIMEOUT_SEC;

/* Error codes */
#define ERR_NONE	0
#define ERR_USER	1
#define ERR_OOM		2
#define ERR_OOPS	3
#define ERR_MAX		3

/*
 * Action after exception will be modified via
 * /proc/err_action.
 * Default behavior is reboot
 */
#define NOTHING_AFTER_EXCEPTION       0
#define REBOOT_AFTER_EXCEPTION        1
#define SHUTDOWN_AFTER_EXCEPTION      2
static unsigned int action_after_exception = REBOOT_AFTER_EXCEPTION;



#ifdef CONFIG_EM_BLINK_LED
struct err_ctrl {
	unsigned int intro;
	unsigned int on;
	unsigned int off;
	unsigned int interval;
	unsigned int ptnlen;
	char ptn[8];
};
static const struct err_ctrl err_user = { 1500, 200, 200,   0, 3,"337" };
static const struct err_ctrl err_oom  = { 1500,1000, 500,1500, 1,"3" };
static const struct err_ctrl err_oops = { 1500,  50,   0,   0, 1,"1" };
static const struct err_ctrl *err_ctrls[] = {
	&err_user,
	&err_oom,
	&err_oops,
};
static unsigned int err_task_event = ERR_NONE;
static struct workqueue_struct *err_workqueue;
static struct work_struct err_work;
#endif


#if defined(CONFIG_EM_BLINK_LED) || defined(CONFIG_EM_GET_RELAXED)
/* kill process */
static void err_kill_process(char *target_comm)
{
	struct task_struct *p;
	if (strlen(target_comm) == 0) return;
	printk(KERN_ERR "enter err_kill\n");
	read_lock(&tasklist_lock);
	for_each_process(p) {
		task_lock(p);
		if (strncmp(target_comm, p->comm, strlen(target_comm)) == 0) {
			printk(KERN_ERR "[process info]: name %s, pid %d\n", p->comm, p->pid);
			printk(KERN_ERR "[KILL PROCESS]: name %s, pid %d\n", p->comm, p->pid);
			do_send_sig_info(SIGKILL, SEND_SIG_FORCED, p, true);
		}
		task_unlock(p);
	}
	read_unlock(&tasklist_lock);
}
#endif

#ifdef CONFIG_EM_GET_RELAXED
static void err_relax(void)
{
	int pos;
	int fd;
	int i;
	char *filename;
	char data[10];
	mm_segment_t old_fs;
	/*
	 * data = {0xAA, 0x16, 0x00, 0x06, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC1};
	 */
	data[0] = 0xAA;
	data[1] = 0x16;
	data[2] = 0x00;
	data[3] = 0x06;
	data[4] = 0xFF;
	data[5] = 0xFF;
	data[6] = 0xFF;
	data[7] = 0xFF;
	data[8] = 0xFF;
	data[9] = 0xC1;
	filename = "/dev/ttyHS3";
	pos = 0;

	printk(KERN_NOTICE "err_relax: enter relax mode\n");
	printk(KERN_NOTICE "err_relax: kill body_controller\n");
	err_kill_process("body_controller");
	old_fs = get_fs();
	set_fs(KERNEL_DS);

	fd = sys_open(filename, O_RDWR, 0);

	if (fd >= 0) {
		for (i = 0; i < 2; i++) {
			printk(KERN_NOTICE "err_relax: Send relax cmd %s time\n", i ? "second" : "first");
			pos = sys_write(fd, data, sizeof(data));
			if (pos != sizeof(data)) {
				printk(KERN_ERR "cannot write to:%s with expected %lud bytes data, actually write %d bytes\n",filename, sizeof(data), pos);
			}
			msleep(RELAX_CMD_INTERVAL_MS);
		}
		sys_close(fd);
	} else {
		printk(KERN_ERR "open file:%s error: %d\n",filename, fd);
	}
	set_fs(old_fs);
}
#endif

#ifdef CONFIG_EM_BLINK_LED
/* LED driver */
static void set_led(int on)
{
	if (on)
		gpio_set_value(RED_LED_GPIO, 1);
	else
		gpio_set_value(RED_LED_GPIO, 0);
}

#ifdef CONFIG_EM_GET_RELAXED
static void err_system_to_end(void)
{
	/* system will reboot or shutdown depends on action_after_exception */
	if (action_after_exception == REBOOT_AFTER_EXCEPTION) {
		printk(KERN_NOTICE "err_handler: going to reboot\n");
		machine_restart("exception");
	} else {
		printk(KERN_NOTICE "err_handler: going to power off\n");
		kernel_power_off();
	}

	/* Never come here */
}
#endif

static void err_sequencer(int code)
{
	const struct err_ctrl *ctl;
	int pos, cnt;
#ifdef CONFIG_EM_GET_RELAXED
	unsigned long timeout = jiffies + msecs_to_jiffies(waiting_time * MSEC_PER_SEC);

	/* Enter relax mode */
	err_relax();

	/*
	 * If waiting time is 0, we will not blink led to notify exceptions
	 * system is going to reboot or shutdown after waiting relax command completion.
	 */
	if (waiting_time == 0) {
		printk(KERN_NOTICE "err_sequncer: Wait for %d sec to complete relax command\n",
		       RELAX_CMD_COMPLETION_SEC);
		msleep(RELAX_CMD_COMPLETION_SEC * MSEC_PER_SEC);
		err_system_to_end();
		/* Never come here */
	}
#endif

	if (code < 1  ||  ERR_MAX < code) {
		printk(KERN_ERR "err_sequncer:ERROR:code=%d\n", code);
		return;
	}
	ctl = err_ctrls[code - 1];

	gpio_set_value(GREEN_LED_GPIO, 0);
	gpio_set_value(YELLOW_LED_GPIO, 0);

	set_led(1);
	msleep(ctl->intro);
	set_led(0);
	msleep(ctl->on + ctl->off);
#ifdef CONFIG_EM_GET_RELAXED
	while (time_before(jiffies, timeout)) {
#else
	while (1) {
#endif
		for (pos = 0; pos < ctl->ptnlen; pos++) {
			printk_once(KERN_NOTICE "err_sequncer: blink LED for %u sec\n", waiting_time);
			gpio_set_value(GREEN_LED_GPIO, 0);
			gpio_set_value(YELLOW_LED_GPIO, 0);
			cnt = ctl->ptn[pos] - '0';
			while (cnt > 0) {
				set_led(1);
				msleep(ctl->on);
				set_led(0);
				msleep(ctl->off);
				cnt--;
			}
			msleep(ctl->on + ctl->off);
		}
		msleep(ctl->interval);
	}
	/* if CONFIG_EM_GET_RELAXED n, never come here */
#ifdef CONFIG_EM_GET_RELAXED
	err_system_to_end();
	/* Never come here */
#endif
}

static void err_work_func(struct work_struct *work)
{
	struct sched_param param = { .sched_priority = MAX_RT_PRIO - 1 };

	sched_setscheduler(current, SCHED_FIFO, &param);
	err_sequencer(err_task_event);
}
#endif /*  CONFIG_EM_BLINK_LED */

static void err_handler(struct pt_regs *regs)
{
#ifdef CONFIG_EM_BLINK_LED
	int code;
#endif

	printk(KERN_INFO "enter err handler\n");

	if (action_after_exception == NOTHING_AFTER_EXCEPTION) {
		printk(KERN_INFO "do nothing in err handler\n");
		return;
	}

#ifdef CONFIG_EM_BLINK_LED
	/* analyze */
	code = ERR_OOPS;
	if (user_mode(regs)) {
		code = ERR_USER;
		if (test_tsk_thread_flag(current, TIF_MEMDIE)) {
			code = ERR_OOM;
		}
	}
	/* local indicator */
	err_task_event = code;
	err_kill_process("powermanagerd");
	if (code == ERR_OOPS) {
		printk(KERN_DEBUG "err:blink LED in main thread.\n");
		err_sequencer(code);
	} else {
		printk(KERN_DEBUG "err:kick blink LED work.\n");
		queue_work(err_workqueue, &err_work);
	}
#endif
}

static ssize_t err_action_read(struct file *file, char __user *user_buf,
					  size_t count, loff_t *ppos)
{
	char buf[2];
	size_t ret;

	if (action_after_exception == NOTHING_AFTER_EXCEPTION)
		buf[0] = 'n';
	else if (action_after_exception == REBOOT_AFTER_EXCEPTION)
		buf[0] = 'r';
	else
		buf[0] = 's';

	buf[1] = '\n';

	ret = simple_read_from_buffer(user_buf, count, ppos, buf, sizeof(buf));

	return ret;
}


static ssize_t err_action_write(struct file *file, const char __user *user_buf,
					  size_t count, loff_t *ppos)
{
	char buf[2];
	size_t ret;

	ret = simple_write_to_buffer(buf, sizeof(buf), ppos, user_buf, count);

	if (buf[0] == 'n') {
		action_after_exception = NOTHING_AFTER_EXCEPTION;
	} else if (buf[0] == 'r') {
		action_after_exception = REBOOT_AFTER_EXCEPTION;
	} else if (buf[0] == 's') {
		action_after_exception = SHUTDOWN_AFTER_EXCEPTION;
	} else {
		printk(KERN_ERR "err:invalid value\n");
		return -EINVAL;
	}

	return ret;
}

static const struct file_operations err_action_fops = {
	.owner	= THIS_MODULE,
	.read = err_action_read,
	.write = err_action_write,
};

static int err_action_register(void)
{
	int ret = 0;

	if (!proc_create("err_action", S_IWUSR|S_IRUSR, NULL, &err_action_fops)) {
		printk(KERN_ERR
		       "Err: Unable to create proc entry\n");
		ret = -ENOMEM;
	}

	return ret;
}

static void err_action_unregister(void)
{
	remove_proc_entry("err_action", NULL);
}


static ssize_t err_led_blink_time_read(struct file *file, char __user *user_buf,
				     size_t count, loff_t *ppos)
{
	char buf[8];
	size_t ret;

	memset(buf, 0, sizeof(buf));	
	snprintf(buf, sizeof(buf), "%u\n", waiting_time);
	ret = simple_read_from_buffer(user_buf, count, ppos, buf, sizeof(buf));

	return ret;
}


static ssize_t err_led_blink_time_write(struct file *file, const char __user *user_buf,
				      size_t count, loff_t *ppos)
{
	char buf[8];
	size_t ret;
	unsigned int val;

	ret = simple_write_to_buffer(buf, sizeof(buf), ppos, user_buf, count);

	val = simple_strtoul(buf, NULL, 0);
	if ((val == 0) || ((val >= 60) && (val <= 7200))) {
		waiting_time = val;
	} else {
		printk(KERN_ERR "err: valid value is 0 or between 60 and 7200 in sec\n");
		return -EINVAL;
	}

	return ret;
}

static const struct file_operations err_led_blink_time_fops = {
	.owner	= THIS_MODULE,
	.read = err_led_blink_time_read,
	.write = err_led_blink_time_write,
};

static int err_led_blink_time_register(void)
{
	int ret = 0;

	if (!proc_create("err_led_blink_time", S_IWUSR|S_IRUSR, NULL, &err_led_blink_time_fops)) {
		printk(KERN_ERR
		       "Err: Unable to create proc entry\n");
		ret = -ENOMEM;
	}

	return ret;
}

static void err_led_blink_time_unregister(void)
{
	remove_proc_entry("err_led_blink_time", NULL);
}

static int __init err_init(void)
{
	int ret = 0;

	ret = err_action_register();
	if (ret < 0)
		return ret;

	ret = err_led_blink_time_register();
	if (ret < 0)
		return ret;

#ifdef CONFIG_EM_BLINK_LED
	err_workqueue = create_singlethread_workqueue("em_blink_led");
	if (!err_workqueue) {
		err_action_unregister();
		err_led_blink_time_unregister();
		return -ENOMEM;
	}
	INIT_WORK(&err_work, err_work_func);
#endif

	em_hook = err_handler;

	return ret;
}

static void __exit err_exit(void)
{
	em_hook = NULL;

#ifdef CONFIG_EM_BLINK_LED
	destroy_workqueue(err_workqueue);
#endif

	err_action_unregister();

	err_led_blink_time_unregister();
}

module_init(err_init);
module_exit(err_exit);
