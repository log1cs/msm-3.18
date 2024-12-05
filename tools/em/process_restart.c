/* 2021-01-25: File added and changed by Sony Corporation */
/*
 *  process_restart.c  - Exception Monitor addon 
 *
 */

/* With non GPL files, use following license */
/*
 * Copyright 2017,2021 Sony Corporation.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions, and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
/* Otherwise with GPL files, use following license */
/*
 *  Copyright 2017,2021 Sony Corporation.
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
 *  51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */
#include <linux/ctype.h>
#include <linux/slab.h>
#include <linux/time.h>
#include <linux/sched.h>
#include <linux/seq_file.h>
#include <linux/proc_fs.h>
#include <asm/uaccess.h>
#include "exception.h"

struct proc_dir_entry *proc_restart;

/*
 * White list process structure
 * structure is defined in include/linux/em_export.h
 * time is calculated in sec
*/
struct whitelist_process {
        char process_name[TASK_COMM_LEN];
        unsigned short counter;
        unsigned short max_counter;
        unsigned long process_time;
        unsigned long max_process_time;
        struct whitelist_process *next;
};

struct whitelist_process *process_list_head, *last_exception_process;

struct child_process {
	pid_t pid;
	char name[TASK_COMM_LEN];
	struct child_process *sibling;
};

struct child_process *first_child = NULL;
static bool is_process_restart_enable = true;

/*
 * This function is to dump the whitelist process status to
 * console/dump file as per the config.
 */
void em_process_status_dump(void)
{
	struct timeval now;
	struct whitelist_process *ref = process_list_head;

	do_gettimeofday(&now);

	em_dump_write("|     Process Name     |  Counter  |  Running Time(s)  |\n");

	while (ref != NULL) {
		if (ref->process_time) {
			em_dump_write("|  %-18.18s  |  %3d/%-3d  |  %7lu/%-7lu  |\n",
				      ref->process_name, ref->counter, ref->max_counter,
				      (now.tv_sec - ref->process_time), ref->max_process_time);
		}
		else
			em_dump_write("|  %-18.18s  |  %3d/%-3d  |  %7d/%-7lu  |\n",
				      ref->process_name, ref->counter, ref->max_counter,
				      0, ref->max_process_time);
		ref = ref->next;
	}
}

/*
 * proc entry to show the Status of the whitelist processes.
 */
static int process_status_show(struct seq_file *m, void *v)
{
	struct timeval now;
	struct whitelist_process *ref = process_list_head;

	do_gettimeofday(&now);

	seq_printf(m, "|     Process Name     |  Counter  |  Running Time(s)  |\n");

	while (ref != NULL) {
		if (ref->process_time) {
			seq_printf(m, "|  %-18.18s  |  %3d/%-3d  |  %7lu/%-7lu  |\n",
				ref->process_name, ref->counter, ref->max_counter,
			(now.tv_sec - ref->process_time), ref->max_process_time);
		} else {
			seq_printf(m, "|  %-18.18s  |  %3d/%-3d  |  %7d/%-7lu  |\n",
				ref->process_name, ref->counter, ref->max_counter,
			0, ref->max_process_time);
		}
			ref = ref->next;
	}
	return 0;
}

static int process_status_open(struct inode *inode, struct file *file)
{
	return single_open(file, process_status_show, NULL);
}

static const struct file_operations process_status_fops = {
	.open           = process_status_open,
	.read           = seq_read,
	.release        = single_release,
};

/*
 * This proc entry is created to enable and disable system reboot
 * framework.
 * '0' implies disable
 * '1' implies enable
 */
static ssize_t system_reboot_action_read(struct file *file,
			char __user *user_buf, size_t count, loff_t *ppos)
{
	char buf[2];
	size_t ret;

	if (is_process_restart_enable)
		buf[0] = '1';
	else
		buf[0] = '0';

	buf[1] = '\n';

	ret = simple_read_from_buffer(user_buf, count, ppos, buf, sizeof(buf));

	return ret;
}


static ssize_t system_reboot_action_write(struct file *file,
			const char __user *user_buf, size_t count, loff_t *ppos)
{
	char buf[2];
	size_t ret;

	ret = simple_write_to_buffer(buf, sizeof(buf), ppos, user_buf, count);

	if (buf[0] == '1') {
		is_process_restart_enable = true;
	} else if (buf[0] == '0') {
		is_process_restart_enable = false;
	} else {
		printk(KERN_ERR "err:status invalid value\n");
		printk(KERN_ERR "1 to enable & 0 to disable\n");
		return -EINVAL;
	}
	return ret;
}

static const struct file_operations system_reboot_support_fops = {
	.read = system_reboot_action_read,
	.write = system_reboot_action_write,
};

static void em_clear_whitelist(void)
{
	struct whitelist_process *ref;
	struct whitelist_process *next;
	ref = process_list_head;
	while (ref != NULL) {
		next = ref->next;
		kfree(ref);
		ref = next;
	}
	process_list_head = NULL;
}

static int em_append_whitelist(struct whitelist_process **process_list,
			char *name, unsigned long max_counter, unsigned long max_time)
{

	struct whitelist_process *traverse_list = *process_list;
	struct whitelist_process *process_node =
		(struct whitelist_process*) kmalloc (sizeof(struct whitelist_process), GFP_KERNEL);

	if (!process_node) {
		return -ENOMEM;
	}

	strncpy(process_node->process_name, name, TASK_COMM_LEN);
	process_node->counter = 0;
	process_node->max_counter = (int)max_counter;
	process_node->process_time = 0;
	process_node->max_process_time = max_time;
	process_node->next = NULL;

	if (*process_list == NULL) {
		*process_list = process_node;
		return 0;
	}
	while (traverse_list->next != NULL) {
		traverse_list = traverse_list->next;
	}

	traverse_list->next = process_node;
	return 0;
}

/*
 * This function extracts the whitelist from buffer
 * @buffer: data from the whitelist text file
 * @length: length of the buffer
 */
static int em_extract_whitelist(char *buffer, int length)
{
	int i = 0, j = 0;
	char array[3][TASK_COMM_LEN];
	char name[TASK_COMM_LEN];
	int count = 0;
	int ret = 0;
	unsigned long max_counter, max_time;

	if (length == 2 && buffer[0] == '0') {
		em_clear_whitelist();
		return 0;
	}
	while (buffer[i] != '\0') {
		while (buffer[i] != '\n') {
			if (count > 2) {
				em_print_error("Pass three parameters\n");
				return -1;
			} else {
				if(buffer[i] == ' ') {
					array[count][j] = '\0';
					/* for next word */
					count++;
					/* for next word, init index to 0 */
					j = 0;
					i++;
				} else {
					array[count][j] = buffer[i];
					j++;
					i++;
					if(count == 0 && j == TASK_COMM_LEN) {
						em_print_warning("[WARN] Max whitelist "
							"process name length should preferably "
							"be %d\n", TASK_COMM_LEN-1);
						j--;
						while (buffer[i] != ' ') {
							if (buffer[i] == '\n')
								break;
							i++;
						}
					}
				}
			}
		}
		array[count][j] = '\0';

		strncpy(name, array[0], TASK_COMM_LEN);

		ret = kstrtoul(array[1], 10, &max_counter);
		if (ret < 0) {
			em_print_error("Pass three parameters\n");
			return -1;
		}

		if(max_counter > USHRT_MAX) {
			em_print_error("Counter value out of range ( >%d )\n"
				, USHRT_MAX);
			return -1;
		}

		ret = kstrtoul(array[2], 10, &max_time);
		if (ret < 0) {
			em_print_error("Pass three parameters\n");
			return -1;
		}

		ret = em_append_whitelist(&process_list_head, name, max_counter, max_time);
		if (ret) {
			em_print_error("Memory not available to update white list\n");
			return -1;
		}

		memset(array, 0, sizeof(array));

		count = 0;
		j = 0;
		i++;
	}

	return 0;
}

/*
 * This proc entry is to update the whitelist.
 */
static ssize_t whitelist_proc_write(struct file *filp,
			const char __user *ubuf, size_t count, loff_t *ppos)
{
	char *buffer = NULL;
	int error_check;
	int ret;

	em_clear_whitelist();

	if (*ppos > 0 || count > 4096) {
		em_print_error("Max whitelist file size allowed is 4K\n");
		ret = -EFAULT;
		goto buffer_free;
	}

	buffer = (char *)kmalloc((count + 1) * sizeof(char), GFP_KERNEL);
	if (!buffer) {
		em_print_error("Memory not available to copy user buffer\n");
		ret = -ENOMEM;
		goto buffer_free;
	}

	if (copy_from_user(buffer, ubuf, count)) {
		em_print_error("user buffer copy failed in whitelist\n");
		ret = -EFAULT;
		goto buffer_free;
	}

	buffer[count] = '\0';

	error_check = em_extract_whitelist(buffer, count);
	if (error_check < 0) {
		em_print_error("Whitelist not updated\n");
		em_clear_whitelist();
		ret = -EINVAL;
		goto buffer_free;
	}

	*ppos = strlen(buffer);
	ret = *ppos;

buffer_free:
	kfree(buffer);
	return ret;
}

static const struct file_operations whitelist_update_ops = {
	.write = whitelist_proc_write,
};

/*
 * proc entry to show the killed child processes(if any) of the whitelist processes.
*/
static int child_killed_show(struct seq_file *file, void *v)
{
	struct child_process *current_child = first_child, *ref;

	seq_printf(file, "Parent :\n %16s\n", last_exception_process->process_name);
	if(first_child != NULL) {
		seq_printf(file, "Child processes:\n");
		while(current_child != NULL) {
			seq_printf(file, "%4u %16s\n", current_child->pid, current_child->name);
			ref = current_child->sibling;
			kfree(current_child);
			current_child = ref;
		}
	} else {
		seq_printf(file, "No child for this process\n");
	}
	first_child = NULL;
	return 0;
}

static int child_killed_open(struct inode *inode, struct file *file)
{
	return single_open(file, child_killed_show, NULL);
}

static const struct file_operations child_killed_fops = {
	.open           = child_killed_open,
	.read           = seq_read,
	.release        = single_release,
};

/*
 * This function is called to create the required proc entries for
 * system reboot framework
 */
int em_system_reboot_register(void)
{
	int ret = 0;

	proc_restart = proc_mkdir("em_proc_restart",NULL);

	if (!proc_create("enable", S_IWUSR|S_IRUSR, proc_restart, &system_reboot_support_fops)) {
		em_print_error(
		       "Unable to create proc entry for enable\n");
		ret = -ENOMEM;
		goto release_em_proc_restart;
	}
	if (!proc_create("whitelist", S_IWUSR, proc_restart, &whitelist_update_ops)) {
		em_print_error(
		       "Unable to create proc entry for whitelist\n");
		ret = -ENOMEM;
		goto release_em_proc_enable;
	}
	if (!proc_create("status", S_IRUGO, proc_restart, &process_status_fops)) {
		em_print_error(
		       "Unable to create proc entry for status\n");
		ret = -ENOMEM;
		goto release_em_proc_whitelist;
	}
	if (!proc_create("killed_child_info", S_IRUGO, proc_restart, &child_killed_fops)) {
		em_print_error(
		       "Unable to create proc entry for process killed\n");
		ret = -ENOMEM;
		goto release_em_proc_status;
	}

	goto out;

release_em_proc_status:
	remove_proc_entry("status", proc_restart);
release_em_proc_whitelist:
	em_clear_whitelist();
	remove_proc_entry("whitelist", proc_restart);
release_em_proc_enable:
	remove_proc_entry("enable", proc_restart);
release_em_proc_restart:
	remove_proc_entry("em_proc_restart", NULL);
out:
	return ret;
}

/*
 * This is called to remove the proc entries for process
 * reboot framework.
 */
void em_system_reboot_unregister(void)
{
	remove_proc_entry("enable", proc_restart);
	em_clear_whitelist();
	remove_proc_entry("whitelist", proc_restart);
	remove_proc_entry("status", proc_restart);
	remove_proc_entry("killed_child_info", proc_restart);
	remove_proc_entry("em_proc_restart", NULL);
}

void em_kill_child_process(struct task_struct *p)
{
	struct task_struct *child = NULL;
	struct list_head *list;
	struct child_process *current_child = NULL;
	list_for_each(list, &p->children) {
		if (list) {
			child = list_entry (list, struct task_struct, sibling);
			if (child) {
				if(first_child == NULL ) {
					first_child = (struct child_process *)kmalloc(sizeof(struct child_process), GFP_KERNEL);
					current_child = first_child;
				} else {
					current_child->sibling = (struct child_process *)kmalloc(sizeof(struct child_process), GFP_KERNEL);
					current_child = current_child->sibling;
				}
				current_child->pid = child->pid;
				strncpy(current_child->name, (void *)child->comm, TASK_COMM_LEN);
				kill_proc_info(SIGKILL, SEND_SIG_FORCED, child->pid);
			}
		} else {
			return;
		}
	}
	current_child->sibling = NULL;
}

int system_reboot_framework(void)
{
	int ret = 1;
	struct timeval now;
	struct whitelist_process *ref = process_list_head;

	if (!is_process_restart_enable)
		return 0;
	/*
	 * Initial state, action to do after exception is
	 * saved. This can be updated using the proc entry.
	 */
	do_gettimeofday(&now);

	while (ref != NULL) {
		/*
		 * string comparison is done to verify if the process
		 * exist in whitelist or not.
		*/
		if (strncmp(current->comm, ref->process_name,
					strlen(current->comm)) == 0) {
			last_exception_process = ref;
			if (ref->process_time == 0)
				ref->process_time = now.tv_sec;

			/*
			 * Process running time is compared to check the
			 * process running time. if running for more than
			 * N time reset the counter
			 */
			if ((now.tv_sec - ref->process_time) >
					ref->max_process_time) {
				ref->counter = 0;
				ref->process_time = now.tv_sec;
			} else {
				ref->process_time = now.tv_sec;
			}

			ref->counter += 1;

			/*
			 * Comparing if the max defined counter is reached or not.
			 * If reached perform action as per the
			 * action_after_exception value
			 * if not, do nothing after exception.
			 */
			if (ref->counter <= ref->max_counter) {
				if (!list_empty(&current->children))
					em_kill_child_process(current);
				ret = 0;
			} else {
				ret = 1;
			}
			break;
		} else {
			ret = 1;
		}

	ref = ref->next;
	}
	return ret;
}
