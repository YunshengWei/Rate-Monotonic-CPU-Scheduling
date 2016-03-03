#include <linux/fs.h>
#include <linux/init.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/timer.h>
#include <linux/types.h>
#include <asm/semaphore.h>
#include <asm/uaccess.h>
#include "mp2_given.h"

#define PROCFS_MAX_SIZE 1024

MODULE_AUTHOR("Yunsheng Wei; Juanli Shen; Funing Xu; Wei Yang");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Rate-Monotonic Scheduler");

struct mp2_task_struct;

static const char delimiters[] = ",";
static struct proc_dir_entry *mp2_dir;
static unsigned long procfs_buffer_size = 0;
static char procfs_buffer[PROCFS_MAX_SIZE];
static struct task_struct *dispatching_thread;
static struct mp2_task_struct current_running_thread;
LIST_HEAD(task_list);
DECLARE_MUTEX(mutex);

enum task_state { RUNNING, READY, SLEEPING };

struct mp2_task_struct {
    struct task_struct *task;
    struct list_head list;
    struct timer_list timer;

    enum task_state state;
    unsigned int pid;
    unsigned long period;
    unsigned long processing_time;
    unsigned long next_period;
};

int context_switch(void *data) {
    struct sched_param sparam_pr99;
    sparam_pr99.sched_priority = 99;
    struct sched_param sparam_pr0;
    sparam_pr0.sched_priority = 0;

    while (!kthread_should_stop()) {
        struct mp2_task_struct *entry;
        struct mp2_task_struct *highest_priority_task = NULL;
        unsigned long min_period = ULONG_MAX;

        if (down_interruptible(&mutex)) {
            return -ERESTARTSYS;
        }
        list_for_each_entry(entry, &task_list, list) {
            if (entry->period < min_period && entry->state == READY) {
                min_period = entry->period;
                highest_priority_task = entry;
            }
        }
        up(&mutex);

        if (current_running_thread && current_running_thread != highest_priority_task) {
            sched_setscheduler(current_running_thread, SCHED_NORMAL, &sparam_pr0);
        }

        
        wake_up_process(highest_priority_task);
        sched_setscheduler(highest_priority_task, SCHED_FIFO, &sparam_pr99);
        current_running_thread = highest_priority_task;
        highest_priority_task->state = RUNNING;

        set_current_state(TASK_UNINTERRUPTIBLE);
        schedule();
    }
    return 0;
}

static void wakeup_timer_callback(unsigned long data) {
    struct mp2_task_struct *entry = (struct mp2_task_struct *) data;
    set_current_state(current_running_thread, TASK_UNINTERRUPTIBLE);
    // Do we need lock here? How?
    entry->state = READY;
    wake_up_process(dispatching_thread);
}

static int rms_show(struct seq_file *file, void *v) {
    struct mp2_task_struct *entry;

    if (down_interruptible(&mutex)) {
        return -ERESTARTSYS;
    }
    list_for_each_entry(entry, &task_list, list) {
        seq_printf(file, "%u, %lu, %lu\n", 
            entry->pid, entry->period, entry->processing_time);
    }
    up(&mutex);

    return 0;
}

static int rms_open(struct inode *inode, struct file *file) {
    return single_open(file, rms_show, NULL);
}

// pass_admission_control should only be called when holding mutex
static bool pass_admission_control(unsigned long period,
    unsigned long processing_time) {
    unsigned long sum;

    struct mp2_task_struct *entry;
    list_for_each_entry(entry, &task_list, list) {
        sum += entry->processing_time * 1000 / entry->period + 1;
    }
    sum += processing_time * 1000 / period + 1;

    if (sum <= 693) {
        return true;
    } else {
        return false;
    }
}

static ssize_t register(unsigned int pid, unsigned long period,
    unsigned long processing_time) {

    if (down_interruptible(&mutex)) {
        return -ERESTARTSYS;
    }
    if (pass_admission_control(pid, period, processing_time)) {
        struct mp2_task_struct *entry = kmalloc(sizeof(struct mp2_task_struct),
        GFP_KERNEL);
        entry->pid = pid;
        entry->period = period;
        entry->processing_time = processing_time;
        entry->task = find_task_by_pid(pid);
        entry->state = SLEEPING;
        entry->next_period = jiffies;
        setup_timer(&entry->timer, wakeup_timer_callback, (unsigned long) entry);
        list_add(&entry->list, &task_list);
    }
    up(&mutex);

    return 0;
}

static ssize_t yield(unsigned int pid) {
    struct mp2_task_struct *entry;
    if (down_interruptible(&mutex)) {
        return -ERESTARTSYS;
    }
    list_for_each_entry(entry, &task_list, list) {
        if (entry->pid == pid) {
            current_running_thread = NULL;
            entry->state = SLEEPING;
            unsigned long next_period = entry->next_period;
            do {
                next_period += entry->period;
            } while (next_period <= jiffies);
            mod_timer(&entry->timer, next_period);
            entry->next_period = next_period;
            set_current_state(entry->task, TASK_UNINTERRUPTIBLE);
            break;
        }
    }
    up(&mutex);

    wake_up_process(dispatching_thread);
    return 0;
}

static void free_task_struct(struct mp2_task_struct *entry) {
    list_del(&entry->list);
    del_timer(&entry->timer);
    kfree(entry);
}

static ssize_t deregister(unsigned int pid) {
    struct mp2_task_struct *entry;

    if (down_interruptible(&mutex)) {
        return -ERESTARTSYS;
    }
    list_for_each_entry_safe(entry, &task_list, list) {
        if (entry->pid == pid) {
            free_task_struct(entry);
            break;
        }
    }
    up(&mutex);

    return 0;
}

static ssize_t rms_write(struct file *file, const char __user *buffer, size_t count, loff_t *data) {
    
    procfs_buffer_size = count;
    if (procfs_buffer_size > PROCFS_MAX_SIZE) {
        procfs_buffer_size = PROCFS_MAX_SIZE;
    }

    if (copy_from_user(procfs_buffer, buffer, procfs_buffer_size)) {
        return -EFAULT;
    }

    char *running;
    char instr = *strsep(&running, delimiters);
    unsigned int pid;
    kstrtouint(strsep(&running, delimiters), 0, &pid);
    ssize_t error_code;

    switch (instr) {
        case 'R': 
            unsigned long period;
            unsigned long process_time;
            kstrtoul(strsep(&running, delimiters), 0, &period);
            kstrtoul(strsep(&running, delimiters), 0, &process_time);

            error_code = register(pid, period, process_time));
            break;
        case 'Y':
            error_code = yield(pid);
            break;
        case 'D':
            error_code = deregister(pid);
            break;
    }

    if (error_code) {
        return error_code;
    } else {
        return byetsToCopy;
    }
}

static const struct file_operations rms_fops = {
    .owner = THIS_MODULE,
    .open = rms_open,
    .read = seq_read,
    .write = rms_write,
    .llseek = seq_lseek,
    .release = single_release,
};

static int __init rms_init(void) {
    printk(KERN_INFO "Loading rate-monotonic scheduler module.\n");

    mp2_dir = proc_mkdir("mp2", NULL);
    proc_create("status", 0666, mp2_dir, &rms_fops);

    dispatching_thread = kthread_create(context_switch,
        NULL, "dispatching thread");


    return 0;
}

static void __exit rms_exit(void) {
    kthread_stop(dispatching_thread);

    struct mp2_task_struct *entry;

    if (down_interruptible(&mutex)) {
        return -ERESTARTSYS;
    }
    list_for_each_entry_safe(entry, &task_list, list) {
        free_task_struct(entry);
    }
    up(&mutex);

    remove_proc_entry("status", mp2_dir);
    remove_proc_entry("mp2", NULL);

    printk(KERN_INFO "Rate-monotonic scheduler module unloaded successfully.\n");
}


module_init(rms_init);
module_exit(rms_exit);
