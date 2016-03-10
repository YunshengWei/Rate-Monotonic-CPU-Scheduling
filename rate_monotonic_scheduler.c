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
#include <linux/semaphore.h>
#include <asm/uaccess.h>

#include "mp2_given.h"

#define PROCFS_MAX_SIZE 1024

MODULE_AUTHOR("Yunsheng Wei; Juanli Shen; Funing Xu; Wei Yang");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Rate-Monotonic Scheduler");

/* Forward declaration */

// For struct
struct mp2_task_struct;

// For functions
int context_switch(void *data);
static void wakeup_timer_callback(unsigned long data);
static int rms_show(struct seq_file *file, void *v);
static int rms_open(struct inode *inode, struct file *file);
static ssize_t rms_write(struct file *file, const char __user *buffer, size_t count, loff_t *data);
static ssize_t rms_register(unsigned int pid, unsigned long period,
                            unsigned long processing_time);
static bool _pass_admission_control(unsigned long period,
                                   unsigned long processing_time);
static ssize_t rms_yield(unsigned int pid);
static ssize_t rms_deregister(unsigned int pid);
static void _free_task_struct(struct mp2_task_struct *entry);

/* Variable declaration */

static const char delimiters[] = ",";
static struct proc_dir_entry *mp2_dir;
static unsigned long procfs_buffer_size = 0;
static char procfs_buffer[PROCFS_MAX_SIZE];
static struct task_struct *dispatching_thread;
static struct mp2_task_struct *current_running_task;
static struct kmem_cache *mp2_task_struct_cachep;
static struct semaphore mutex;

enum task_state { RUNNING, READY, SLEEPING };

LIST_HEAD(task_list);

/* PCB wrapper for RMS */

struct mp2_task_struct {
    // Linux PCB
    struct task_struct *task;

    // Parameters
    unsigned int pid;
    unsigned long period;
    unsigned long processing_time;

    // Calculated for timer reset
    unsigned long next_period;

    struct timer_list timer;
    enum task_state state;

    struct list_head list;
};

/* RMS scheduling */

// Main dispatching thread
//  Usually it's sleeping
//  Two situations need rescheduling
//  1. Timer expires, new period of a task comes
//  2. Some task yields
int context_switch(void *data) {
    struct sched_param sparam_pr90;
    sparam_pr90.sched_priority = 90;
    struct sched_param sparam_pr0;
    sparam_pr0.sched_priority = 0;

    while (!kthread_should_stop()) {
        printk("Enter dispatching thread loop...\n");

        struct mp2_task_struct *entry;
        struct mp2_task_struct *highest_priority_task = NULL;
        unsigned long min_period = ULONG_MAX;

        if (down_interruptible(&mutex)) {
            return -ERESTARTSYS;
        }

        // Must set state to sleep before iterating 
        //  to guarantee highest priority task is chosen before dispatching.
        //  It can be thought as below:
        //   First assume we can finish dispatching without interruption,
        //    so we set ourself as sleep to let our app run smoothly later.
        //   If unluckily, some other task wakes up, 
        //    the timer interrupt handler will wake up the dispatching thread again,
        //    which makes our assumption invalid.
        //    As a result, the dispatching thread will continue to run after schedule(),
        //     until it chooses a legitate task succuessfully.
        set_current_state(TASK_UNINTERRUPTIBLE);

        // Search for the highest priority task among READY or RUNNING tasks
        list_for_each_entry(entry, &task_list, list) {
            if (entry->period < min_period &&
                (entry->state == READY || entry->state == RUNNING)) {
                min_period = entry->period;
                highest_priority_task = entry;

                printk("Temp choice: PID-%u, P-%lu\n", entry->pid, entry->period);
            }
        }
        up(&mutex);

        if (highest_priority_task) {
            printk("Final choice: PID-%u, P-%lu\n", 
                highest_priority_task->pid, highest_priority_task->period);
        }
        
        if (current_running_task != highest_priority_task) {
            if (current_running_task) {
                // Preemption happens
                current_running_task->state = READY;
                sched_setscheduler(current_running_task->task, SCHED_NORMAL, &sparam_pr0);

                printk("%u (%lu) is preempted by %u (%lu)\n",
                    current_running_task->pid, current_running_task->period,
                    highest_priority_task->pid, highest_priority_task->period);
            }
            // Else, use CPU directly

            // Set it properly so that it can be chosen
            wake_up_process(highest_priority_task->task);
            sched_setscheduler(highest_priority_task->task, SCHED_FIFO, &sparam_pr90);

            // We know it will be chosen
            highest_priority_task->state = RUNNING;
            current_running_task = highest_priority_task;
        }

        printk("Leave dispatching thread loop...\n");
        schedule();
    }
    
    return 0;
}

//  1. Timer expires, new period of a task comes
static void wakeup_timer_callback(unsigned long data) {
    struct mp2_task_struct *entry = (struct mp2_task_struct *) data;

    // The task is still sleeping
    //  don't wake_up_process here
    entry->state = READY;
    printk("Timer interrupts, %u new period\n", entry->pid);

    wake_up_process(dispatching_thread);
}

/* Proc FS I/O */

// Callbacks registration
static const struct file_operations rms_fops = {
    .owner = THIS_MODULE,
    .open = rms_open,
    .read = seq_read,
    .write = rms_write,
    .llseek = seq_lseek,
    .release = single_release,
};

// Read callback
static int rms_show(struct seq_file *file, void *v) {
    struct mp2_task_struct *entry;

    if (down_interruptible(&mutex)) {
        return -ERESTARTSYS;
    }
    list_for_each_entry(entry, &task_list, list) {
        // This will be read and checked by app,
        //  so don't change it, 
        //  otherwise seg fault.
        seq_printf(file, "%u, %lu, %lu\n", 
            entry->pid, entry->period, entry->processing_time);
    }
    up(&mutex);

    return 0;
}

static int rms_open(struct inode *inode, struct file *file) {
    return single_open(file, rms_show, NULL);
}

// Write callback
static ssize_t rms_write(struct file *file, const char __user *buffer, size_t count, loff_t *data) {
    procfs_buffer_size = count;
    if (procfs_buffer_size > PROCFS_MAX_SIZE - 1) {
        procfs_buffer_size = PROCFS_MAX_SIZE - 1;
    }

    if (copy_from_user(procfs_buffer, buffer, procfs_buffer_size)) {
        return -EFAULT;
    }

    // Must have this NULL to avoid stale record appears
    procfs_buffer[procfs_buffer_size] = '\0';

    char *running = procfs_buffer;
    char cmd = *strsep(&running, delimiters);

    unsigned int pid;
    unsigned long period;
    unsigned long process_time;

    kstrtouint(strsep(&running, delimiters), 0, &pid);

    ssize_t rv = 0;

    switch (cmd) {
        case 'R' :
            kstrtoul(strsep(&running, delimiters), 0, &period);
            kstrtoul(strsep(&running, delimiters), 0, &process_time);

            rv = rms_register(pid, period, process_time);
            break;

        case 'Y' :
            rv = rms_yield(pid);
            break;

        case 'D' :
            rv = rms_deregister(pid);
            break;

        default:
            printk("Wrong command: %c\n", cmd);
    }

    if (rv) {
        return rv;
    } else {
        return procfs_buffer_size;
    }
}

// 1. R 
static ssize_t rms_register(unsigned int pid, unsigned long period,
    unsigned long processing_time) {

    printk("Try to register: PID-%u, P-%lu, C-%lu\n", pid, period, processing_time);

    if (down_interruptible(&mutex)) {
        return -ERESTARTSYS;
    }
    if (_pass_admission_control(period, processing_time)) {
        struct mp2_task_struct *entry = kmem_cache_alloc(mp2_task_struct_cachep, GFP_KERNEL);
        entry->pid = pid;
        entry->period = period;
        entry->processing_time = processing_time;
        entry->task = find_task_by_pid(pid);
        entry->state = SLEEPING;
        // The first period is skipped
        entry->next_period = jiffies;
        // Timer is updated and started in the yield() exactly after register()
        setup_timer(&entry->timer, wakeup_timer_callback, (unsigned long) entry);
        list_add(&entry->list, &task_list);

        printk("Register succeeded: PID-%u.\n", pid);
    } else {
        printk("Register failed: PID-%u.\n", pid);
    }

    up(&mutex);

    return 0;
}

// It should only be called when holding mutex
static bool _pass_admission_control(unsigned long period,
    unsigned long processing_time) {

    // Floating point computation is too expensive,
    //  so must use fixed point instead.
    unsigned long sum = 0;

    struct mp2_task_struct *entry;
    list_for_each_entry(entry, &task_list, list) {
        sum += entry->processing_time * 1000 / entry->period + 1;
    }
    sum += processing_time * 1000 / period + 1;

    printk("AC sum is %lu\n", sum);

    if (sum <= 693) {
        return true;
    } else {
        return false;
    }
}

// 2. Y
static ssize_t rms_yield(unsigned int pid) {
    if (down_interruptible(&mutex)) {
        return -ERESTARTSYS;
    }

    // Restart the timer for next period
    struct mp2_task_struct *entry;
    list_for_each_entry(entry, &task_list, list) {
        if (entry->pid == pid) {
            current_running_task = NULL;
            
            // In case doesn't finish in this period.
            do {
                entry->next_period += msecs_to_jiffies(entry->period);
            } while (entry->next_period <= jiffies);

            mod_timer(&entry->timer, entry->next_period);

            printk(KERN_INFO "Yield: PID-%u.\n", pid);
            break;
        }
    }

    wake_up_process(dispatching_thread);

    // Must release lock before setting to sleep,
    //  otherwise might cause deadlock!
    //  What will happen if setting to sleep is followed by releasing lock?
    //   If timer interrupt happens in the middle,
    //    the dispatching thread will block on the list,
    //    what's important is that this task will sleep forever,
    //     and won't release the lock,
    //    because even when its timer expires,
    //     it will depend on the dispatching thread to select itself.
    up(&mutex);

    entry->state = SLEEPING;
    set_task_state(entry->task, TASK_UNINTERRUPTIBLE);
    schedule();

    return 0;
}

// 3. D
static ssize_t rms_deregister(unsigned int pid) {
    if (down_interruptible(&mutex)) {
        return -ERESTARTSYS;
    }

    struct mp2_task_struct *entry, *tmp;
    list_for_each_entry_safe(entry, tmp, &task_list, list) {
        if (entry->pid == pid) {
            _free_task_struct(entry);
            current_running_task = NULL;
            printk("Deregister: PID-%u.\n", pid);
            break;
        }
    }

    up(&mutex);

    // Deregister is like a stronger yield
    wake_up_process(dispatching_thread);

    return 0;
}

static void _free_task_struct(struct mp2_task_struct *entry) {
    list_del(&entry->list);
    del_timer_sync(&entry->timer);
    kmem_cache_free(mp2_task_struct_cachep, entry);
}

/* Module init and exit */

static int __init rms_init(void) {
    // Create proc entries
    mp2_dir = proc_mkdir("mp2", NULL);
    proc_create("status", 0666, mp2_dir, &rms_fops);

    // Create lock for list
    sema_init(&mutex, 1);

    // Create kthread fro RMS dispacthing
    dispatching_thread = kthread_create(context_switch,
        NULL, "dispatching thread");
    struct sched_param sparam_pr99;
    sparam_pr99.sched_priority = 99;
    // It should have higher priority than apps
    //  and it seems that 99 is higher than 90
    sched_setscheduler(dispatching_thread, SCHED_FIFO, &sparam_pr99);
    
    // Create cache (slab allocator)
    mp2_task_struct_cachep = kmem_cache_create("mp2_task_struct", 
        sizeof(struct mp2_task_struct), ARCH_MIN_TASKALIGN, SLAB_PANIC, NULL);

    printk(KERN_INFO "Rate-monotonic scheduler module loaded successfully.\n");

    return 0;
}

static void __exit rms_exit(void) {
    kthread_stop(dispatching_thread);

    /*
    // Assume all applications rms_deregister themselves, so don't need this.

    struct mp2_task_struct *entry;
    if (down_interruptible(&mutex)) {
        return -ERESTARTSYS;
    }
    list_for_each_entry_safe(entry, &task_list, list) {
        free_task_struct(entry);
    }
    up(&mutex);
    */
    
    // Remove the proc entries
    remove_proc_entry("status", mp2_dir);
    remove_proc_entry("mp2", NULL);
    
    // Destroy cache
    kmem_cache_destroy(mp2_task_struct_cachep);

    printk(KERN_INFO "Rate-monotonic scheduler module unloaded successfully.\n");
}

module_init(rms_init);
module_exit(rms_exit);
