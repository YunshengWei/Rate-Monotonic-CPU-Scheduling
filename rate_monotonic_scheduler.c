#include <linux/fs.h>
#include <linux/init.h>
#include <linux/jiffies.h> // jiffies
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
#include <linux/sched.h>
#include <linux/semaphore.h> // semaphore
#include <asm/uaccess.h>
#include "mp2_given.h"

#define PROCFS_MAX_SIZE 1024
// #define set_task_state(task, state) task->state = state

MODULE_AUTHOR("Yunsheng Wei; Juanli Shen; Funing Xu; Wei Yang");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Rate-Monotonic Scheduler");

/* global variables */
static const char delimiters[] = ",";
static struct proc_dir_entry *mp2_dir;
static unsigned long procfs_buffer_size = 0;
static char procfs_buffer[PROCFS_MAX_SIZE];
static struct task_struct *dispatching_thread;
static struct mp2_task_struct* current_running_thread; // global running task
static struct semaphore sem; // semaphore mutex
LIST_HEAD(task_list);
enum task_state { RUNNING, READY, SLEEPING };
static void free_task_struct(struct mp2_task_struct *entry);
static ssize_t deregister(unsigned int pid);
static ssize_t rms_write(struct file *file, const char __user *buffer, size_t count, loff_t *data);

/* function and struct declaration */
struct mp2_task_struct;
int context_switch(void *data);
static int rms_show(struct seq_file *file, void *v);
static int rms_open(struct inode *inode, struct file *file);
static bool pass_admission_control(unsigned int pid, unsigned long period, unsigned long processing_time);
static void wakeup_timer_callback(unsigned long data);
static ssize_t __register(unsigned int pid, unsigned long period, unsigned long processing_time);
static ssize_t __yield(unsigned int pid);


// augment PCB
struct mp2_task_struct 
{
    struct task_struct *task; // PCB
    struct list_head list;
    struct timer_list timer;

    enum task_state state;
    unsigned int pid;
    unsigned long period;
    unsigned long processing_time;
    unsigned long next_period;
};


// show all jobs: pid, period, processing time
static int rms_show(struct seq_file *file, void *v) {
    
    printk(KERN_INFO "calling rms_show ...\n");
    // CS
    if (down_interruptible(&sem)) {
        return -ERESTARTSYS;
    }
    struct mp2_task_struct *entry;
    list_for_each_entry(entry, &task_list, list) 
    {
        seq_printf(file, "%u, %lu, %lu\n", 
            entry->pid, entry->period, entry->processing_time);
    }
    up(&sem);

    return 0;
}

static int rms_open(struct inode *inode, struct file *file) {
    printk(KERN_INFO "calling rms_open ...\n");
    return single_open(file, rms_show, NULL);
}

// pass_admission_control should only be called when holding mutex
static bool pass_admission_control(unsigned int pid, unsigned long period, unsigned long processing_time) 
{
    printk(KERN_INFO "calling pass_admission_control ...\n");
    unsigned long sum = 0;

    struct mp2_task_struct *entry;
    list_for_each_entry(entry, &task_list, list) 
    {
        sum += entry->processing_time * 1000 / entry->period + 1;
    }
    sum += processing_time * 1000 / period + 1;

    if (sum <= 693) {
        return true;
    }
    
    return false;
}

// context_switch
int context_switch(void *data) 
{
    printk(KERN_INFO "calling context_switch ...\n");
    struct sched_param* sparam_pr99 = (struct sched_param*)kmalloc(sizeof(struct sched_param),GFP_KERNEL);
    sparam_pr99->sched_priority = 99;
    struct sched_param* sparam_pr0 = (struct sched_param*)kmalloc(sizeof(struct sched_param),GFP_KERNEL);
    sparam_pr0->sched_priority = 0;

    // while kthread not return
    while (!kthread_should_stop()) 
    {       
        struct mp2_task_struct *highest_priority_task = NULL;
        unsigned long min_period = ULONG_MAX;

        // CS
        if (down_interruptible(&sem)) {
            return -ERESTARTSYS;
        }

        // This can avoid missing wakeup?
        // Need proof.
        // set_current_state(TASK_UNINTERRUPTIBLE); // cur job will be moved off the run queue and goes to sleep

        // find the job with min period (max priority)
        struct mp2_task_struct *entry;
        list_for_each_entry(entry, &task_list, list) 
        {
            if (entry->period < min_period && entry->state == READY) 
            {
                min_period = entry->period;
                // update max priority task
                highest_priority_task = entry;
            }
        }
        
        // if cur job is running and it is not the one with max priority
        if (current_running_thread->pid != highest_priority_task->pid) 
        {
            // cur job state might not be running as it can finish earlier and become READY, so both of READY and RUNNING are possible
            if (current_running_thread->state != SLEEPING)
            {
                current_running_thread->state = READY;
            }
            // set cur job priority to be 0, policy = normal, this ensures cur job will not run even it wakes up
            sched_setscheduler(current_running_thread->task, SCHED_NORMAL, sparam_pr0);
            // wakes up sleeping task with TASK_UNINTERRUPTIBLE
            // wake_up_process(highest_priority_task->task);

            // schedule max priority job
            sched_setscheduler(highest_priority_task->task, SCHED_FIFO, sparam_pr99);
            // update cur job = max priority job
            current_running_thread = highest_priority_task;
            highest_priority_task->state = RUNNING;
        }
        up(&sem);
        // sleep cur job
        // schedule();
    }

    kfree(sparam_pr99);
    kfree(sparam_pr0);
    return 0;
}

// call back function when timer expires
static void wakeup_timer_callback(unsigned long data) 
{
    printk(KERN_INFO "calling wakeup_timer_callback ...\n");
    struct mp2_task_struct *entry = (struct mp2_task_struct *) data;
    // CS
    down_interruptible(&sem);
    // wake up job
    wake_up_process(entry->task);
    // set wake job state to ready
    entry->state = READY;
    up(&sem);
    // do context switch
    wake_up_process(dispatching_thread);
    set_task_state(dispatching_thread, TASK_UNINTERRUPTIBLE);
    schedule();
}

// register job
static ssize_t __register(unsigned int pid, unsigned long period, unsigned long processing_time)
{
    printk(KERN_INFO "calling register ...\n");
    // CS
    if (down_interruptible(&sem)) {
        return -ERESTARTSYS;
    }
    // new job need to pass adm control
    if (pass_admission_control(pid, period, processing_time)) 
    {
        // init mp2_task_struct
        struct mp2_task_struct *entry = (struct mp2_task_struct*)kmalloc(sizeof(struct mp2_task_struct), GFP_KERNEL);
        entry->pid = pid;
        entry->period = period;
        entry->processing_time = processing_time;
        entry->task = find_task_by_pid(pid);
        // init to sleeping state
        entry->state = SLEEPING;
        // set next_period to cur time
        entry->next_period = jiffies;
        // init timer
        setup_timer(&entry->timer, wakeup_timer_callback, (unsigned long) entry);
        list_add(&entry->list, &task_list);
    }
    up(&sem);

    return 0;
}

// yield, block a job
static ssize_t __yield(unsigned int pid) 
{
    printk(KERN_INFO "calling yield ...\n");
    struct mp2_task_struct *entry;

    // CS
    if (down_interruptible(&sem)) {
        return -ERESTARTSYS;
    }
    list_for_each_entry(entry, &task_list, list) 
    {
        // find job matches pid
        if (entry->pid == pid) 
        {
            current_running_thread = NULL;

            entry->next_period += msecs_to_jiffies(entry->period);
            // update timer
            mod_timer(&entry->timer, entry->next_period);

            printk(KERN_INFO "Yield process %u.\n", pid);
            break; // exit for loop
        }
    }
    // set yield job to sleep
    entry->state = SLEEPING;
    // sleep yield job
    set_task_state(entry->task, TASK_UNINTERRUPTIBLE);
    schedule();
    up(&sem);
    // wake up dispatching thread to context switch to select the max priority job to run
    wake_up_process(dispatching_thread);
    // sleep dispatching_thread
    set_task_state(dispatching_thread, TASK_UNINTERRUPTIBLE);
    schedule();

    return 0;
}

// free task struct
static void free_task_struct(struct mp2_task_struct *entry) 
{
    list_del(&entry->list);
    del_timer(&entry->timer);
    kfree(entry);
}

// deregister job
static ssize_t deregister(unsigned int pid) 
{ 
    printk(KERN_INFO "calling deregister ...\n");
    
    // CS
    if (down_interruptible(&sem)) {
        return -ERESTARTSYS;
    }
    // delete a job's task from list
    struct mp2_task_struct *entry;
    list_for_each_entry(entry, &task_list, list) 
    {
        if (entry->pid == pid) 
        {
            free_task_struct(entry);
            break;
        }
    }
    up(&sem);

    return 0;
}

// app call module
static ssize_t rms_write(struct file *file, const char __user *buffer, size_t count, loff_t *data) 
{    
    printk(KERN_INFO "calling rms_write ...\n");
    procfs_buffer_size = count;
    if (procfs_buffer_size > PROCFS_MAX_SIZE) 
    {
        procfs_buffer_size = PROCFS_MAX_SIZE;
    }

    if (copy_from_user(procfs_buffer, buffer, procfs_buffer_size)) 
    {
        return -EFAULT;
    }

    char *running;
    char instr = *strsep(&running, delimiters);
    unsigned int pid;
    kstrtouint(strsep(&running, delimiters), 0, &pid);
    ssize_t error_code = 0; // init error_code
    unsigned long period;
    unsigned long process_time;
    // action: Register, Yield, Deregister
    switch (instr) 
    {
        case 'R' :
            kstrtoul(strsep(&running, delimiters), 0, &period);
            kstrtoul(strsep(&running, delimiters), 0, &process_time);
            error_code = __register(pid, period, process_time);
            break;
        case 'Y' :
            error_code = __yield(pid);
            break;
        case 'D':
            error_code = deregister(pid);
            break;
    }

    if (error_code) {
        return error_code;
    }
        
    return procfs_buffer_size;
}

static const struct file_operations rms_fops = {
    .owner = THIS_MODULE,
    .open = rms_open,
    .read = seq_read,
    .write = rms_write, // app call module
    .llseek = seq_lseek,
    .release = single_release,
};

// init module
static int __init rms_init(void) 
{
    printk(KERN_INFO "Loading rate-monotonic scheduler module ...\n");

    // create proc dir and file
    mp2_dir = proc_mkdir("mp2", NULL);
    proc_create("status", 0666, mp2_dir, &rms_fops);

    // init dispatching thread
    dispatching_thread = kthread_create(context_switch, NULL, "dispatching thread");
    // struct sched_param sparam;
    // put dispatching_thread to sleep
    set_task_state(dispatching_thread, TASK_UNINTERRUPTIBLE);
    schedule();
    // SCHED_FIFO min/max priority : 1/99
    // sparam.sched_priority = 98; // will context switch able to run if its priority is always lower than cur job?
    // sched_setscheduler(dispatching_thread, SCHED_FIFO, &sparam);

    // init semaphore
    sema_init(&sem,1);

    printk(KERN_INFO "rate-monotonic scheduler module loaded.\n");

    return 0;
}

// exit module
static void __exit rms_exit(void) 
{
    // stop dispatching thread
    kthread_stop(dispatching_thread);

    // free task struct list
    struct mp2_task_struct *entry;
    list_for_each_entry(entry, &task_list, list) 
    {
        free_task_struct(entry);
    }

    // remove proc files
    remove_proc_entry("status", mp2_dir);
    remove_proc_entry("mp2", NULL);

    printk(KERN_INFO "Rate-monotonic scheduler module removed successfully.\n");
}


module_init(rms_init);
module_exit(rms_exit);
