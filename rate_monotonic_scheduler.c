#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>

static struct proc_dir_entry *mp2_dir;

static int rms_show(struct seq_file *m, void *v) {
    return 0;
}

static int rms_open(struct inode *inode, struct file *file) {
    return single_open(file, rms_show, NULL);
}

static ssize_t rms_write(struct file *file, const char __user *buffer, size_t count, loff_t *data) {
    return 0;
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

    return 0;
}

static void __exit rms_exit(void) {

    remove_proc_entry("status", mp2_dir);
    remove_proc_entry("mp2", NULL);

    printk(KERN_INFO "Unloading rate-monotonic scheduler module.\n");
}


module_init(rms_init);
module_exit(rms_exit);
MODULE_LICENSE("GPL");