#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
    
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <asm/uaccess.h>

#define PROCFS_NAME    "jiffies"
ssize_t procfile_read(struct file *file,
                      char *buffer,
                      size_t count,
                      loff_t *f_pos)
{
    int len;

    len = sprintf(buffer, "%ld\n",
                 jiffies);

    return len;
}

struct file_operations fops = {
    owner:  THIS_MODULE,
    read:   procfile_read,
};

static struct proc_dir_entry *myprocfile;
int init_module()
{
    /*  create the /proc file */

    myprocfile = 
    proc_create(PROCFS_NAME, 0666, NULL, &fops);

    if (myprocfile == NULL) {   /*  create fail */
        remove_proc_entry(PROCFS_NAME, myprocfile);
        printk(KERN_ALERT "Error: Could not initialize /proc/%s\n",
                 PROCFS_NAME);
        return -ENOMEM;
    }

    printk(KERN_INFO "/proc/%s created\n", PROCFS_NAME);
    return 0;   /*  everything is ok */
}

void cleanup_module()
{
    remove_proc_entry(PROCFS_NAME, NULL);
}
