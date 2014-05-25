#ifndef _MY_ROOTKIT_H_
#define _MY_ROOTKIT_H_

#ifdef DEBUG
#define my_rootkit_debug(fmt, args...) printk(KERN_DEBUG fmt, ##args)
#else
#define my_rootkit_debug(fmt, args...)
#endif

#endif
