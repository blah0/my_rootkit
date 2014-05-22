#define my_rootkit_debug(fmt, args...) printk(fmt, ##args)
/* ioctl stuff */
#define HACKED_CMD 0xfffffffe
#define HIDE_FILE 0x1
#define UNHIDE_FILE 0x2

#ifdef DEBUG
#ifdef __KERNEL__
#define my_rootkit_debug(fmt, args...) printk(fmt, ##args)
#else
//#define my_rootkit_debug(fmt, args...) fprintf(stderr, fmt, ##args)
#endif
#else
//#define my_rootkit_debug(fmt, args...)
#endif
