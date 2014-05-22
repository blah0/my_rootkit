ifneq ($(KERNELRELEASE),)
	obj-m := my_rootkit.o
else
	SRC_PWD := $(shell pwd)
	EXTRA_CFLAGS += -DDEBUG -D__KERNEL__ -I$(SRC_PWD)/
	KERNELDIR :=/lib/modules/$(shell uname -r)/build
	PWD	:= $(shell pwd)
all:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules
endif
clean:
	rm -f *.o *.ko *.mod.c
