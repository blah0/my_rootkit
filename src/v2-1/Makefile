ifneq ($(KERNELRELEASE),)
	#EXTRA_CFLAGS += -DDEBUG
	obj-m += my_rootkit.o remove_module.o
else
	SRC_PWD := $(shell pwd)
	EXTRA_CFLAGS += -DDEBUG -D -I$(SRC_PWD)/
	KERNELDIR :=/lib/modules/$(shell uname -r)/build
	PWD	:= $(shell pwd)
all:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules
endif
clean:
	rm -f modules.order Module.symvers *.o *.ko *.mod.c .*.o.cmd .*.ko.cmd .*.mod.o.cmd
