##########################################
# Makefile (!not makefile)
ifneq ($(KERNELRELEASE),)
obj-m       := jiffies.o
else
KDIR        := /lib/modules/`uname -r`/build
PWD         := $(shell pwd)
default:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) clean
endif
