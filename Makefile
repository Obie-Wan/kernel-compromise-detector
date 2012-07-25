name := kcd
obj-m += $(name).o
$(name)-objs := checks/nf_check.o main.o mem.o

KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

default:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules
	@echo "  Now you can type 'make detect' to start checking"
	@echo "  And 'make unhide' to unhide them"
	@echo "  Use dmesg to grab results"

detect:
	@echo "  Checking for hidden modules ..."
	@insmod $(name).ko
	@rmmod $(name).ko

unhide:
	@echo "  Unhiding hidden modules ..."
	@insmod $(name).ko unhide=1
	@rmmod $(name).ko

clean:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) clean
