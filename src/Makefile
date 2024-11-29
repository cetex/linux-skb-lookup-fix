
obj-m += livepatch-skb-lookup-fix.o

mkfile_path := $(abspath $(lastword $(MAKEFILE_LIST)))
mkfile_dir := $(dir $(mkfile_path))

.PHONY: build
build:
	make -C /lib/modules/$(shell uname -r)/build M=$(mkfile_dir) modules

.PHONY: clean
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(mkfile_dir) clean

.PHONY: sign
sign:
	kmodsign sha512 /var/lib/shim-signed/mok/MOK.priv /var/lib/shim-signed/mok/MOK.der *.ko

/sys/kerne/livepatch/livepatch_skb_lookup_fix/enabled:
	insmod livepatch-skb-lookup-fix.ko

.PHONY: load
load: /sys/kerne/livepatch/livepatch_skb_lookup_fix/enabled

.PHONY: unload
unload:
	echo 0 > /sys/kernel/livepatch/livepatch_skb_lookup_fix/enabled
	rmmod livepatch_skb_lookup_fix

.PHONY: sign_load
sign_load: sign load
all: unload clean build sign load
