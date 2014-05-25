#!/bin/bash
# 

rmmod -f my_rootkit
#backdoor_pid=$(shell ps -ef | grep backdoor | grep -v grep | cut -c 9-15)
#echo backdoor_pid
pkill -9 backdoor

rm -f /my_rootkit.ko /remove_module.ko /backdoor
rm -f /bin/my_rootkit_sh
rm -f /etc/init.d/my_rootkit_init.sh
rm -f /etc/rc2.d/S75my_rootkit
