#!/bin/bash
# ./my_rootkit_uninstall.sh 

# kill the process of backdoor
#backdoor_pid=$(ps -ef | grep backdoor | grep -v grep | cut -c 9-15)
#echo ${backdoor_pid}
pkill -9 backdoor

# delete the modules and execute file of backdoor
rm -f /my_rootkit.ko /remove_module.ko /backdoor /exec_my_rootkit.sh
# delete the sysmbol link of /bin/bash
rm -f /bin/my_rootkit_sh
# delete the auto-start shell script
rm -f /etc/init.d/my_rootkit_init.sh
# delete the link of auto-start shell script
rm -f /etc/rc2.d/S75my_rootkit
