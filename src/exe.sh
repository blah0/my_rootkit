#!/bin/bash
# source exe.sh

cd v2-1/
make clean
rm -f *~
cd ../

tar -zcf my_rootkit.tar.gz v2-1/
mv my_rootkit.tar.gz ../bin/

cd ../bin/

