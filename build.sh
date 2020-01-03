#!/usr/bin/env bash
cd ./http-parser/
echo '----------compile http-parser'
make package
make clean
cd ./../libuv/
echo ''
echo '----------compile libuv'
sh autogen.sh
./configure
make
mv ./.libs/libuv.a ./../lib/Linux/
make clean
cd ./../nodecc/
echo ''
echo '----------compile nodecc'
make
echo ''
cd ./../out/Linux/
echo $(pwd)"/nodecc.out"
echo ''
echo '----------END----------'

