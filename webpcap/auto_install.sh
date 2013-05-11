#!/bin/bash
# A very ugly script to quickly download & compile lighttpd with mod_websocket.
# This assumes you have installed the dependencies for both.
#
# Note: If you don't use sudo, comment the last line and run make install as root.

git clone git://github.com/nori0428/mod_websocket.git
wget http://download.lighttpd.net/lighttpd/releases-1.4.x/lighttpd-1.4.32.tar.gz
tar xvf ./lighttpd-1.4.32.tar.gz

cd ./mod_websocket
./bootstrap
./configure --with-websocket=RFC-6455 --with-test
make clean check

./bootstrap
./configure --with-lighttpd=../lighttpd-1.4.32
make install

cd ../lighttpd-1.4.32
./autogen.sh
./configure --with-websocket=RFC-6455
make
sudo make install