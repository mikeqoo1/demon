#!/bin/bash

# 設定 games 的密碼是 "Aa123456"
echo "games:Aa123456" | chpasswd

# 修改 games 的 shell 是 /bin/bash
sudo usermod -s /bin/bash games

# 修改群組
sudo usermod -aG wheel,utmp,mysql games

