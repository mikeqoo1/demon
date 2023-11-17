#!/bin/sh

sudo passwd -u games
sudo usermod -s /bin/bash games
sudo passwd games

sudo usermod -aG wheel games
sudo usermod -aG utmp games
sudo usermod -aG mysql games
