#!/bin/bash

sudo ctsced -f -C . -c config1
./aos 192.168.10.102
sudo ./libnet eth1