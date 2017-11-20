#!/bin/bash
#sudo执行 更改参数
gnome-terminal -x bash -c "ctsced -f -C . -c config1;exec bash"
gnome-terminal -x bash -c "./aos 192.168.1.102;exec bash"
gnome-terminal -x bash -c "./pcap eth2;exec bash"