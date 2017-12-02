#!/bin/bash
#sudo执行 更改参数 
gnome-terminal -x bash -c "ctsced -f -C . -c config-he-tcp;exec bash;" & 
sleep 1 
gnome-terminal -x bash -c "./aos-send 127.0.0.1;exec bash;" & 
sleep 1 
gnome-terminal -x bash -c "./pcap-ip eth0;exec bash;" &
