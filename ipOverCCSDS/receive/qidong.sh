#!/bin/bash
#sudo执行 更改参数
gnome-terminal -x bash -c "sudo ctsced -f -C . -c config-he-tcp;exec bash;" & 
sleep 1 
gnome-terminal -x bash -c "./aos-recv 127.0.0.1;exec bash;" & 
sleep 1 
gnome-terminal -x bash -c "sudo ./libnet eth0;exec bash;" &
