#!/bin/bash
sudo ctsced -f -C . -c config1
./aos 192.168.1.102
sudo ./pcap eth2
