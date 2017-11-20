#!/bin/bash
gcc -o pcap-ip pcap-ip.c -lpcap
g++ -std=c++11 -o aos-send aos-send.cpp
