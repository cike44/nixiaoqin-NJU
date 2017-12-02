#!/bin/bash
gcc -o libnet libnet.c -lnet
g++ -std=c++11 -o aos-recv aos-recv.cpp
