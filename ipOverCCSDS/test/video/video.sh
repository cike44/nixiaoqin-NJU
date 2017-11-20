#!/bin/bash
#ffmpeg -s 640*480  -i /dev/video0   -vcodec h264  -tune:v zerolatency -preset:v ultrafast -b 600k -f h264 udp://192.168.1.103:5005 -vcodec h264  -tune:v zerolatency -preset:v ultrafast -b 600k -f h264 udp://127.0.0.1:5012
ffmpeg -s 640*480  -i /dev/video0   -vcodec h264  -tune:v zerolatency -preset:v ultrafast -b 600k -f h264 udp://127.0.0.1:5002
ffplay -vcodec h264 udp://127.0.0.1:5002