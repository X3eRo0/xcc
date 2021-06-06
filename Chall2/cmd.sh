#!/bin/bash

rm -rf checks/*
rm -rf bins/*

python3 create.py > main.asm
~/xvm/cmake-build-debug/xasm -i ./main.asm ../../xlib/* ./bins/*.asm -o chall2.xvm

