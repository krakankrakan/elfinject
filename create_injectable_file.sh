#!/bin/sh
gcc -c $1 -o tmp
objcopy -O binary --only-section=.text tmp $2
rm tmp
