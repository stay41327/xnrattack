#!/bin/bash

#  This Bash Shell tries solve the glitches when running
#  the simulation attack process, specifically when jump
#  randomly in the libc area, the attack process can 
#  simply run into a infinite loop, which requires to kill
#  the process by force.

while true; do
pid=`pgrep -P $1 file`;
sleep 4;
cpid=`pgrep -P $1 file`;
if [[ $pid -eq $cpid ]]; then
kill -9 $pid;
fi;
done;
