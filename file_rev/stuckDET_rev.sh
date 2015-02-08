#!/bin/bash

#  This Bash Shell tries solve the glitches when running
#  the simulation attack process. Specifically when jump
#  randomly in the libc area, the attack process can 
#  simply run into a infinite loop, which requires to kill
#  the process by force.

nomad=`cat libc`;
while true; do
pid=`pgrep -P $1 file`;
tstad=`cat libc`;
echo "Nomad:$nomad , Tstad:$tstad";
while (( $((16#$tstad)) > $((16#$nomad)) )); do
echo $nomad > libc;
sleep 1;
tstad=`cat libc`;
done;
nomad=`cat libc`;
sleep 4;
cpid=`pgrep -P $1 file`;
if [[ $pid -eq $cpid ]]; then
kill -9 $pid;
fi;
done;
