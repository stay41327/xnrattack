# xnrattack
This project is to demonstrate how to break the slinding-window based XnR (SW-XnR) technique.

This git contains the following files
- file/
- file_2/
- file_rev/
- log_libc-2.15_call
- log_libc-2.15_ret
- log_libc-2.15_potential_ret
- log_libc-2.15_jmp

file/
file_2/
file_rev/
These directories contain the POC Simulation to attack XnR.

log_*
These log files calculates the number of certain op-codes every 4k bytes( 1 page ) in libc-2.15.
log_libc-2.15_call ==> call command
log_libc-2.15_ret  ==> ret  command
log_libc-2.15_potential_ret ==> c2 & c3 op-code
log_libc-2.15_jmp  ==> jump command