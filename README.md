# IO Visor packet tracing and collection
Guide and Source code for the IO Visor packet tracing and collection.

The target HW is SmartX Type S/C/O.

Recommended for Linux Kernel version 4.8.0.

To upgrade the Linux Kernel version of HW, read Guide

## List of files

packet_tracing.c

packet_tracing.py

result.txt

list.txt

## Name of each NIC in each machine

Type S : eth0
Type C : ens2f0
Type O : eth0


## How to execute

sudo python packet_tracing.py


Result will be collected in "result.txt"
