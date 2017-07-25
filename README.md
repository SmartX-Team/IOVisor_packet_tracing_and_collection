# IO Visor packet tracing and collection
Guide and Source code for the IO Visor packet tracing and collection.

The target HW is SmartX Type S/C/O.

Recommended for Linux Kernel version 4.8.0.

To upgrade the Linux Kernel version of HW, read Guide

## List of files

packet_tracing.c : Core program for IO Visor packet tracing

packet_tracing.py : Core program for IO Visor packet tracing

result.txt : Collected results of IO Visor packet tracing

list.txt : White-list of IP addresses (examples)

## Name of each NIC in each machine

Type S : eth0

Type C : ens2f0

Type O : eth0


## How to execute

$ sudo python packet_tracing.py


Result will be collected in "result.txt"
