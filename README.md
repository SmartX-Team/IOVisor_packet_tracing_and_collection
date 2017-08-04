# IO Visor packet tracing and collection

This document is about a tool for tracing packets at the kernel level through the Network Interface Card for Linux OS boxes based on the IO Visor project, one of the Linux Foundation's open source project.
Using the tools provided by the following IO Visor BCC (BPF Compiler Collection), it is possible to implement programs that utilize various kernel level IOs.

## About IO Visor Project

![](https://github.com/SmartX-Team/IOVisor_packet_tracing_and_collection/blob/master/io_visor.png)

The IO Visor Project is an open source project and a community of developers to accelerate the innovation, development, and sharing of virtualized in-kernel IO services for tracing, analytics, monitoring, security and networking functions. It builds on the Linux community to bring open, flexible, distributed, secure and easy to operate technologies that enable any stack to run efficiently on any physical infrastructure.

https://www.iovisor.org/

>>>

# Guide for IO Visor Packet Tracing and Collection

Guide and Source code for the IO Visor packet tracing and collection.

The target HW is SmartX Type S/C/O, and others.

Recommended for Linux Kernel version 4.8.0.

To upgrade the Linux Kernel version of HW and build IO Visor environment, read [Guide](https://github.com/SmartX-Team/IOVisor_packet_tracing_and_collection/blob/master/Guide%20for%20IO%20Visor%20Environment.pdf)

## Requirements

The following IO Visor packet tracing can be executed with the IO Visor BCC enabled environment.

Construction of the IO Visor BCC environment is possible through IO Visor BCC Github page.

https://github.com/iovisor/bcc

This program is optimized for Linux Kernel 4.8.0 environment and Ubuntu 16.04 LTS version.

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
