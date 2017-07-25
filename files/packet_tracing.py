#!/usr/bin/python
#
#Bertrone Matteo - Polytechnic of Turin
#November 2015
#
#eBPF program http_filter is used as SOCKET_FILTER attached to eth0 interface.
#python script uses bcc BPF Compiler Collection by iovisor (https://github.com/iovisor/bcc)


from __future__ import print_function
from bcc import BPF
from datetime import datetime

import sys
import socket
import os
import argparse


# initialize BPF - load source code from http-parse-simple.c
bpf = BPF(src_file = "packet_tracing.c",debug = 0)

#load eBPF program http_filter of type SOCKET_FILTER into the kernel eBPF vm
#more info about eBPF program types
#http://man7.org/linux/man-pages/man2/bpf.2.html
function_http_filter = bpf.load_func("http_filter", BPF.SOCKET_FILTER)

#create raw socket, bind it to eth0
#attach bpf program to socket created
BPF.attach_raw_socket(function_http_filter, "ens2f0")

#get file descriptor of the socket previously created inside BPF.attach_raw_socket
socket_fd = function_http_filter.sock

#create python socket object, from the file descriptor
sock = socket.fromfd(socket_fd,socket.PF_PACKET,socket.SOCK_RAW,socket.IPPROTO_IP)
#set it as blocking socket
sock.setblocking(True)
print("ver         Src IP Addr     Port       Dst IP Addr     Port")

count_c1 = 0

while 1:
  #retrieve raw packet from socket
  packet_str = os.read(socket_fd,2048)

  #DEBUG - print raw packet in hex format
  #packet_hex = toHex(packet_str)
  #print ("%s" % packet_hex)

  #convert packet into bytearray
  packet_bytearray = bytearray(packet_str)
  
  #ethernet header length
  ETH_HLEN = 14 

  #IP HEADER
  #https://tools.ietf.org/html/rfc791
  # 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  # |Version|  IHL  |Type of Service|          Total Length         |
  # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  #
  #IHL : Internet Header Length is the length of the internet header 
  #value to multiply * 4 byte
  #e.g. IHL = 5 ; IP Header Length = 5 * 4 byte = 20 byte
  #
  #Total length: This 16-bit field defines the entire packet size, 
  #including header and data, in bytes.

  #calculate packet total length
  total_length = packet_bytearray[ETH_HLEN + 2]               #load MSB
  total_length = total_length << 8                            #shift MSB
  total_length = total_length + packet_bytearray[ETH_HLEN+3]  #add LSB
  
  #calculate ip header length
  ip_header_length = packet_bytearray[ETH_HLEN]               #load Byte
  ip_header_length = ip_header_length & 0x0F                  #mask bits 0..3
  ip_header_length = ip_header_length << 2                    #shift to obtain length

  #TCP HEADER 
  #https://www.rfc-editor.org/rfc/rfc793.txt
  #  12              13              14              15  
  #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
  # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  # |  Data |           |U|A|P|R|S|F|                               |
  # | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
  # |       |           |G|K|H|T|N|N|                               |
  # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  #
  #Data Offset: This indicates where the data begins.  
  #The TCP header is an integral number of 32 bits long.
  #value to multiply * 4 byte
  #e.g. DataOffset = 5 ; TCP Header Length = 5 * 4 byte = 20 byte

  #calculate tcp header length
  tcp_header_length = packet_bytearray[ETH_HLEN + ip_header_length + 12]  #load Byte
  tcp_header_length = tcp_header_length & 0xF0                            #mask bit 4..7
  tcp_header_length = tcp_header_length >> 2                              #SHR 4 ; SHL 2 -> SHR 2
  
  #calculate payload offset
  payload_offset = ETH_HLEN + ip_header_length + tcp_header_length
  

  #line ends with 0xOD 0xOA (\r\n)


  #parsing ip version from ip packet header
  ipversion = str(bin(packet_bytearray[14])[2:5])

  #parsing source ip address, destination ip address from ip packet header
  srcAddr = str(packet_bytearray[26]) + "." + str(packet_bytearray[27]) + "." + str(packet_bytearray[28]) + "." + str(packet_bytearray[29])
  dstAddr = str(packet_bytearray[30]) + "." + str(packet_bytearray[31]) + "." + str(packet_bytearray[32]) + "." + str(packet_bytearray[33])
  
  srcPort = str(int(str(bin(packet_bytearray[36])[2:]),2))
  dstPort = str(int(str(bin(packet_bytearray[37])[2:]),2))
  
  action = ""
  for i in range (payload_offset-1,len(packet_bytearray)-1):
    if (packet_bytearray[i]== 0x0A):
      if (packet_bytearray[i-1] == 0x0D):
        break
    action += chr(packet_bytearray[i])

  #print information including ipVer/srcAddr/dstAddr:port/action
  print("%3s%20s%9s%20s%9s" % (str(int(ipversion, 2)), srcAddr, srcPort, dstAddr, dstPort))
  f = open("result.txt", "a")
  f.write("%20s%3s%20s%20s%9s\n" % (datetime.now(),str(int(ipversion, 2)), srcAddr, dstAddr, dstPort))
  f.close
  
"""
# list.txt has the white-list of IP addresses

  f = open("list.txt", "r")
  ip_list = f.readlines()

  if any(srcAddr not in s for s in ip_list):
        print("Suspicious IP detected")
        print(datetime.now())
        f = open("result.txt", "a")
        f.write("%20s%3s%20s%20s%9s\n" % (datetime.now(),str(int(ipversion, 2)), srcAddr, dstAddr, dstPort)
        f.close


  if any(dstAddr not in s for s in ip_list):
        print("Suspicious IP detected")
        print(datetime.now())
        f = open("result.txt", "a")
        f.write("%20s%3s%20s%20s%9s\n" % (datetime.now(),str(int(ipversion, 2)), srcAddr, dstAddr, dstPort)
        f.close
"""
