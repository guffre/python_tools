#!/usr/bin/env python2
import socket
import sys
import binascii
import struct

try:
    addr = sys.argv[1]
    port = int(sys.argv[2])
except:
    print("Usage: ./raw_tcp_recv.py <addr> <port>")
    print("./raw_tcp_recv.py 1.2.3.4 80")
    sys.exit(1)

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
except socket.error as e:
    print('Socket could not be created. Error: ' + str(e))
    sys.exit(2)

# receive a packet
received_data = b""
while True:
    packet = s.recvfrom(65535)
    packet = packet[0]
    ip_header = packet[0:20]
    iph = struct.unpack('!BBHHHBBH4s4s' , ip_header)

    version_ihl = iph[0]
    ihl = version_ihl & 0xF
    iph_length = ihl * 4

    s_addr = socket.inet_ntoa(iph[8]);
    if s_addr != addr:
        continue

    tcp_header = packet[iph_length:iph_length+20]
    tcph = struct.unpack('!HHLLBBHHH' , tcp_header)

    dest_port = tcph[1]
    if dest_port != port:
        continue
    if tcph[5] == 0x2:
        sequence = tcph[2]
        if sequence == 0xffffffff:
            break
        sequence= "%x" % sequence
        r = binascii.unhexlify('0'*(len(sequence)%2)+sequence)
        received_data += r

for n in received_data.split(b"\n"):
        print(n)
