#!/usr/bin/env python2
import sys
import socket
import struct
import binascii
import time

from threading import Thread
source_ips = dict()

def get_source_ip(dst_ip):
    #Credit: 131264/alexander from stackoverflow. This gets the correct IP for sending. Useful if you have multiple interfaces
    global source_ips
    print(dst_ip)
    if dst_ip in source_ips:
        return source_ips[dst_ip]
    else:
        source_ips[dst_ip] = [(s.connect((dst_ip, 53)), s.getsockname()[0], s.close()) for s in [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]][0][1]
        print(source_ips)
        return source_ips[dst_ip]

def handshake_completer():
    #Raw socket listener for when send_raw_syn() is used. This will catch return SYN-ACKs
    listen = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    ips_of_interest = [ip]
    ports = [port]
    sys.stdout.write("Starting Listener\n")
    while True:
        #packet = ('E \x00(\x1f\xaa@\x00w\x06\x99w2\xe0\xc8\xa2\xa2\xf3\xac\x18\xdf\xb3\x00\x16\xb6\x80\xc1\xa0/\xa6=$P\x10\xce\xab\xd1\xe4\x00\x00', ('50.XXX.200.162', 0))
        raw_packet = listen.recvfrom(65565)
        #Now we need to unpack the packet. It will be an IP/TCP packet
        #We are looking for SYN-ACKs from our SYN scan
        #Fields to check: IP - src addr; TCP - src port, flags
        #We want to pull out and compare only these three
        #Heres the math for unpacking: B=1, H=2, L=4, 4s=4  (those are bytes)
        packet = raw_packet[0]
        ip_header = struct.unpack('!BBHHHBBH4s',packet[0:16]) #This is the IP header, not including any options OR THE DST ADDR. Normal length is 20, Im parsing as little as possible
        ip_header_length = (ip_header[0] & 0xf) * 4         #If there are any options, the length of the IP header will be >20. We dont care about options
        src_addr = socket.inet_ntoa(ip_header[8])           #This is the source address (position 8, or the first "4s" in our unpack)
        
        tcp_header_raw = packet[ip_header_length:ip_header_length+14]   #We had to get the proper IP Header length to find the TCP header offset.
        tcp_header = struct.unpack('!HHLLBB',tcp_header_raw)            #TCP header structure is pretty straight-forward. We want PORTS and FLAGS, so we partial unpack it
        
        src_port = tcp_header[0]    #self-explanatory
        dst_port = tcp_header[1]    #self-explanatory
        sequence = tcp_header[2]
        acknowledgement = tcp_header[3]
        flag = tcp_header[5]        #We only care about syn-ack and fin-ack, which will be 18 (0x12) and 17 (0x11) respectively
        
        if src_addr in ips_of_interest and src_port in ports:
            dst_ip = src_addr
            sys.stdout.write("[recv]\t{}:{}\tseq: {} ack: {}\n".format(src_addr,src_port,sequence,acknowledgement))
            # Received SYN-ACK
            # Send: ACK
            # Send: FIN-ACK
            ack_num = (sequence+1)%0x100000000
            if flag == 0x12:
                sys.stdout.write("[recv-syn-ack] sending ACK, FIN-ACK\n")
                send_raw_tcp(dst_ip,src_port=dst_port,dst_port=src_port,seq_num=acknowledgement,ack_num=ack_num,data_offset=0x50,fin=0,syn=0,rst=0,psh=0,ack=1,urg=0,window=5840,check=0,urg_ptr=0)
                send_raw_tcp(dst_ip,src_port=dst_port,dst_port=src_port,seq_num=acknowledgement,ack_num=ack_num,data_offset=0x50,fin=1,syn=0,rst=0,psh=0,ack=1,urg=0,window=5840,check=0,urg_ptr=0)
            # Received FIN-ACK
            # Send: ACK
            if flag == 0x11:
                sys.stdout.write("[recv-fin-ack] sending ACK\n")
                send_raw_tcp(dst_ip,src_port=dst_port,dst_port=src_port,seq_num=acknowledgement,ack_num=ack_num,data_offset=0x50,fin=0,syn=0,rst=0,psh=0,ack=1,urg=0,window=5840,check=0,urg_ptr=0)

class TCPHeader():
    #TCP header class. Thanks to Silver Moon for the flags calculation and packing order
    #This was designed to be re-used. You might want to randomize the seq number
    #get_struct performs packing based on if you have a valid checksum or not
    def __init__(self,src_port=0,dst_port=0,seq_num=0,ack_num=0,data_offset=0x50,fin=0,syn=0,rst=0,psh=0,ack=0,urg=0,window=5840,check=0,urg_ptr=0):
        self.order = "!HHLLBBHHH" #!=network(big-endian), H=short(2), L=long(4),B=char(1)
        self.src_port = src_port
        self.dst_port = dst_port
        self.seq_num = seq_num
        self.ack_num = ack_num
        self.data_offset = data_offset #size of tcp header; size is specified by 4-byte words; This is 80 decimal, which is 0x50, which is 20bytes (5words*4bytes).
        self.fin = fin
        self.syn = syn
        self.rst = rst
        self.psh = psh
        self.ack = ack
        self.urg = urg
        self.window = socket.htons(window)
        self.check = check
        self.urg_ptr = urg_ptr
        self.header = self.get_struct()
        
    def flags(self):
        return self.fin + (self.syn << 1) + (self.rst << 2) + (self.psh <<3) + (self.ack << 4) + (self.urg << 5)
    
    def get_struct(self,check=False,checksummed=False):
        if check != False: self.check = check
        if checksummed:
            return struct.pack('!HHLLBBH',self.src_port,self.dst_port,self.seq_num,self.ack_num,self.data_offset,self.flags(),self.window)+struct.pack('H',self.check)+struct.pack('!H',self.urg_ptr)
        else:
            return struct.pack(self.order,self.src_port,self.dst_port,self.seq_num,self.ack_num,self.data_offset,self.flags(),self.window,self.check,self.urg_ptr)
    
    def tcp_checksum(self,src_ip,dst_ip,tcp_header,tcp_body=''):
        # Calculates the correct checksum for the tcp header
        # Checksum is calculated as: Pseudo-IP Header + TCP Header + TCP data
        tcp_length = len(tcp_header) + len(tcp_body)
        ip_header = struct.pack('!4s4sBBH',socket.inet_aton(src_ip),socket.inet_aton(dst_ip),0,socket.IPPROTO_TCP,tcp_length)
        msg = ip_header + tcp_header + tcp_body
        
        #Shoutout to Silver Moon @ binarytides for this checksum algo.
        sum = 0
        for i in range(0,len(msg),2):
            w = ord(msg[i]) + (ord(msg[i+1]) << 8 )
            sum = sum + w
        
        sum = (sum>>16) + (sum & 0xffff)
        sum = sum + (sum >> 16)
        sum = ~sum & 0xffff
        return sum
    
    def make_packet(self, src_ip, dst_ip):
        tcp_header = self.get_struct()
        packet = self.get_struct(check=self.tcp_checksum(src_ip,dst_ip,tcp_header),checksummed=True)
        return packet

def send_raw_tcp(dst_ip,src_port=0,dst_port=0,seq_num=0,ack_num=0,data_offset=0x50,fin=0,syn=0,rst=0,psh=0,ack=0,urg=0,window=5840,check=0,urg_ptr=0):
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    src_ip = get_source_ip(dst_ip)
    tcp_header = TCPHeader(src_port,dst_port,seq_num,ack_num,data_offset,fin,syn,rst,psh,ack,urg,window,check,urg_ptr)
    packet = tcp_header.make_packet(src_ip, dst_ip)
    s.sendto(packet,(dst_ip,0))
    sys.stdout.write("[sent] RAW packet {} {} {}\n".format(dst_ip,dst_port,seq_num))

def send_data(dst_ip, dst_port, data="",src_port=54321):
    time.sleep(0.2)
    for i in range(0, len(data), 4):
        chunk = data[i:i+4]
        seq_num = int(binascii.hexlify(chunk),16)
        send_raw_tcp(dst_ip, dst_port=dst_port, src_port=src_port, seq_num=seq_num, syn=1)
        time.sleep(0.02)
        src_port = max(30000,((src_port+1)%65535))
    seq_num = int(binascii.hexlify("\xff\xff\xff\xff"),16)
    send_raw_tcp(dst_ip, dst_port=dst_port, src_port=src_port, seq_num=seq_num, syn=1)
    time.sleep(1)

if __name__ == '__main__':
    data = ''
    if not sys.stdin.isatty():
        for line in sys.stdin:
            data += line
    
    try:
        ip = sys.argv[1]
        port = int(sys.argv[2])
        data += ' '.join(sys.argv[3:])
    except Exception:
        print("Usage: ./raw_tcp_send <ip> <port> <data>")
        sys.exit(1)
    
    listen_thread = Thread(target=handshake_completer)
    listen_thread.setDaemon(True)
    listen_thread.start()
    print(data)
    send_data(ip, port, data)