#!/usr/bin/python
#Will operate under cygwin, windows, and linux environments.
#Tested in 2.6 and 2.7
#Cygwin/Windows might not be able to perform syn-scan due to use of raw sockets
import os, subprocess, sys, socket, itertools
from threading import Thread
from threading import active_count
from Queue import Queue
from optparse import OptionParser
from struct import *
from time import sleep

source_ips = {}
try:
    ips = sys.argv[1]
except Exception:
    print("IP must be first argument")
    sys.exit(1)

devnull = open(os.devnull,'w')
ip_queue = Queue()
socket_queue = Queue()
parser = OptionParser()
parser.add_option("-t", "--threads", type="int", dest="threads", default=64, help="Set number of threads")
parser.add_option("--timeout", type="int", dest="timeout", default=5, help="Set timeout value (for ping and TCP)")
parser.add_option("-s", type="string", dest="scan_type", default="T", help="Set the scan type\n\tT = TCP full connect\n\tS = TCP Syn Scan")
parser.add_option("--ping","--ping-scan", action="store_true", dest="ping_only",default=False, help="Perform a ping-only scan")
parser.add_option("-P", type="string",dest="ping", default="y",help="Use -PN or -Pn to skip pinging targets")
parser.add_option("-p","--ports",type="string",dest="ports", help="Ports to scan. Format is comma separated, and accepts ranges with a \"-\"")
parser.add_option("--source",type="string",dest="source",default="auto", help="Optional. Set a source IP if using -sS option. Skips sending UDP packets to auto-determine source IP")
parser.add_option("-v","--verbose",action="store_true",dest="verbose",default=False, help="Verbose output (for debugging)")
parser.add_option("--example",help="Example usage: ./scan 192.168.0-10.0-255 -sS -Pn -p 20-80,400-500\n./scan 1.1.1.1 --ping --threads 1 --timeout 10")
options,args = parser.parse_args()
print(options)

def tcp_listener():
    #Raw socket listener for when send_raw_syn() is used. This will catch return SYN-ACKs
    listen = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    ips_of_interest = [n for n in convert_ips(ips)]
    print("Starting Listener")
    while True:
        #packet = ('E \x00(\x1f\xaa@\x00w\x06\x99w2\xe0\xc8\xa2\xa2\xf3\xac\x18\xdf\xb3\x00\x16\xb6\x80\xc1\xa0/\xa6=$P\x10\xce\xab\xd1\xe4\x00\x00', ('50.XXX.200.162', 0))
        raw_packet = listen.recvfrom(65565)
        #Now we need to unpack the packet. It will be an IP/TCP packet
        #We are looking for SYN-ACKs from our SYN scan
        #Fields to check: IP - src addr; TCP - src port, flags
        #We want to pull out and compare only these three
        #Heres the math for unpacking: B=1, H=2, L=4, 4s=4  (those are bytes)
        packet = raw_packet[0]
        ip_header = unpack('!BBHHHBBH4s',packet[0:16]) #This is the IP header, not including any options OR THE DST ADDR. Normal length is 20!! Im parsing as little as possible
        ip_header_length = (ip_header[0] & 0xf) * 4         #If there are any options, the length of the IP header will be >20. We dont care about options
        src_addr = socket.inet_ntoa(ip_header[8])           #This is the source address (position 8, or the first "4s" in our unpack)
        
        tcp_header_raw = packet[ip_header_length:ip_header_length+14]   #We had to get the proper IP Header length to find the TCP header offset.
        tcp_header = unpack('!HHLLBB',tcp_header_raw)                         #TCP header structure is pretty straight-forward. We want PORTS and FLAGS, so we partial unpack it
        
        src_port = tcp_header[0]    #self-explanatory
        dst_port = tcp_header[1]    #self-explanatory
        flag = tcp_header[5]        #We only care about syn-ack, which will be 18 (0x12)
        
        if flag == 18:
            if src_addr in ips_of_interest and src_port in options.ports:
                sys.stdout.write("OPEN: \t{} : {}\n".format(src_addr,src_port))

def ping(ip_q):
    #ping function. Populates the socket queue for port scanning if ping and port scans are being performed
    #Since ping() is called from daemon threads, the threads are killed by passing the ip as "HALT"
    while True:
        ip = ip_q.get()
        if ip == "HALT":
            ip_q.task_done()
            return
        if "win" in sys.platform.lower():
            # *1000 since windows does millisecond timeout values
            command = ["ping","-n","1","-w",str(options.timeout*1000),ip]
        else:
            command = ["ping","-c 1","-W {}".format(options.timeout),ip]
        ret_value = subprocess.call(command, stdin=devnull, stdout=devnull, stderr=devnull)
        if ret_value == 0:
            sys.stdout.write("UP: \t{0}\n".format(ip))
            if options.ping_only != True:
                for port in options.ports:
                    if options.verbose: sys.stdout.write("Placing ({},{}) in socket queue\n".format(ip,port))
                    socket_queue.put((ip,port))
                    if options.verbose: print(socket_queue.queue)
        if options.verbose: sys.stdout.write("DONE: {} ping\n".format(ip))
        ip_q.task_done()

def port_check(socket_q):
    #If port scan type is "T", calls TCP full connect function
    #If the port scan type is "S", then it calls the raw socket syn-scan function
    while True:
        ip,port = socket_q.get()
        if options.scan_type.upper() == "T":
            send_full_connect_syn(ip,port)
        elif options.scan_type.upper() == "S":
            send_raw_syn(ip,port)
        else:
            sys.stderr.write("Invalid port scan type, doing nothing...\n")
        socket_q.task_done()

def convert_ips(ips):
    #This converts IPs from 10-12.50-60.1.2-5 format to a list of IPs formatted correctly
    #I found that itertools is slower than doing for loops by about 4 seconds for a /8 subnet
    #On my test system, itertools finishes generating the IPs in about 19 seconds for a /8, I consider this acceptable
    #DOES NOT ATTEMPT TO CORRECT MALFORMED IPS. input correctly! Malformed IPs wont crash the scanner, but its a waste of time
    octets = []
    for ip in ips.split("."):
        if "-" in ip:
            lo,hi = ip.split("-")
            octets.append(range(int(lo),int(hi)+1))
        else:
            octets.append([int(ip)])
    for ip in itertools.product(octets[0],octets[1],octets[2],octets[3]):
        yield "{}.{}.{}.{}".format(ip[0],ip[1],ip[2],ip[3])

def convert_ports(ports):
    #Converts ports from form 20-40,100-900,40000-70000
    #It will automatically prune off non-existent ports (<1 >65535)
    if ports == None: return [21,22,23,25,80,443,110,111,135,139,445,8080,8443,53,143,989,990,3306,1080,5554,6667,2222,4444,666,6666,1337,2020,31337]
    else:
        if "-" not in ports:
            tports = ports.split(",")
            print(tports)
        else:
            ports = ports.split(",")
            tports = []
            for port in ports:
                if "-" not in port: tports.append(int(port))
                else: tports.extend(range(int(port.split("-")[0]),int(port.split("-")[1])+1)) #I made this one line because I wanted to
    ports = [int(n) for n in tports if int(n) > 0 and int(n) < 65536]
    if options.verbose: print("Converted ports: {}".format(ports))
    return ports

class TCPHeader():
    #TCP header class. Thanks to Silver Moon for the flags calculation and packing order
    #This was designed to be re-used. You might want to randomize the seq number
    #get_struct performs packing based on if you have a valid checksum or not
    def __init__(self,src_port=47123,dst_port=80,seqnum=1000,acknum=0,data_offset=80,fin=0,syn=1,rst=0,psh=0,ack=0,urg=0,window=5840,check=0,urg_ptr=0):
        self.order = "!HHLLBBHHH" #!=network(big-endian), H=short(2), L=long(4),B=char(1) 
        self.src_port = src_port
        self.dst_port = dst_port
        self.seqnum = seqnum
        self.acknum = acknum
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
    def flags(self):
        return self.fin + (self.syn << 1) + (self.rst << 2) + (self.psh <<3) + (self.ack << 4) + (self.urg << 5)
    def get_struct(self,check=False,checksummed=False):
        if check != False: self.check = check
        if checksummed:
            return pack('!HHLLBBH',self.src_port,self.dst_port,self.seqnum,self.acknum,self.data_offset,self.flags(),self.window)+pack('H',self.check)+pack('!H',self.urg_ptr)
        else:
            return pack(self.order,self.src_port,self.dst_port,self.seqnum,self.acknum,self.data_offset,self.flags(),self.window,self.check,self.urg_ptr)

def checksum(msg):
    #Shoutout to Silver Moon @ binarytides for this checksum algo.
    sum = 0
    for i in range(0,len(msg),2):
        w = ord(msg[i]) + (ord(msg[i+1]) << 8 )
        sum = sum + w
    
    sum = (sum>>16) + (sum & 0xffff)
    sum = sum + (sum >> 16)
    sum = ~sum & 0xffff
    return sum

def tcp_checksum(source_ip,dest_ip,tcp_header,user_data=''):
    #Calculates the correct checksum for the tcp header
    tcp_length = len(tcp_header) + len(user_data)
    ip_header = pack('!4s4sBBH',socket.inet_aton(source_ip),socket.inet_aton(dest_ip),0,socket.IPPROTO_TCP,tcp_length) #This is an IP header w/ TCP as protocol.
    packet = ip_header + tcp_header + user_data #Assemble the packet (IP Header + TCP Header + data, and then send it to checksum function)
    return checksum(packet)

def send_raw_syn(dest_ip,dst_port):
    #Use raw sockets to send a SYN packet.
    #If you want, you could use the IP header assembled in the tcp_checksum function to have a fully custom TCP/IP stack
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP) #Using IPPROTO_TCP so the kernel will deal with the IP packet for us. Change to IPPROTO_IP if you want control of IP header as well
    except Exception:
        sys.stderr.write("Error creating socket in send_raw_syn\n")
    if options.source == "auto":
        src_addr = get_source_ip(dest_ip) #This gets the correct source IP. Just in case of multiple interfaces, it will pick the right one
    else:
        src_addr = options.source
    src_port = 54321
    make_tcpheader = TCPHeader(src_port,dst_port)
    tcp_header = make_tcpheader.get_struct()
    packet = make_tcpheader.get_struct(check=tcp_checksum(src_addr,dest_ip,tcp_header),checksummed=True)
    if options.verbose: sys.stdout.write("SEND: SYN packet {} {}\n".format(dest_ip,dst_port))
    try: s.sendto(packet,(dest_ip,0))
    except Exception: sys.stderr.write("Error utilizing raw socket in send_raw_syn\n")

def send_full_connect_syn(ip,port):
    #Normal scan using socket to connect. Does 3-way handshack, then graceful teardown using FIN
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(options.timeout)
    except Exception:
        sys.stdout.write("Error creating socket in send_full_connect_syn\n")
    try:
        if options.verbose: sys.stdout.write("START: {} {} port\n".format(ip,port))
        s.connect((ip,port))
        sys.stdout.write("OPEN: \t{0} : {1}\n".format(ip,port))
        s.close()
    except Exception:
        pass
    if options.verbose: sys.stdout.write("DONE: {} {} port\n".format(ip,port))

def populate_queues():
    #Note: If pinging happens, the ping() function populates the socket queue
    #This function just fills up ip_queue with all the IPs that will need pinging/port scanning
    #If only doing a port scan, fills up socket_queue with the sockets (ip,port)
    options.ports = convert_ports(options.ports)
    for ip in convert_ips(ips):
        if options.ping.lower() == "n":
            for port in options.ports:
                if options.verbose: sys.stdout.write("Placing ({},{}) in socket queue\n".format(ip,port))
                if options.verbose: print(socket_queue.queue)
                socket_queue.put((ip,port))
        else:
            ip_queue.put(ip)

def start_ping_threads():
    #Starts up the threads responsible for sending pings
    #If youre unfamiliar, ip_queue.join() is a blocking line, meaning code will stop there until the queue is finished
    for index in range(options.threads):
        if options.ping == "y":
            ping_worker = Thread(target=ping, args=(ip_queue,))
            ping_worker.setDaemon(True)
            ping_worker.start()
        
    if options.verbose: print("THREADS inside ping: {}".format(active_count()))
    ip_queue.join()
    print("********* IP QUEUE BLOCK RELEASED ************")

def start_port_threads():
    #Starts up threads to perform port scanning.
    #If youre doing raw syn-scanning, starts up the listener for syn-acks
    if options.scan_type.lower() == "s":
        listen_thread = Thread(target=tcp_listener)
        listen_thread.setDaemon(True)
        listen_thread.start()
    for index in range(options.threads):
        port_worker = Thread(target=port_check, args=(socket_queue,))
        port_worker.setDaemon(True)
        port_worker.start()
    
    if options.verbose: print("THREADS inside port: {}".format(active_count()))
    socket_queue.join()
    if options.scan_type.lower() == "s": sleep(options.timeout)
    print("********* SOCKET QUEUE BLOCK RELEASED *************")

def halt_ping_threads():
    #Stops all the threads for pinging by sending them "HALT". They have an if: clause that tells them to return
    if options.ping == "y":
        for i in range(options.threads):
            ip_queue.put("HALT")

def get_source_ip(dst_addr):
    #Credit: 131264/alexander from stackoverflow. This gets the correct IP for sending. Useful if you have multiple interfaces
    global source_ips
    try:
        if dst_addr in source_ips:
            return source_ips[dst_addr]
        else:
            source_ips[dst_addr] = [(s.connect((dst_addr, 53)), s.getsockname()[0], s.close()) for s in [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]][0][1]
            return source_ips[dst_addr]
    except Exception:
        sys.stderr.write("Something went wrong in get_source_ip, results might be wrong\n")

populate_queues()
start_ping_threads()
halt_ping_threads()
if options.ping_only != True:
    start_port_threads()
