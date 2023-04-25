# Covert TCP Handshake

This is a POC tool that uses the sequence number to pass data in a series of TCP handshakes.
It does this by creating a custom TCP header, and attaching it as the data section to an IP packet using raw sockets

This tool was inspired by an offhand comment I heard at a conference claiming "there's no data passed in a TCP handshake".

# Usage

This tool requires raw sockets! It will work on *nix with root privileges, but Windows will need libpcap installed (not tested)

## Send

Raw sockets will "trick" the OS into not realizing that the packet was sent. This will result in RST packets being sent when the target responds with a SYN-ACK.
To avoid this, you can block the RST segments using iptables:

```
iptables -A OUTPUT -p tcp --tcp-flags ALL RST --dport 3000 -j DROP
cat my_data.bin | ./raw_tcp_send.py <dst_ip> <dst_port>
```

## Receive

Since it uses raw sockets, it does not matter if the port is bound or not. Go ahead and bind to port 80 and "blend" with http traffic!

```
./raw_tcp_recv.py <ip_to_recv_from> <port>
```


# Sample

![mintty_2023-04-24_20-41-39](https://user-images.githubusercontent.com/21281361/234154070-b8bbb856-1ee4-44f3-b574-1672cf614eba.gif)

# Wireshark Peek

![2023-04-24_20-40-10](https://user-images.githubusercontent.com/21281361/234154476-600fbd4f-053c-421f-b5a7-4d0b56c64c0c.png)
