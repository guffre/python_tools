# Covert TCP Handshake

This is a POC tool that uses the sequence number to pass data in a series of TCP handshakes.
It does this by creating a custom TCP header, and attaching it as the data section to an IP packet using raw sockets

This tool was inspired by an offhand comment I heard at a conference claiming "there's no data passed in a TCP handshake".

# Sample

![mintty_2023-04-24_20-41-39](https://user-images.githubusercontent.com/21281361/234154070-b8bbb856-1ee4-44f3-b574-1672cf614eba.gif)

# Wireshark Peek

![2023-04-24_20-40-10](https://user-images.githubusercontent.com/21281361/234154476-600fbd4f-053c-421f-b5a7-4d0b56c64c0c.png)
