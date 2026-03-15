# TryHackMe: Wireshark – Traffic Analysis

## Task 2: Nmap Scans

### What is the total number of "TCP Connect" scans?
The Nmap flag for a TCP connect scan is "-sT".
A connect scan initiates the TCP connection but does not complete the full handshake. It sends a SYN packet, examines the reply, then terminates the connection.

So a SYN packet is sent, but the corresponding ACK message is never received. The packets also have a window size larger than 1024 bytes.

Let's try this filter:

tcp.flags.syn == 1 and tcp.flags.ack == 0 and tcp.window_size > 1024

1000 packets are returned, and that's the correct answer

