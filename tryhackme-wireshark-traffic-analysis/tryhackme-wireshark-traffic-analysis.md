# TryHackMe: Wireshark – Traffic Analysis

## Task 2: Nmap Scans

### What is the total number of "TCP Connect" scans?
The Nmap flag for a TCP connect scan is "-sT".
A connect scan initiates the TCP connection but does not complete the full handshake. It sends a SYN packet, examines the reply, then terminates the connection.

So a SYN packet is sent, but the corresponding ACK message is never received. The packets also have a window size larger than 1024 bytes.

Let's try this filter:

tcp.flags.syn == 1 and tcp.flags.ack == 0 and tcp.window_size > 1024

### 1000 packets are returned, and that's the correct answer

![Filter](images/1-ss.jpg)

### Which scan type is used to scan the TCP port 80?

The task tells us this:

![Filter](images/1-2-ss.jpg)

**Answer:** TCP connect 


### How many "UDP close port" messages are there?

The task tells us this too: 

![Filter](images/1-3-ss.jpg)

**Answer:** 1083 


### Which UDP port in the 55-70 port range is open?

Let's set a filter to check for UDP ports in the 55–70 range 

udp.port >= 55 and udp.port <= 70

![Filter](images/1-4.jpg)

**Answer:** 48

## Task 3: ARP Poisoning & Man In The Middle!

### What is the number of ARP requests crafted by the attacker?

We know that the ARP request opcode is 1  
We also know the attacker's MAC address from the task, so we can filter based on that:

arp.opcode == 1 && arp.src.hw_mac == 00:0c:29:e2:18:b4

![Filter](images/2-1.jpg)

**Answer:** 284

### What is the number of HTTP packets received by the attacker?

We can filter by protocol and using the attacker's MAC address 
http and eth.addr == 00:0c:29:e2:18:b4

![Filter](images/2-2.jpg)

**Answer: 90**

### What is the number of sniffed username&password entries?

We know that we need to look for **POST requests**, since login credentials are typically submitted through HTTP POST forms

This one took a while for me to figure out

I started by applying this filter:

http.request.method == POST and eth.dst == 00:0c:29:e2:18:b4

![Filter](images/2-3-1.jpg)

However, 10 is not the correct answer.

Inspecting the POST requests further, we notice that the relevant fields contain "uname", so we can filter for that 
This returns 7 packets, but that is still not the correct answer.

![Filter](images/2-3-2.jpg)

At this point, it appears that only the **POST requests to `/userinfo.php`** are relevant, so we refine the filter:

http.request.full_uri == "http://testphp.vulnweb.com/userinfo.php" &&
http.request.method == POST &&
urlencoded-form contains "uname"

This returns 6 packets, which correspond to the sniffed username and password entries.

![Filter](images/2-3-3.jpg)

**Answer: 6**

### What is the password of the "Client986"?

Keeping the filter we just used, double-click packet 1668, and go to HTML Form URL encoded

![Filter](images/2-4.jpg)

**Answer: clientnothere!**

### What is the comment provided by the "Client354"?

We're looking for POST requests again, we get 10 packets by filtering for those 

http.request.method == POST

The only suspect entry is the comment.php one

![Filter](images/2-5-1.jpg)

Sure enough, we select it, and we see our answer there

![Filter](images/2-5-2.jpg)

**Answer: Nice work!**

## Task 4: Identifying Hosts: DHCP, NetBIOS and Kerberos

### What is the MAC address of the host "Galaxy A30"?

My first move was probably the most predictable one

Using the filter:

dhcp.option.hostname contains "Galaxy A30"

yielded no results, so I broadened the search to:

dhcp.option.hostname contains "Galaxy"

This returns three packets. Two of them correspond to the broadcast address of the local network segment, leaving only one relevant packet

![Filter](images/3-1.jpg)

**Answer:** 9a:81:41:cb:96:6c

### How many NetBIOS registration requests does the "LIVALJM" workstation have?

First thing we need to do is narrow down the research:
nbns.name contains LIVALJM

40 packets are returned, we're only interested in those with a registration value in them

One common denominator those packets seem to have are two flags with the value of 0x2810 and 0x2910 respectively, so let's filter by those 
nbns.name contains "LIVALJM" and nbns.flags in {0x2810 0x2910}

![Filter](images/3-2.jpg)

![Filter](images/3-3.jpg)

**Answer: 16**

### Which host requested the IP address "172.16.13.85"?

The task basically gives us the answer, so we use the filter:

dhcp.option.requested_ip_address == 172.16.13.85

ONE packet is returned 

![Filter](images/3-4.jpg)

**Answer: Galaxy A-12**

### What is the IP address of the user "u5"? (Enter the address in defanged format.)

As the task suggests –> kerberos.CNameString == "u5"

![Filter](images/3-5.jpg)

Use [Cyberchef](https://gchq.github.io/CyberChef/) to defang it

**Answer: 10[.]1[.]12[.]2**

### What is the hostname of the available host in the Kerberos packets?

Once again, the task comes to our aid

![Filter](images/3-6.jpg)

We issue: kerberos.CNameString contains "$" and we get one result 

![Filter](images/3-7.jpg)

**Answer: xp1$**

## Task 5: Tunneling Traffic: DNS and ICMP

### Investigate the anomalous packets. Which protocol is used in ICMP tunnelling?

### ICMP Overview

ICMP (Internet Control Message Protocol) is used by network devices to send **error messages and diagnostic information** — not actual data like TCP or UDP.

You can think of it as the troubleshooting protocol *par excellence*.

Tools like ping and traceroute rely on ICMP. Ping works by sending ICMP echo request messages and receiving echo replies.  

When analyzing traffic, ICMP can quickly tell us:
- whether a host is alive  
- if packets are failing to reach their destination  
- how traffic is moving across the network  

While it doesn’t carry data itself, it can provide us with useful information about the devices we are trying to communicate with.

### DNS analysis overview 

Adversary often sets up a domain address and configures it as a C2 channel and the commands executed post-exploitation send DNS queries to the C2 server. One way to recognize these queries is that they are longer than default length. 

### Use the "Desktop/exercise-pcaps/dns-icmp/icmp-tunnel.pcap" file. Investigate the anomalous packets. Which protocol is used in ICMP tunnelling?

It took some trial and error of looking at the raw data of various packets, but I finally got it:

**Answer: SSH**

### Use the "Desktop/exercise-pcaps/dns-icmp/dns.pcap" file.Investigate the anomalous packets. What is the suspicious main domain address that receives anomalous DNS queries? (Enter the address in defanged format.)

Let’s try: dns.qry.name.len > 15 and !mdns
(which is the task's recommended filter)  
But that returned 30k packets, that’s not gonna help us

After rummaging in vain among the returned packets, I asked [Echo](https://tryhackme.com/echo) for a way to get a cleaner output, and he recommended this filter: 
dns.qry.name.len > 15 and !mdns and dns.qry.type == 5 

![Filter](images/4-1.jpg)

That returned 3308 packets – still messy, but the packets all look very similar  
Pick a random packet, go to Follow –> UDP Stream

![Filter](images/4-2.jpg)

Back to Cyberchef to defang it

**Answer: dataexfil[.]com**

## Task 6: Cleartext Protocol Analysis: FTP

### How many incorrect login attempts are there?

The task basically gave us the answer:
ftp.response.code == 530

![Filter](images/5-1.jpg)

![Filter](images/5-2.jpg)

**Answer: 737**

### What is the size of the file accessed by the "ftp" account?

First I tried this filter: ftp.request.arg contains "ftp" && (ftp.request.command == "LIST" || ftp.request.command == "CWD")  
But no packets are returned

Since the 213 code indicates file status, I try: ftp.request.arg contains "ftp" and ftp.response.code == 213  
Still nothing 

![Filter](images/5-3.jpg)

Finally I try: ftp.request.arg contains "ftp" or ftp.response.code == 213  
4 packets are displayed, 2 of them contain a 213 response 

![Filter](images/5-4.jpg)

**Answer: 39424**

### The adversary uploaded a document to the FTP server. What is the filename?

Simply follow the TCP stream of the packet we got from the last answer

![Filter](images/5-6.jpg)

**Answer: resume.doc**

### The adversary tried to assign special flags to change the executing permissions of the uploaded file. What is the command used by the adversary?

We get this info from the same data stream 

![Filter](images/5-7.jpg)

**Answer: CHMOD 777**
