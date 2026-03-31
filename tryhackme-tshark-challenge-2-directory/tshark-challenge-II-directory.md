# TShark Challenge II: Directory  

This room presents you with a challenge to investigate some traffic data as a part of the SOC team. Let's start working with TShark to analyse the captured traffic. We recommend completing the TShark: The Basics and TShark: CLI Wireshark Features rooms first, which will teach you how to use the tool in depth.

Start the VM by pressing the green Start Machine button in this task. The machine will start in split view, so you don't need SSH or RDP. In case the machine does not appear, you can click the blue Show Split View button located at the top of this room.

NOTE: Exercise files contain real examples. DO NOT interact with them outside of the given VM. Direct interaction with samples and their contents (files, domains, and IP addresses) outside the given VM can pose security threats to your machine. 

**An alert has been triggered:** "A user came across a poor file index, and their curiosity led to problems".

The case was assigned to you. Inspect the provided directory-curiosity.pcap located in ~/Desktop/exercise-files and retrieve the artefacts to confirm that this alert is a true positive.

Your tools: TShark, VirusTotal(opens in new tab.

**Answer the questions below**

*Investigate the DNS queries.
Investigate the domains by using VirusTotal.
According to VirusTotal, there is a domain marked as malicious/suspicious.*

### What is the name of the malicious/suspicious domain?
*Enter your answer in a defanged format.*  

To identify potentially malicious domains, we first need to analyze the DNS traffic. That will tell us which domains the victim attempted to resolve, which are a main source of suspicious activity   

Since a capture contains both DNS queries and responses, we will filter specifically for DNS query packets. To do that, we will use the filter dns.flags.response == 0, which isolates only query packets (as opposed to responses)  

In order to visualize the queried domain names, we can use TShark’s field output functionality, focusing on the dns.qry.name field:  

tshark -r directory-curiosity.pcap -Y "dns.flags.response == 0" -T fields -e dns.qry.name  

![Filter](images/1.jpg)

Defang it using [Cyberchef](https://gchq.github.io/CyberChef/)

**Answer: jx2-bavuong[.]com**

### What is the total number of HTTP requests sent to the malicious domain?

To investigate HTTP activity related to the malicious domain, we first need to extract all HTTP requests from the capture. HTTP requests represent outbound communication initiated by the client and can reveal interactions with suspicious infrastructure.  

To isolate only HTTP request packets, we apply the display filter http.request. We then use TShark’s field output functionality to extract the full requested URIs via the http.request.full_uri field:  

tshark -r directory-curiosity.pcap -Y "http.request" -T fields -e http.request.full_uri

![Filter](images/2-1.jpg)

The output contains too many empty lines due to packets that do not include the specified field. To clean the output, we remove blank lines using awk NF  

Next, we filter for requests targeting the identified malicious domain (jx2-bavuong.com) using grep. Finally, we count the total number of matching requests with wc -l, which gives us the number of HTTP requests sent to the malicious domain  

tshark -r directory-curiosity.pcap -Y "http.request" -T fields -e http.request.full_uri awk NF grep "jx2-bavuong.com" wc -l

![Filter](images/2-2.jpg)

**Answer: 14**

### What is the IP address associated with the malicious domain?
*Enter your answer in a defanged format.*

To determine the IP address associated with the malicious domain, we need to analyze the DNS response traffic. While DNS queries show which domains were requested, DNS responses contain the actual resolved IP addresses.  

To isolate this information, we filter for DNS response packets using dns.flags.response == 1 and match only those related to the malicious domain (jx2-bavuong.com). We then extract the corresponding IPv4 address using the dns.a field, as DNS A records map a domain to its IPv4 address.  

tshark -r directory-curiosity.pcap -Y "dns.flags.response == 1 and dns.qry.name contains jx2-bavuong.com" -T fields -e dns.a

![Filter](images/3.jpg)

Defang using [Cyberchef](https://gchq.github.io/CyberChef/)

**Answer: 141[.]164[.]41[.]174**

### What is the server info of the suspicious domain?

To identify the server information associated with the suspicious domain, we need to analyze HTTP response traffic. HTTP requests are sent by the client, whereas HTTP responses are returned by the server and they often include metadata about the server itself (eg HTTP headers, which is what we are interested in)   

To isolate this information, we filter for HTTP response packets using http.response. We then extract the value of the http.server field, which corresponds to the server header in HTTP responses — a header commonly used to indicate the software running on the web server  

tshark -r directory-curiosity.pcap -Y "http.response" -T fields -e "http.server" 

![Filter](images/4.jpg)

**Answer: Apache/2.2.11 (Win32) DAV/2 mod_ssl/2.2.11 OpenSSL/0.9.8i PHP/5.2.9**

### Follow the "first TCP stream" in "ASCII"
*Investigate the output carefully.*

### What is the number of listed files?

To determine the number of files listed on the suspicious server, we reconstruct the TCP stream between the client and the server. This way, we can view the communication between the two, including HTTP requests and responses.   

This allows us to inspect the server’s response content directly. We see that the response contains an HTML directory listing (see: “Index of /”), and that shows us the files hosted on the server. It can be tricky (as it was, in this instance) to distinguish noise from usable data, but that's our mission here.  

tshark -r directory-curiosity.pcap -q -z "follow,tcp,ascii,0"

The output is too messy to screenshot.  

**Answer: 3**

### What is the filename of the first file?

*Enter your answer in a defanged format*

From the output of the previous command:  
![Filter](images/7.jpg)

**Answer: 123[.]php**

### Export all HTTP traffic objects.
*What is the name of the downloaded executable file?*

### Enter your answer in a defanged format

The following command will save basically everything transferred over HTTP (the -Q flag is to exclude noise):

tshark -Q -r directory-curiosity.pcap --export-objects http,.

![Filter](images/8.jpg)

That executable looks sketchy, but really we don't need much more evidence other than the fact it's an executable  

**Answer: vlauto[.]exe**

### What is the SHA256 value of the malicious file?

![Filter](images/9.jpg)

**Answer: b4851333efaf399889456f78eac0fd532e9d8791b23a86a19402c1164aed20de**

### Search the SHA256 value of the file on VirtusTotal.

*What is the "PEiD packer" value?*

![Filter](images/10.jpg)

**Answer: .NET executable**

### Search the SHA256 value of the file on VirtusTotal

*What does the "Lastline Sandbox" flag this as?*

![Filter](images/11.jpg)

**Answer: Malware Trojan**
