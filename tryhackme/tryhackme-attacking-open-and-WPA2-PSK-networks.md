# Attacking Open and WPA2-PSK Networks
## Bypass a captive portal, then capture, crack and decrypt a WPA2 handshake.

## Task 1: Introduction 

The Wi-Fi Fundamentals and Reconnaissance room covered observation, producing a description of an entire wireless environment without connecting to any of it. That description confers no access. This room converts it into access.  

Two configurations are addressed, being the two most frequently encountered in practice. An open network requires no password and applies no encryption, so every frame crosses the radio in cleartext and is readable by any receiver in range. WPA2-PSK does encrypt that traffic, but the scheme rests on one passphrase shared by every client, and the four-way handshake proving a client knows it can be captured and attacked offline. Recovering that passphrase exposes the traffic of every device on the network, not only the attacker's own.  

Two access points from the reconnaissance scan are in scope, each identified below by its BSSID (Basic Service Set Identifier), the hardware address of the access point's radio and the value every tool in this room is pointed at. Guest-WiFi (F0:9F:C2:71:22:10) is an open network on channel 6 behind a captive portal. Home-2G (F0:9F:C2:71:22:12) is WPA2-PSK, also on channel 6, with an unknown passphrase. The objective is access to both and a flag from each. The two are worked in parallel because the WPA2 attack differs from the open one by exactly one step.  

### Learning Objectives
- Bypass a captive portal on an open network by spoofing the MAC address of an already-authorised client.  
- Explain WPA2-PSK and the role of the four-way handshake in proving a client knows the passphrase.  
- Capture a WPA2 four-way handshake by deauthenticating a connected client.  
- Crack a captured handshake against a wordlist to recover the passphrase.  
- Connect to the network with the recovered passphrase and retrieve a flag from behind it.  
- Decrypt captured WPA2 traffic to steal a victim's live session cookie.  

### Prerequisites 

Completion of the Wi-Fi Fundamentals and Reconnaissance room, which is where monitor mode and airodump-ng are introduced and practised. Both are treated here as established tools rather than taught a second time.  

### Machine Access

Start the lab by clicking the Start Machine button below. The machine takes a couple of minutes to boot and then appears in Split View in your browser. For convenience, you can use the expand button in the bottom-left corner of Split View to open the VM in full-screen mode. No login is required, as the session opens directly onto the desktop, already authenticated as the user account.  

### Confirming the Wireless Interfaces

Open a Terminal on the machine and confirm that the wireless interfaces are present:  

```console
user@debian-thm:~$ sudo iw dev
```

Several wlan interfaces are listed, numbered from wlan0 upward. These are the radios used to observe the networks in the lab and to attack them. Most of the tooling requires root privileges, so commands are prefixed with sudo; the password, where prompted, is user

The attacks in this room run from a card in monitor mode, so create the monitor interface before you begin:  

```console
user@debian-thm:~$ sudo airmon-ng check kill
user@debian-thm:~$ sudo airmon-ng start wlan0
```

airmon-ng check kill is not optional here, and it matters for more than the monitor interface.  NetworkManager manages every wireless radio on the machine, so when it is left running it will reclaim the managed radio moments after wpa_supplicant associates with a network. The association appears to succeed,  wpa_supplicant reports no error, and then  iw dev wlan1 link reads Not connected and every  DHCPDISCOVER goes unanswered. Stopping it first avoids that, and it has to come first because the command also stops any  wpa_supplicant already running.
That gives you wlan0mon, the interface every capture and injection command in this room expects. The two managed radios stay as they are, wlan2 for the open network and wlan1 for the WPA2 one once its passphrase is known, because a card in monitor mode cannot associate with anything.  

### Answer the questions below   

**Deploy the machine and read through the introduction, then continue to the next task when you are ready.** 
_No answer needed_

## Task 2: Bypassing the Captive Portal 

An open network issues no key, so joining one takes nothing more than asking. What stands between a new client and the rest of the network is the venue's captive portal, and the decision it records is made per client, against an identifier that client announces. Reaching what sits behind it therefore means joining as an ordinary client, confirming the traffic is being held back, then presenting the identity of a client the portal has already admitted.  

The target is the access point the reconnaissance scan in the [previous room](https://tryhackme.com/room/wififundamentalsandrecon) flagged OPN in its ENC column, Guest-WiFi on channel 6 at BSSID F0:9F:C2:71:22:10. It is the network in the lab requiring the least effort.  

**What Open Means**  

The term open describes the authentication, but its consequence concerns encryption. An access point configured for open authentication performs no key exchange, so nothing transmitted afterwards is protected. Every frame travels in cleartext and is readable by any receiver within range in monitor mode. There is no handshake to capture and nothing to crack, because no secret was established.  

OWE (Opportunistic Wireless Encryption) is the alternative, which the previous room's 5 GHz sweep showed on FreeConnect as AUTH OWE. Joining it looks no different from joining this one, and yet a capture of it yields nothing readable, for a reason the Attacking WPA3 and Rogue Access Points room introduces and the Attacking OWE and the 6 GHz Band room works through (both coming soon). Guest-WiFi is plain OPN, so the techniques below apply in full.  

**Captive Portals**  

A captive portal is an authentication step a venue requires before forwarding client traffic onward. Guest-WiFi runs one served by openNDS. It gates access but provides no encryption, so traffic before, during and after the portal remains as readable as on any other open network. This task defeats the portal; the next exploits the absence of encryption.

**Joining Guest-WiFi**

The monitor interface is wlan0mon. A second managed-mode radio, wlan2, serves as an ordinary client. Because the network is open, the only significant configuration line is key_mgmt=NONE. Write the following to guest-open.conf. 

```console
network={
    ssid="Guest-WiFi"
    key_mgmt=NONE
}
```

Bring the association up and request an address:  

```console
user@debian-thm:~$ sudo wpa_supplicant -B -i wlan2 -c guest-open.conf
Successfully initialized wpa_supplicant
user@debian-thm:~$ sudo dhclient wlan2
```

wpa_supplicant drives the association with the same -B, -i and -c flags introduced in the previous room. Association is a layer 2 event and provides no IP address, so dhclient follows to request one from the access point by DHCP (Dynamic Host Configuration Protocol).

A single iw command achieves the same result without a configuration file:  

```console
user@debian-thm:~$ sudo iw dev wlan2 connect Guest-WiFi
```

Once DHCP replies, the interface holds an address on the guest subnet, with the access point acting as gateway on 192.168.10.1:  

```console
user@debian-thm:~$ ip addr show wlan2
9: wlan2: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 02:00:00:00:02:00 brd ff:ff:ff:ff:ff:ff
    inet 192.168.10.84/24 brd 192.168.10.255 scope global wlan2
       valid_lft forever preferred_lft forever
    inet6 fe80::ff:fe00:200/64 scope link 
       valid_lft forever preferred_lft forever
```

**The Portal Response, HTTP 511**

openNDS intercepts port 80 traffic from every MAC address absent from its allow-list. Addressing the request to an IP rather than a hostname keeps name resolution out of the test:  

```console
user@debian-thm:~$ curl -sI http://192.168.10.1/
HTTP/1.1 511 Network Authentication Required
Content-Length: 1289
Connection: close
Content-Type: text/html; charset=utf-8
Date: Sat, 04 Jul 2026 14:41:22 GMT
```

-sI combines two options. -I asks for the response headers alone rather than the page body, which is all that is needed to see how the gateway answers an unauthenticated client, and -s keeps the progress meter out of the output.  
HTTP 511 Network Authentication Required, defined in [RFC 6585](https://www.rfc-editor.org/info/rfc6585/), indicates the client is on the network but has not authenticated. No header names the software, but the splash page returned in the body signs itself openNDS S/N:f09fc2712210, identifying the daemon. Every request receives the same response until openNDS considers the client authorized.  

**Bypassing the Portal by Spoofing a MAC Address**

The mechanism determining authorization is the weakness. Once a client accepts the terms, openNDS adds it to an allow-list keyed on the client's MAC address (Media Access Control). A MAC address is not a secret. It is transmitted in the clear in every frame the client sends, and on an open network those frames have been readable throughout.  

The reconnaissance scan listed three clients on Guest-WiFi, and the same rows come from airodump-ng pinned to channel 6 and filtered to F0:9F:C2:71:22:10, which leaves only the stations associated with that access point:  

```console
user@debian-thm:~$ sudo airodump-ng -c 6 --bssid F0:9F:C2:71:22:10 wlan0mon
...
 BSSID              STATION            PWR    Rate    Lost   Frames  Notes  Probes
 F0:9F:C2:71:22:10  80:18:44:BF:72:47  -41   0 - 1e     0      24
 F0:9F:C2:71:22:10  B0:72:BF:B0:78:48  -44   0 - 1      0      12
 F0:9F:C2:71:22:10  B0:72:BF:44:B0:49  -47   0 - 1      0       8
```

Clone the first of those addresses onto wlan2. macchanger rewrites the address a card presents to the network, with -m supplying the one to adopt. The driver accepts the change only while the interface is down, so it is taken down first and brought back up once the new address is in place:  

```console
user@debian-thm:~$ sudo ip link set wlan2 down
user@debian-thm:~$ sudo macchanger -m 80:18:44:BF:72:47 wlan2
Current MAC:   02:00:00:00:02:00 (unknown)
Permanent MAC: 02:00:00:00:02:00 (unknown)
New MAC:       80:18:44:bf:72:47 (unknown)
user@debian-thm:~$ sudo ip link set wlan2 up
```

Reconnect by rerunning wpa_supplicant and dhclient, then issue the identical request. The same URL that returned 511 now returns a redirect to the panel's login page:  

```console
user@debian-thm:~$ curl -sI http://192.168.10.1/
HTTP/1.1 302 Found
Date: Sat, 04 Jul 2026 14:43:07 GMT
Server: Apache/2.4.66 (Debian)
Set-Cookie: PHPSESSID=REDACTED; path=/
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
location: login.php
Content-Type: text/html; charset=UTF-8
```

<img width="2124" height="918" alt="image" src="https://github.com/user-attachments/assets/57a02755-212f-4387-b52b-d05156f09b8a" />

**Answer the question below**
*What HTTP status code does the openNDS captive portal return to a client that has not yet authenticated?*

**Answer:** 511
