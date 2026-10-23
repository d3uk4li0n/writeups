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
