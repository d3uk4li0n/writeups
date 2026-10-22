# Attacking Open and WPA2-PSK Networks
## Bypass a captive portal, then capture, crack and decrypt a WPA2 handshake.

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

>_ sudo iw dev
