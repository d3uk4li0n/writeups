# Attacking Open and WPA2-PSK Networks
## Bypass a captive portal, then capture, crack and decrypt a WPA2 handshake.

The Wi-Fi Fundamentals and Reconnaissance room covered observation, producing a description of an entire wireless environment without connecting to any of it. That description confers no access. This room converts it into access.  

Two configurations are addressed, being the two most frequently encountered in practice. An open network requires no password and applies no encryption, so every frame crosses the radio in cleartext and is readable by any receiver in range. WPA2-PSK does encrypt that traffic, but the scheme rests on one passphrase shared by every client, and the four-way handshake proving a client knows it can be captured and attacked offline. Recovering that passphrase exposes the traffic of every device on the network, not only the attacker's own.  

Two access points from the reconnaissance scan are in scope, each identified below by its BSSID (Basic Service Set Identifier), the hardware address of the access point's radio and the value every tool in this room is pointed at. Guest-WiFi (F0:9F:C2:71:22:10) is an open network on channel 6 behind a captive portal. Home-2G (F0:9F:C2:71:22:12) is WPA2-PSK, also on channel 6, with an unknown passphrase. The objective is access to both and a flag from each. The two are worked in parallel because the WPA2 attack differs from the open one by exactly one step.  
