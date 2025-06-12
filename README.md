#!/usr/bin/env python3

"""
📡 Ethical Wi-Fi Audit Tool
Author: devil0rose (hack th box)
Purpose: Educational and ethical network testing toolkit
Note: ONLY use on lab environments with full control and consent

✅ Supported Ethical Attacks & Tests:
- 🔍 Wi-Fi Discovery (airodump-ng)
- 🎯 Client Tracking on AP
- 🧠 OS & Service Fingerprinting (nmap)
- 🕵 HTTP/HTTPS Traffic Inspection (mitmproxy)
- 🍪 Cookie Capture (via mitmproxy + trusted CA)
- 🔑 Credential Interception (HTTP basic/form)
- 💉 Simulated ARP spoofing / MITM (manual extension)
- 🔌 DoS Simulation (e.g., deauth packets – NOT active here)
- 📲 Device Profiling by MAC/vendor
- 🧬 DNS Spoof Testing (optionally via bettercap)

These attacks are simulated or monitored for visibility, and must never be used outside authorized environments.
