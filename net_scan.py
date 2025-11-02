#!/usr/bin/env python3
"""
netdash_cli.py
CLI tool: scan LAN (ARP), measure internet speed, block/unblock devices via iptables,
store aliases in SQLite.

Requirements:
  sudo apt install python3-pip nmap         # optionally nmap
  pip3 install scapy speedtest-cli tabulate

Run:
  sudo python3 netdash_cli.py
"""
import os
import sqlite3
import socket
import subprocess
import sys
import time
import re
from datetime import datetime
from manuf import manuf

try:
    from scapy.all import ARP, Ether, srp
except Exception as e:
    print("Missing scapy. Install: pip3 install scapy")
    raise

try:
    import speedtest
except Exception:
    print("Missing speedtest-cli. Install: pip3 install speedtest-cli")
    raise

from tabulate import tabulate

OUI_MAP = {
    "a0:f3:c1": "Mobile (Apple iPhone/iPad)",
    "d4:85:64": "Laptop/Desktop (Dell)",
    "b8:27:eb": "Single-board Computer (Raspberry Pi)",
    "50:6b:03": "Mobile (Samsung Phone)",
    # أضف المزيد حسب الحاجة
}
p = manuf.MacParser()

def get_device_category(mac):
    
    vendor = p.get_manuf(mac)
    if vendor:
        if any(x in vendor.lower() for x in ["iphone","samsung","xiaomi","huawei"]):
            return "Mobile"
        elif any(x in vendor.lower() for x in ["dell","hp","lenovo","asus"]):
            return "Laptop/Desktop"
        else:
            return "Other"
    return "Unknown"






def get_device_type(mac):
    vendor = p.get_manuf(mac)
    return vendor if vendor else "Unknown"




DB_PATH = os.path.join(os.path.dirname(__file__), "netdash_devices.db")
NETWORK_CIDR_DEFAULT = "192.168.1.0/24"  # لو شبكتك مختلفة عدلها أو ادخلها عند التشغيل

# ---------- Database helpers ----------
def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS devices (
        ip TEXT PRIMARY KEY,
        mac TEXT,
        hostname TEXT,
        alias TEXT,
        last_seen TEXT
    )
    """)
    conn.commit()
    conn.close()

def upsert_device(ip, mac, hostname):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    now = datetime.utcnow().isoformat()
    cur.execute("INSERT INTO devices(ip,mac,hostname,last_seen) VALUES(?,?,?,?) ON CONFLICT(ip) DO UPDATE SET mac=excluded.mac, hostname=excluded.hostname, last_seen=excluded.last_seen",
                (ip, mac, hostname, now))
    conn.commit()
    conn.close()

def set_alias(ip, alias):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("UPDATE devices SET alias=? WHERE ip=?", (alias, ip))
    conn.commit()
    conn.close()

def get_all_devices():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT ip, mac, hostname, alias, last_seen FROM devices ORDER BY last_seen DESC")
    rows = cur.fetchall()
    conn.close()
    devices = []
    for r in rows:
        devices.append({
            "ip": r[0], "mac": r[1], "hostname": r[2], "alias": r[3], "last_seen": r[4]
        })
    return devices

# ---------- Network scanning (ARP) ----------
def arp_scan(network_cidr=NETWORK_CIDR_DEFAULT, timeout=2, iface=None):
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=network_cidr)
    ans, _ = srp(pkt, timeout=timeout, verbose=False, iface=iface)
    devices = []
    for sent, received in ans:
        ip = received.psrc
        mac = received.hwsrc
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except Exception:
            hostname = None
        devices.append({"ip": ip, "mac": mac, "hostname": hostname})
        upsert_device(ip, mac, hostname)
    return devices


# ---------- Speed measurement ----------
def measure_speed():
    """
    Uses speedtest-cli. This will do real upload/download tests and may take ~20s.
    Returns dict with download_mbps, upload_mbps, ping_ms
    """
    st = speedtest.Speedtest()
    st.get_best_server()
    dl = st.download()
    ul = st.upload()
    ping = st.results.ping
    return {
        "download_mbps": round(dl / 1e6, 2),
        "upload_mbps": round(ul / 1e6, 2),
        "ping_ms": round(ping, 2)
    }

# ---------- Block / Unblock ----------
def is_root():
    return os.geteuid() == 0 if hasattr(os, "geteuid") else ctypes.windll.shell32.IsUserAnAdmin() != 0

def iptables_block(ip):
    # Insert DROP rule for source ip (INPUT chain). Adjust if you need FORWARD chain depending on topology.
    cmd = ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"]
    subprocess.run(cmd)
    print(f"Blocked {ip} via iptables.")

def iptables_unblock(ip):
    cmd = ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"]
    subprocess.run(cmd)
    print(f"Unblocked {ip} via iptables.")

def check_blocked(ip):
    # list rules that match
    res = subprocess.run(["iptables", "-L", "INPUT", "-n"], capture_output=True, text=True)
    return ip in res.stdout and "DROP" in res.stdout

# ---------- CLI interaction ----------
def pretty_print_devices(devs):
    table = []
    for i, d in enumerate(devs, start=1):
        alias = d.get("alias") or ""
        hostname = d.get("hostname") or ""
        last_seen = d.get("last_seen") or ""
        blocked = "YES" if check_blocked(d["ip"]) else "NO"
        dev_type = get_device_type(d["mac"])  # <-- الجديد
        dev_category = get_device_category(d["mac"])
        table.append([i, d["ip"], d["mac"], hostname, alias, last_seen, blocked, dev_type, dev_category])
    headers = ["Nub", "IP", "MAC", "Hostname", "Alias", "Last Seen (UTC)", "Blocked", "Device Type", "Device Category"]
    print(tabulate(table, headers=headers, tablefmt="grid"))


def interactive_run():
    print("Starting LAN scan... (requires root/admin)")
    net = input(f"Network CIDR [{NETWORK_CIDR_DEFAULT}]: ").strip() or NETWORK_CIDR_DEFAULT
    devices = arp_scan(net)  # بدون iface
    print(f"Found {len(devices)} device(s).")
    # fetch alias/last_seen from DB to enrich list
    db_devices = get_all_devices()
    # merge
    dev_map = {d["ip"]: d for d in db_devices}
    enriched = []
    for d in devices:
        rec = dev_map.get(d["ip"], {})
        enriched.append({
            "ip": d["ip"],
            "mac": d["mac"],
            "hostname": rec.get("hostname") or d.get("hostname"),
            "alias": rec.get("alias"),
            "last_seen": rec.get("last_seen")
        })
    pretty_print_devices(enriched)
    print("\nMeasuring internet speed (this may take 20-40s)...")
    sp = measure_speed()
    print(f"Download: {sp['download_mbps']} Mbps | Upload: {sp['upload_mbps']} Mbps | Ping: {sp['ping_ms']} ms\n")

    # prompt for action
    while True:
        cmd = input("Enter device number/IP to block/unblock, 'alias' to set alias, 'rescan', or 'exit': ").strip()
        if cmd.lower() in ("exit", "quit"):
            print("Bye.")
            break
        if cmd.lower() == "rescan":
            return interactive_run()
        if cmd.lower() == "alias":
            ip = input("IP to set alias for: ").strip()
            alias = input("Alias name: ").strip()
            set_alias(ip, alias)
            print("Alias updated.")
            continue
        # handle number
        target_ip = None
        if cmd.isdigit():
            idx = int(cmd) - 1
            if 0 <= idx < len(enriched):
                target_ip = enriched[idx]["ip"]
            else:
                print("Invalid index.")
                continue
        else:
            # assume ip or alias or hostname
            # try exact ip match
            matches = [d for d in enriched if d["ip"] == cmd or (d.get("alias") and d["alias"] == cmd) or (d.get("hostname") and d["hostname"] == cmd)]
            if len(matches) == 1:
                target_ip = matches[0]["ip"]
            elif len(matches) > 1:
                print("Multiple matches, give IP or index:")
                for i,m in enumerate(matches,1):
                    print(i, m["ip"], m.get("alias"), m.get("hostname"))
                continue
            else:
                print("No matching device.")
                continue
        # got target_ip
        currently_blocked = check_blocked(target_ip)
        action = input(f"Device {target_ip} currently blocked={currently_blocked}. Type 'block' or 'unblock' or 'cancel': ").strip().lower()
        if action == "block":
            iptables_block(target_ip)
        elif action == "unblock":
            iptables_unblock(target_ip)
        else:
            print("Cancelled.")

def main():
    init_db()
    if os.geteuid() != 0:
        print("Warning: recommended to run with root privileges for ARP scan and iptables.")
        # continue but some ops will fail
    print("NetDash CLI - Commands: run | list | speed | block <ip> | unblock <ip> | alias <ip> <name> | exit")
    while True:
        try:
            cmdline = input("netdash> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nExiting.")
            break
        if not cmdline:
            continue
        parts = cmdline.split()
        cmd = parts[0].lower()
        if cmd == "run":
            interactive_run()
        elif cmd == "list":
            devs = get_all_devices()
            pretty_print_devices(devs)
        elif cmd == "speed":
            print("Measuring speed...")
            print(measure_speed())
        elif cmd == "block" and len(parts) >= 2:
            ip = parts[1]
            iptables_block(ip)
        elif cmd == "unblock" and len(parts) >= 2:
            ip = parts[1]
            iptables_unblock(ip)
        elif cmd == "alias" and len(parts) >= 3:
            ip = parts[1]; alias = " ".join(parts[2:])
            set_alias(ip, alias)
            print("Alias set.")
        elif cmd in ("exit", "quit"):
            break
        else:
            print("Unknown command.")
    print("Goodbye.")

if __name__ == "__main__":
    main()
